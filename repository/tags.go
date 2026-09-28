// Package repository — tags for the ARN-addressed services (SQS, IAM,
// RDS, Route53, DynamoDB, EKS).
//
// One row per (resource ARN, key). Each call names the table the ARN
// must live in, so a tag call on a missing resource is ErrNotFound
// rather than a stored orphan. An AFTER DELETE trigger on every
// taggable table drops a resource's tags with it, so a resource
// recreated under the same ARN starts untagged.
package repository

import (
	"database/sql"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
)

// TaggedTable is a table whose rows can carry tags, keyed by its arn
// column.
type TaggedTable string

const (
	TagsSQSQueue          TaggedTable = "sqs_queues"
	TagsIAMRole           TaggedTable = "iam_roles"
	TagsIAMUser           TaggedTable = "iam_users"
	TagsIAMPolicy         TaggedTable = "iam_policies"
	TagsRDSInstance       TaggedTable = "rds_db_instances"
	TagsRDSParameterGroup TaggedTable = "rds_db_parameter_groups"
	TagsRDSSubnetGroup    TaggedTable = "rds_db_subnet_groups"
	TagsRoute53Zone       TaggedTable = "route53_hosted_zones"
	TagsDynamoDBTable     TaggedTable = "dynamodb_tables"
	TagsEKSCluster        TaggedTable = "eks_clusters"
)

var taggedTables = []TaggedTable{
	TagsSQSQueue, TagsIAMRole, TagsIAMUser, TagsIAMPolicy,
	TagsRDSInstance, TagsRDSParameterGroup, TagsRDSSubnetGroup,
	TagsRoute53Zone, TagsDynamoDBTable, TagsEKSCluster,
}

func init() {
	registeredMigrations = append(registeredMigrations, `CREATE TABLE IF NOT EXISTS resource_tags (
		account_id TEXT NOT NULL,
		arn        TEXT NOT NULL,
		key        TEXT NOT NULL,
		value      TEXT NOT NULL,
		PRIMARY KEY (account_id, arn, key)
	)`)
	for _, table := range taggedTables {
		registeredMigrations = append(registeredMigrations, fmt.Sprintf(
			`CREATE TRIGGER IF NOT EXISTS %[1]s_drop_resource_tags AFTER DELETE ON %[1]s BEGIN
				DELETE FROM resource_tags WHERE account_id = OLD.account_id AND arn = OLD.arn;
			END`, table))
	}
	prependResetTables([]string{"resource_tags"})
}

// TagResource adds tags to the resource, overwriting the value of a
// key already on it.
func (r *Repository) TagResource(account string, table TaggedTable, arn string, tags map[string]string) error {
	return r.ChangeResourceTags(account, table, arn, tags, nil)
}

// UntagResource removes the keys from the resource; a key it does not
// carry is ignored, as AWS does.
func (r *Repository) UntagResource(account string, table TaggedTable, arn string, keys []string) error {
	return r.ChangeResourceTags(account, table, arn, nil, keys)
}

// ChangeResourceTags removes then adds tags in one transaction.
func (r *Repository) ChangeResourceTags(account string, table TaggedTable, arn string, add map[string]string, remove []string) error {
	return r.inTx(func(tx *sql.Tx) error {
		if err := resourceExists(tx, account, table, arn); err != nil {
			return err
		}
		for _, k := range remove {
			if _, err := tx.Exec(`DELETE FROM resource_tags WHERE account_id = ? AND arn = ? AND key = ?`, account, arn, k); err != nil {
				return err
			}
		}
		for k, v := range add {
			if _, err := tx.Exec(
				`INSERT INTO resource_tags (account_id, arn, key, value) VALUES (?, ?, ?, ?)
				ON CONFLICT (account_id, arn, key) DO UPDATE SET value = excluded.value`,
				account, arn, k, v,
			); err != nil {
				return err
			}
		}
		return nil
	})
}

// ResourceTags returns the resource's tags, never nil.
func (r *Repository) ResourceTags(account string, table TaggedTable, arn string) (map[string]string, error) {
	out := map[string]string{}
	err := r.inTx(func(tx *sql.Tx) error {
		if err := resourceExists(tx, account, table, arn); err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT key, value FROM resource_tags WHERE account_id = ? AND arn = ?`, account, arn)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				return err
			}
			out[k] = v
		}
		return rows.Err()
	})
	return out, err
}

// resourceExists reports ErrNotFound unless table holds arn. table is
// always one of the TaggedTable constants, never caller input.
func resourceExists(tx *sql.Tx, account string, table TaggedTable, arn string) error {
	var one int
	err := tx.QueryRow(fmt.Sprintf(`SELECT 1 FROM %s WHERE account_id = ? AND arn = ?`, table), account, arn).Scan(&one)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%s %s: %w", table, arn, models.ErrNotFound)
	}
	return err
}
