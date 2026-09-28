// Package repository — EC2 resource tags.
//
// One row per (resource, key). Resource ids are account-unique, so a
// tag names its resource by id alone; region is kept so DescribeTags
// can be scoped like the rest of EC2. An AFTER DELETE trigger on every
// taggable table drops a resource's tags with it, including rows a
// foreign-key cascade removes (a VPC delete takes its subnets' tags).
package repository

import (
	"database/sql"
	"fmt"
)

// ec2TaggedTables are the tables whose rows can carry tags.
var ec2TaggedTables = []string{
	"ec2_vpcs",
	"ec2_subnets",
	"ec2_internet_gateways",
	"ec2_route_tables",
	"ec2_security_groups",
	"ec2_instances",
	"ec2_network_interfaces",
}

func init() {
	registeredMigrations = append(registeredMigrations, `CREATE TABLE IF NOT EXISTS ec2_tags (
		account_id    TEXT NOT NULL,
		region        TEXT NOT NULL,
		resource_id   TEXT NOT NULL,
		resource_type TEXT NOT NULL,
		key           TEXT NOT NULL,
		value         TEXT NOT NULL,
		PRIMARY KEY (account_id, resource_id, key)
	)`)
	for _, table := range ec2TaggedTables {
		registeredMigrations = append(registeredMigrations, fmt.Sprintf(
			`CREATE TRIGGER IF NOT EXISTS %[1]s_drop_tags AFTER DELETE ON %[1]s BEGIN
				DELETE FROM ec2_tags WHERE account_id = OLD.account_id AND resource_id = OLD.id;
			END`, table))
	}
	prependResetTables([]string{"ec2_tags"})
}

// EC2Tag is one tag on one resource.
type EC2Tag struct {
	ResourceID   string
	ResourceType string // EC2's resourceType: "vpc", "instance", ...
	Key          string
	Value        string
}

// EC2TagMatch selects a tag for DeleteTags: by key, and by value too
// when Value is non-nil.
type EC2TagMatch struct {
	Key   string
	Value *string
}

// PutTags adds tags, overwriting the value of a key already on the
// resource, in one transaction.
func (r *Repository) PutTags(account, region string, tags []EC2Tag) error {
	return r.inTx(func(tx *sql.Tx) error {
		for _, t := range tags {
			if _, err := tx.Exec(
				`INSERT INTO ec2_tags (account_id, region, resource_id, resource_type, key, value) VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (account_id, resource_id, key) DO UPDATE SET value = excluded.value`,
				account, region, t.ResourceID, t.ResourceType, t.Key, t.Value,
			); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteTags removes the matching tags from each resource, or every
// tag on it when matches is empty, in one transaction.
func (r *Repository) DeleteTags(account string, resourceIDs []string, matches []EC2TagMatch) error {
	return r.inTx(func(tx *sql.Tx) error {
		for _, id := range resourceIDs {
			if len(matches) == 0 {
				if _, err := tx.Exec(`DELETE FROM ec2_tags WHERE account_id = ? AND resource_id = ?`, account, id); err != nil {
					return err
				}
			}
			for _, m := range matches {
				if _, err := tx.Exec(
					`DELETE FROM ec2_tags WHERE account_id = ? AND resource_id = ? AND key = ? AND (? IS NULL OR value = ?)`,
					account, id, m.Key, m.Value, m.Value,
				); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ListTags returns the account's tags, optionally scoped to a region
// (empty = all regions), ordered by resource id then key.
func (r *Repository) ListTags(account, region string) ([]EC2Tag, error) {
	rows, err := r.db.Query(
		`SELECT resource_id, resource_type, key, value FROM ec2_tags
		WHERE account_id = ? AND (? = '' OR region = ?) ORDER BY resource_id, key`,
		account, region, region,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EC2Tag
	for rows.Next() {
		var t EC2Tag
		if err := rows.Scan(&t.ResourceID, &t.ResourceType, &t.Key, &t.Value); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *Repository) inTx(fn func(*sql.Tx) error) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
