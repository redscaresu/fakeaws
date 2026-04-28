// Package repository — DynamoDB tables and items.
//
// Per fakeaws/PLAN.md § "Phase 3 — Stateful data (S45)" — DynamoDB
// at v1 supports table CRUD plus minimal item ops (PutItem,
// GetItem, UpdateItem, DeleteItem, Query, Scan). GSI/LSI are
// explicitly OUT OF SCOPE per concepts.md § "Resource coverage
// matrix § DynamoDB" — global_secondary_index / local_secondary_index
// HCL blocks are silently ignored at the handler layer.
//
// Item PK shape: tables have a hash_key (PK) and optional range_key
// (SK). Items are stored with the canonical shape:
//
//   PRIMARY KEY (account_id, table_name, hash_value, range_value)
//
// where range_value is "" (empty string) for tables with no SK —
// keeps the primary-key tuple uniform.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/redscaresu/fakeaws/models"
)

var dynamodbMigrations = []string{
	`CREATE TABLE IF NOT EXISTS dynamodb_tables (
		account_id   TEXT NOT NULL,
		region       TEXT NOT NULL,
		name         TEXT NOT NULL,
		hash_key     TEXT NOT NULL,
		range_key    TEXT NOT NULL DEFAULT '',
		attributes   TEXT NOT NULL DEFAULT '[]',
		billing_mode TEXT NOT NULL DEFAULT 'PAY_PER_REQUEST',
		status       TEXT NOT NULL DEFAULT 'ACTIVE',
		arn          TEXT NOT NULL,
		data         TEXT NOT NULL,
		created_at   TEXT NOT NULL,
		PRIMARY KEY (account_id, region, name)
	)`,
	`CREATE TABLE IF NOT EXISTS dynamodb_items (
		account_id  TEXT NOT NULL,
		region      TEXT NOT NULL,
		table_name  TEXT NOT NULL,
		hash_value  TEXT NOT NULL,
		range_value TEXT NOT NULL DEFAULT '',
		item        TEXT NOT NULL,
		PRIMARY KEY (account_id, table_name, hash_value, range_value),
		FOREIGN KEY (account_id, region, table_name)
		    REFERENCES dynamodb_tables(account_id, region, name) ON DELETE CASCADE
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, dynamodbMigrations...)
	prependResetTables([]string{
		"dynamodb_items",
		"dynamodb_tables",
	})
}

// ----- Typed wire shapes -----

type DynamoDBAttributeDef struct {
	Name string `json:"name"`
	Type string `json:"type"` // S | N | B
}

type DynamoDBTable struct {
	Name        string                 `json:"name"`
	HashKey     string                 `json:"hash_key"`
	RangeKey    string                 `json:"range_key,omitempty"`
	Attributes  []DynamoDBAttributeDef `json:"attributes"`
	BillingMode string                 `json:"billing_mode"`
	Status      string                 `json:"status"`
	Region      string                 `json:"region"`
	ARN         string                 `json:"arn"`
	CreatedAt   string                 `json:"created_at"`
}

type DynamoDBItem struct {
	TableName  string `json:"table_name"`
	HashValue  string `json:"hash_value"`
	RangeValue string `json:"range_value,omitempty"`
	// Item is the opaque AttributeValue map as the AWS provider
	// produces it — `{"name": {"S": "alice"}, "age": {"N": "30"}}`.
	// Stored as JSON; handlers don't introspect it beyond the PK.
	Item json.RawMessage `json:"item"`
}

// ----- Table CRUD -----

func (r *Repository) CreateDynamoDBTable(account string, t *DynamoDBTable) error {
	if t.BillingMode == "" {
		t.BillingMode = "PAY_PER_REQUEST"
	}
	if t.Status == "" {
		t.Status = "ACTIVE"
	}
	body, _ := json.Marshal(t)
	attrJSON, _ := json.Marshal(t.Attributes)
	_, err := r.db.Exec(
		`INSERT INTO dynamodb_tables (account_id, region, name, hash_key, range_key, attributes, billing_mode, status, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, t.Region, t.Name, t.HashKey, t.RangeKey, string(attrJSON),
		t.BillingMode, t.Status, t.ARN, string(body), t.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetDynamoDBTable(account, region, name string) (*DynamoDBTable, error) {
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM dynamodb_tables WHERE account_id = ? AND region = ? AND name = ?`,
		account, region, name,
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var t DynamoDBTable
	if err := json.Unmarshal([]byte(data), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *Repository) ListDynamoDBTables(account, region string) ([]*DynamoDBTable, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM dynamodb_tables WHERE account_id = ? ORDER BY name`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM dynamodb_tables WHERE account_id = ? AND region = ? ORDER BY name`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DynamoDBTable
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var t DynamoDBTable
		if err := json.Unmarshal([]byte(data), &t); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

func (r *Repository) DeleteDynamoDBTable(account, region, name string) error {
	res, err := r.db.Exec(
		`DELETE FROM dynamodb_tables WHERE account_id = ? AND region = ? AND name = ?`,
		account, region, name,
	)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- Item CRUD -----

func (r *Repository) PutDynamoDBItem(account, region string, item *DynamoDBItem) error {
	if _, err := r.GetDynamoDBTable(account, region, item.TableName); err != nil {
		return err
	}
	// PutItem is upsert by PK at AWS (replaces any existing item with
	// the same hash+range). INSERT OR REPLACE matches that contract.
	_, err := r.db.Exec(
		`INSERT OR REPLACE INTO dynamodb_items (account_id, region, table_name, hash_value, range_value, item) VALUES (?, ?, ?, ?, ?, ?)`,
		account, region, item.TableName, item.HashValue, item.RangeValue, string(item.Item),
	)
	return err
}

func (r *Repository) GetDynamoDBItem(account, region, tableName, hashValue, rangeValue string) (*DynamoDBItem, error) {
	var raw string
	err := r.db.QueryRow(
		`SELECT item FROM dynamodb_items WHERE account_id = ? AND table_name = ? AND hash_value = ? AND range_value = ?`,
		account, tableName, hashValue, rangeValue,
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &DynamoDBItem{
		TableName: tableName, HashValue: hashValue, RangeValue: rangeValue,
		Item: json.RawMessage(raw),
	}, nil
}

func (r *Repository) DeleteDynamoDBItem(account, region, tableName, hashValue, rangeValue string) error {
	res, err := r.db.Exec(
		`DELETE FROM dynamodb_items WHERE account_id = ? AND table_name = ? AND hash_value = ? AND range_value = ?`,
		account, tableName, hashValue, rangeValue,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ScanDynamoDBTable returns every item in the table — at v1 there's
// no filter expression evaluation, so Scan and Query both come back
// as full-table reads. Handlers can post-filter in Go if needed.
func (r *Repository) ScanDynamoDBTable(account, region, tableName string) ([]*DynamoDBItem, error) {
	if _, err := r.GetDynamoDBTable(account, region, tableName); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(
		`SELECT hash_value, range_value, item FROM dynamodb_items WHERE account_id = ? AND table_name = ? ORDER BY hash_value, range_value`,
		account, tableName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DynamoDBItem
	for rows.Next() {
		var hv, rv, raw string
		if err := rows.Scan(&hv, &rv, &raw); err != nil {
			return nil, err
		}
		out = append(out, &DynamoDBItem{
			TableName: tableName, HashValue: hv, RangeValue: rv,
			Item: json.RawMessage(raw),
		})
	}
	return out, rows.Err()
}
