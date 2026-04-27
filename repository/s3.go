// Package repository — S3 tables and CRUD.
//
// Per concepts.md § "Service surface § S3": bucket-level CRUD only at
// v1. No object payload store; PUT object accepts and discards the
// body, returns the right ETag/headers (handled at the handler layer).
//
// Schema:
//
//   s3_buckets         (account_id, name)               — top-level
//   s3_bucket_configs  (account_id, bucket_name, kind)  — child of s3_buckets,
//                                                          ON DELETE CASCADE
//
// `kind` is one of: versioning, encryption, policy, public_access_block,
// ownership_controls, tagging. We model each config as a row rather
// than separate columns so adding a new sub-resource (e.g. lifecycle,
// CORS) is one INSERT, not a schema migration.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
)

var s3Migrations = []string{
	`CREATE TABLE IF NOT EXISTS s3_buckets (
		account_id TEXT NOT NULL,
		name       TEXT NOT NULL,
		region     TEXT NOT NULL,
		arn        TEXT NOT NULL,
		data       TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, name)
	)`,
	`CREATE TABLE IF NOT EXISTS s3_bucket_configs (
		account_id  TEXT NOT NULL,
		bucket_name TEXT NOT NULL,
		kind        TEXT NOT NULL,
		data        TEXT NOT NULL,
		updated_at  TEXT NOT NULL,
		PRIMARY KEY (account_id, bucket_name, kind),
		FOREIGN KEY (account_id, bucket_name) REFERENCES s3_buckets(account_id, name) ON DELETE CASCADE
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, s3Migrations...)
	prependResetTables([]string{
		"s3_bucket_configs",
		"s3_buckets",
	})
}

// S3Bucket is the typed wire shape stored in s3_buckets.data. AWS
// buckets are global namespace at the wire level but region-scoped at
// the data plane, so we track region as a separate column.
type S3Bucket struct {
	Name      string `json:"name"`
	Region    string `json:"region"`
	ARN       string `json:"arn"`
	CreatedAt string `json:"created_at"`
}

// Bucket-config kind constants. Each maps to one row in
// s3_bucket_configs. Adding a new kind is one INSERT; no migration.
const (
	S3ConfigVersioning         = "versioning"
	S3ConfigEncryption         = "encryption"
	S3ConfigPolicy             = "policy"
	S3ConfigPublicAccessBlock  = "public_access_block"
	S3ConfigOwnershipControls  = "ownership_controls"
	S3ConfigTagging            = "tagging"
)

// ----- Buckets -----

// CreateBucket inserts a new bucket. Returns ErrConflict if a bucket
// with the same name already exists in the account (real S3 returns
// BucketAlreadyOwnedByYou; we collapse to ErrConflict).
func (r *Repository) CreateBucket(account string, b *S3Bucket) error {
	body, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("marshal bucket: %w", err)
	}
	_, err = r.db.Exec(
		`INSERT INTO s3_buckets (account_id, name, region, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		account, b.Name, b.Region, b.ARN, string(body), b.CreatedAt,
	)
	if err != nil {
		return mapInsertError(err)
	}
	return nil
}

func (r *Repository) GetBucket(account, name string) (*S3Bucket, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM s3_buckets WHERE account_id = ? AND name = ?`, account, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var b S3Bucket
	if err := json.Unmarshal([]byte(data), &b); err != nil {
		return nil, fmt.Errorf("unmarshal bucket: %w", err)
	}
	return &b, nil
}

func (r *Repository) ListBuckets(account string) ([]*S3Bucket, error) {
	rows, err := r.db.Query(`SELECT data FROM s3_buckets WHERE account_id = ? ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*S3Bucket
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var b S3Bucket
		if err := json.Unmarshal([]byte(data), &b); err != nil {
			return nil, err
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

// DeleteBucket removes the bucket. CASCADE wipes child configs.
// Real S3 refuses to delete a non-empty bucket — at v1 we don't model
// objects, so deletion is always allowed. (S43-T8 handler layer can
// reject if it ever tracks object counts.)
func (r *Repository) DeleteBucket(account, name string) error {
	res, err := r.db.Exec(`DELETE FROM s3_buckets WHERE account_id = ? AND name = ?`, account, name)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- Bucket configs (versioning, encryption, policy, ...) -----

// PutBucketConfig upserts one config row. The data field is opaque
// JSON — handlers serialise their own typed structs. Caller passes
// kind from the S3Config* constants above.
//
// FK-validates that the bucket exists; otherwise returns ErrNotFound.
func (r *Repository) PutBucketConfig(account, bucket, kind string, payload any) error {
	if _, err := r.GetBucket(account, bucket); err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	_, err = r.db.Exec(
		`INSERT INTO s3_bucket_configs (account_id, bucket_name, kind, data, updated_at)
		 VALUES (?, ?, ?, ?, datetime('now'))
		 ON CONFLICT(account_id, bucket_name, kind) DO UPDATE SET
		   data = excluded.data,
		   updated_at = excluded.updated_at`,
		account, bucket, kind, string(body),
	)
	if err != nil {
		return err
	}
	return nil
}

// GetBucketConfig returns the typed JSON for a bucket config row.
// Caller unmarshals into the right struct. If no row exists with the
// given kind, returns models.ErrNotFound — which handlers map to
// AWS-specific "not configured" responses (real S3 returns the
// resource's default state for some kinds, 404 for others).
func (r *Repository) GetBucketConfig(account, bucket, kind string) (json.RawMessage, error) {
	if _, err := r.GetBucket(account, bucket); err != nil {
		return nil, err
	}
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM s3_bucket_configs WHERE account_id = ? AND bucket_name = ? AND kind = ?`,
		account, bucket, kind,
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// DeleteBucketConfig removes one config row. ErrNotFound if absent.
func (r *Repository) DeleteBucketConfig(account, bucket, kind string) error {
	if _, err := r.GetBucket(account, bucket); err != nil {
		return err
	}
	res, err := r.db.Exec(
		`DELETE FROM s3_bucket_configs WHERE account_id = ? AND bucket_name = ? AND kind = ?`,
		account, bucket, kind,
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

// ListBucketConfigs returns the (kind, data) pairs for a bucket's
// configs. Used by /mock/state to surface the full config surface.
func (r *Repository) ListBucketConfigs(account, bucket string) (map[string]json.RawMessage, error) {
	rows, err := r.db.Query(
		`SELECT kind, data FROM s3_bucket_configs WHERE account_id = ? AND bucket_name = ?`,
		account, bucket,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var kind, data string
		if err := rows.Scan(&kind, &data); err != nil {
			return nil, err
		}
		out[kind] = json.RawMessage(data)
	}
	return out, rows.Err()
}
