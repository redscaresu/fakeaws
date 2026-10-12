// Package repository — KMS keys.
//
// One row per key. Being a row is what puts a key in /mock/reset,
// snapshot and restore, and in the identity guard's empty check. The
// key's mutable fields live in the JSON data column; UpdateKMSKey reads
// and writes it in one transaction.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/redscaresu/fakeaws/models"
)

func init() {
	registeredMigrations = append(registeredMigrations, `CREATE TABLE IF NOT EXISTS kms_keys (
		account_id TEXT NOT NULL,
		region     TEXT NOT NULL,
		key_id     TEXT NOT NULL,
		data       TEXT NOT NULL,
		PRIMARY KEY (account_id, region, key_id)
	)`)
	prependResetTables([]string{"kms_keys"})
}

// KMSKey is a stored key. KeyID and Region are columns, the rest data.
type KMSKey struct {
	KeyID           string            `json:"-"`
	Region          string            `json:"-"`
	State           string            `json:"state"`
	Created         time.Time         `json:"created"`
	DeletionDate    *time.Time        `json:"deletion_date,omitempty"`
	RotationEnabled bool              `json:"rotation_enabled"`
	Description     string            `json:"description"`
	Tags            map[string]string `json:"tags"`
}

// CreateKMSKey inserts k under account.
func (r *Repository) CreateKMSKey(account string, k *KMSKey) error {
	data, err := json.Marshal(k)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(`INSERT INTO kms_keys (account_id, region, key_id, data) VALUES (?, ?, ?, ?)`,
		account, k.Region, k.KeyID, string(data))
	return mapInsertError(err)
}

func scanKMSKey(row interface{ Scan(...any) error }) (*KMSKey, error) {
	var k KMSKey
	var data string
	if err := row.Scan(&k.Region, &k.KeyID, &data); err != nil {
		return nil, err
	}
	return &k, json.Unmarshal([]byte(data), &k)
}

func getKMSKey(q interface {
	QueryRow(string, ...any) *sql.Row
}, account, region, keyID string) (*KMSKey, error) {
	k, err := scanKMSKey(q.QueryRow(`SELECT region, key_id, data FROM kms_keys WHERE account_id = ? AND region = ? AND key_id = ?`,
		account, region, keyID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	return k, err
}

// GetKMSKey returns models.ErrNotFound for an unknown key.
func (r *Repository) GetKMSKey(account, region, keyID string) (*KMSKey, error) {
	return getKMSKey(r.db, account, region, keyID)
}

// ListKMSKeys lists a region's keys by key id.
func (r *Repository) ListKMSKeys(account, region string) ([]KMSKey, error) {
	rows, err := r.db.Query(`SELECT region, key_id, data FROM kms_keys WHERE account_id = ? AND region = ? ORDER BY key_id`, account, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KMSKey
	for rows.Next() {
		k, err := scanKMSKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// UpdateKMSKey applies mutate to the stored key and writes it back, in
// one transaction, so concurrent updates never lose one another.
// models.ErrNotFound for an unknown key.
func (r *Repository) UpdateKMSKey(account, region, keyID string, mutate func(*KMSKey)) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	k, err := getKMSKey(tx, account, region, keyID)
	if err != nil {
		return err
	}
	mutate(k)
	data, err := json.Marshal(k)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE kms_keys SET data = ? WHERE account_id = ? AND region = ? AND key_id = ?`,
		string(data), account, region, keyID); err != nil {
		return err
	}
	return tx.Commit()
}
