package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/redscaresu/fakeaws/models"
)

// Identity is the account fakeaws answers as, and a region that is
// stored but not read yet. The JSON tags are the POST /mock/identity body.
type Identity struct {
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}

func init() {
	registeredMigrations = append(registeredMigrations, `CREATE TABLE IF NOT EXISTS identity (
		id         INTEGER PRIMARY KEY CHECK(id=1),
		account_id TEXT NOT NULL,
		region     TEXT NOT NULL DEFAULT '',
		loaded     INTEGER NOT NULL DEFAULT 0
	)`)
	prependResetTables([]string{"identity"})
}

// emptyExclusions are the reset tables isEmpty skips whole: bookkeeping
// and the identity itself. It also skips ec2_amis rows whose id is a
// fixture AMI id. A story that seeds rows at boot adds them here, or no
// database reads as empty. KMS keys live in kmsStore, not in rows, so
// isEmpty does not see them.
var emptyExclusions = map[string]bool{"operations": true, "audit": true, "identity": true}

// GetIdentity returns the stored identity, or sql.ErrNoRows when none
// is stored.
func (r *Repository) GetIdentity() (Identity, error) {
	var id Identity
	err := r.db.QueryRow(`SELECT account_id, region FROM identity WHERE id = 1`).Scan(&id.AccountID, &id.Region)
	return id, err
}

// SetIdentity stores id. When its account differs from the stored one
// (defaultAccount when none is stored) and the database is not empty,
// it returns models.ErrConflict naming both and writes nothing. The
// stored account with no region or the stored one writes nothing. The
// read, the empty check and the write share one transaction.
func (r *Repository) SetIdentity(id Identity, defaultAccount string, fixtureAMIIDs []string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stored := Identity{AccountID: defaultAccount}
	err = tx.QueryRow(`SELECT account_id, region FROM identity WHERE id = 1`).Scan(&stored.AccountID, &stored.Region)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if stored.AccountID == id.AccountID && (id.Region == "" || id.Region == stored.Region) {
		return nil
	}
	if stored.AccountID != id.AccountID {
		empty, err := isEmpty(tx, fixtureAMIIDs)
		if err != nil {
			return err
		}
		if !empty {
			return fmt.Errorf("%w: account %s refused: the database is not empty and holds account %s",
				models.ErrConflict, id.AccountID, stored.AccountID)
		}
	}
	if _, err := tx.Exec(`INSERT INTO identity (id, account_id, region) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET account_id = excluded.account_id, region = excluded.region`,
		id.AccountID, id.Region); err != nil {
		return err
	}
	return tx.Commit()
}

// isEmpty reports whether no reset table holds a row outside
// emptyExclusions and the fixture AMIs.
func isEmpty(tx *sql.Tx, fixtureAMIIDs []string) (bool, error) {
	for _, table := range resetTables {
		if emptyExclusions[table] {
			continue
		}
		q, args := "SELECT EXISTS (SELECT 1 FROM "+table+")", []any(nil)
		if table == "ec2_amis" {
			q = "SELECT EXISTS (SELECT 1 FROM ec2_amis WHERE id NOT IN (" +
				strings.TrimSuffix(strings.Repeat("?,", len(fixtureAMIIDs)), ",") + "))"
			for _, ami := range fixtureAMIIDs {
				args = append(args, ami)
			}
		}
		var found bool
		if err := tx.QueryRow(q, args...).Scan(&found); err != nil {
			return false, fmt.Errorf("empty check %s: %w", table, err)
		}
		if found {
			return false, nil
		}
	}
	return true, nil
}
