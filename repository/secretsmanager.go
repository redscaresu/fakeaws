// Package repository — Secrets Manager secrets + versions.
//
// Per fakeaws/PLAN.md § "Phase 5 — DNS + secrets (S47)":
// Secrets Manager has a 3-state machine — Active → PendingDeletion →
// Destroyed. DeleteSecret with `recovery_window_in_days > 0` schedules
// deletion; secret remains in PendingDeletion until the window
// elapses or RestoreSecret reverses. RestoreSecret on a fully-
// destroyed secret returns 409 (concepts.md "Standing patterns"
// item 9 — terminal-state refusal).
//
// Versions track AWSCURRENT / AWSPREVIOUS stage labels — AWSCURRENT
// moves to the new version on each PutSecretValue; the prior version
// becomes AWSPREVIOUS.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
)

const (
	SecretStateActive          = "Active"
	SecretStatePendingDeletion = "PendingDeletion"
	SecretStateDestroyed       = "Destroyed"
)

var secretsmanagerMigrations = []string{
	`CREATE TABLE IF NOT EXISTS secretsmanager_secrets (
		account_id              TEXT NOT NULL,
		region                  TEXT NOT NULL,
		name                    TEXT NOT NULL,
		arn                     TEXT NOT NULL,
		description             TEXT NOT NULL DEFAULT '',
		kms_key_id              TEXT NOT NULL DEFAULT '',
		recovery_window_in_days INTEGER NOT NULL DEFAULT 30,
		deleted_at              TEXT NOT NULL DEFAULT '',
		state                   TEXT NOT NULL DEFAULT 'Active',
		tags                    TEXT NOT NULL DEFAULT '{}',
		created_at              TEXT NOT NULL,
		PRIMARY KEY (account_id, region, name)
	)`,
	`CREATE TABLE IF NOT EXISTS secretsmanager_versions (
		account_id  TEXT NOT NULL,
		region      TEXT NOT NULL,
		secret_name TEXT NOT NULL,
		version_id  TEXT NOT NULL,
		secret_string TEXT NOT NULL DEFAULT '',
		stages      TEXT NOT NULL DEFAULT '[]',
		created_at  TEXT NOT NULL,
		PRIMARY KEY (account_id, region, secret_name, version_id),
		FOREIGN KEY (account_id, region, secret_name) REFERENCES secretsmanager_secrets(account_id, region, name) ON DELETE CASCADE
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, secretsmanagerMigrations...)
	prependResetTables([]string{
		"secretsmanager_versions",
		"secretsmanager_secrets",
	})
}

// ----- Typed wire shapes -----

type SecretsManagerSecret struct {
	Name                  string            `json:"name"`
	ARN                   string            `json:"arn"`
	Description           string            `json:"description,omitempty"`
	KMSKeyID              string            `json:"kms_key_id,omitempty"`
	RecoveryWindowInDays  int               `json:"recovery_window_in_days"`
	DeletedAt             string            `json:"deleted_at,omitempty"`
	State                 string            `json:"state"`
	Tags                  map[string]string `json:"tags,omitempty"`
	Region                string            `json:"region"`
	CreatedAt             string            `json:"created_at"`
}

type SecretsManagerVersion struct {
	SecretName   string   `json:"secret_name"`
	VersionID    string   `json:"version_id"`
	SecretString string   `json:"secret_string,omitempty"`
	Stages       []string `json:"stages,omitempty"`
	Region       string   `json:"region"`
	CreatedAt    string   `json:"created_at"`
}

// ----- Secret CRUD -----

func (r *Repository) CreateSecret(account string, s *SecretsManagerSecret) error {
	if s.State == "" {
		s.State = SecretStateActive
	}
	if s.RecoveryWindowInDays == 0 {
		s.RecoveryWindowInDays = 30
	}
	tagsJSON := "{}"
	if s.Tags != nil {
		b, _ := json.Marshal(s.Tags)
		tagsJSON = string(b)
	}
	_, err := r.db.Exec(
		`INSERT INTO secretsmanager_secrets (account_id, region, name, arn, description, kms_key_id, recovery_window_in_days, deleted_at, state, tags, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, s.Region, s.Name, s.ARN, s.Description, s.KMSKeyID,
		s.RecoveryWindowInDays, s.DeletedAt, s.State, tagsJSON, s.CreatedAt,
	)
	return mapInsertError(err)
}

// GetSecret returns the secret row regardless of state. Callers that
// must enforce the "Destroyed = not found" contract use
// GetSecretActiveOrPending which gates the read.
func (r *Repository) GetSecret(account, region, name string) (*SecretsManagerSecret, error) {
	var s SecretsManagerSecret
	var tagsJSON string
	err := r.db.QueryRow(
		`SELECT name, arn, description, kms_key_id, recovery_window_in_days, deleted_at, state, tags, region, created_at
		 FROM secretsmanager_secrets WHERE account_id = ? AND region = ? AND name = ?`,
		account, region, name,
	).Scan(&s.Name, &s.ARN, &s.Description, &s.KMSKeyID, &s.RecoveryWindowInDays,
		&s.DeletedAt, &s.State, &tagsJSON, &s.Region, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(tagsJSON), &s.Tags)
	return &s, nil
}

// GetSecretActiveOrPending returns the secret only if its state is
// not Destroyed. DescribeSecret + GetSecretValue use this — the
// "fully destroyed" contract from concepts.md (Codex pass 2
// BLOCKING #2 fix).
func (r *Repository) GetSecretActiveOrPending(account, region, name string) (*SecretsManagerSecret, error) {
	s, err := r.GetSecret(account, region, name)
	if err != nil {
		return nil, err
	}
	if s.State == SecretStateDestroyed {
		return nil, models.ErrNotFound
	}
	return s, nil
}

// ListSecrets returns secrets that are NOT in the Destroyed state.
// Per concepts.md "fully destroyed" contract — destroyed secrets
// must behave as not-found across read/list paths (Codex pass 2
// BLOCKING #2).
func (r *Repository) ListSecrets(account, region string) ([]*SecretsManagerSecret, error) {
	rows, err := r.db.Query(
		`SELECT name FROM secretsmanager_secrets WHERE account_id = ? AND region = ? AND state != ? ORDER BY name`,
		account, region, SecretStateDestroyed,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	out := make([]*SecretsManagerSecret, 0, len(names))
	for _, n := range names {
		s, err := r.GetSecret(account, region, n)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// ScheduleSecretDeletion moves the secret to PendingDeletion (or
// directly to Destroyed if recoveryWindowInDays==0). Per concepts.md
// "Standing patterns" item 9 — terminal-state refusal: trying to
// delete an already-Destroyed secret is rejected.
func (r *Repository) ScheduleSecretDeletion(account, region, name string, recoveryWindowInDays int, now string) (*SecretsManagerSecret, error) {
	s, err := r.GetSecret(account, region, name)
	if err != nil {
		return nil, err
	}
	if s.State == SecretStateDestroyed {
		return nil, fmt.Errorf("secret %q already destroyed: %w", name, models.ErrConflict)
	}
	newState := SecretStatePendingDeletion
	if recoveryWindowInDays == 0 {
		newState = SecretStateDestroyed
	}
	if _, err := r.db.Exec(
		`UPDATE secretsmanager_secrets SET state = ?, deleted_at = ?, recovery_window_in_days = ? WHERE account_id = ? AND region = ? AND name = ?`,
		newState, now, recoveryWindowInDays, account, region, name,
	); err != nil {
		return nil, err
	}
	return r.GetSecret(account, region, name)
}

// RestoreSecret reverses scheduled deletion. RestoreSecret on a
// Destroyed secret returns 409 (concepts.md item 9).
func (r *Repository) RestoreSecret(account, region, name string) (*SecretsManagerSecret, error) {
	s, err := r.GetSecret(account, region, name)
	if err != nil {
		return nil, err
	}
	if s.State == SecretStateDestroyed {
		return nil, fmt.Errorf("secret %q is destroyed and cannot be restored: %w", name, models.ErrConflict)
	}
	if s.State == SecretStateActive {
		return s, nil
	}
	if _, err := r.db.Exec(
		`UPDATE secretsmanager_secrets SET state = ?, deleted_at = '' WHERE account_id = ? AND region = ? AND name = ?`,
		SecretStateActive, account, region, name,
	); err != nil {
		return nil, err
	}
	return r.GetSecret(account, region, name)
}

// ----- Versions -----

// PutSecretValue creates a new version. AWSCURRENT moves to the new
// version, the prior version becomes AWSPREVIOUS.
func (r *Repository) PutSecretValue(account, region, name string, v *SecretsManagerVersion) error {
	if _, err := r.GetSecret(account, region, name); err != nil {
		return err
	}
	// Demote any existing AWSCURRENT to AWSPREVIOUS.
	rows, err := r.db.Query(
		`SELECT version_id, stages FROM secretsmanager_versions WHERE account_id = ? AND region = ? AND secret_name = ?`,
		account, region, name,
	)
	if err != nil {
		return err
	}
	type vrow struct {
		id     string
		stages []string
	}
	var versions []vrow
	for rows.Next() {
		var vid, stagesJSON string
		if err := rows.Scan(&vid, &stagesJSON); err != nil {
			rows.Close()
			return err
		}
		var stages []string
		_ = json.Unmarshal([]byte(stagesJSON), &stages)
		versions = append(versions, vrow{id: vid, stages: stages})
	}
	rows.Close()
	for _, vr := range versions {
		newStages := make([]string, 0, len(vr.stages))
		for _, st := range vr.stages {
			switch st {
			case "AWSCURRENT":
				newStages = append(newStages, "AWSPREVIOUS")
			case "AWSPREVIOUS":
				// drop — only one AWSPREVIOUS at a time
			default:
				newStages = append(newStages, st)
			}
		}
		stagesJSON, _ := json.Marshal(newStages)
		if _, err := r.db.Exec(
			`UPDATE secretsmanager_versions SET stages = ? WHERE account_id = ? AND region = ? AND secret_name = ? AND version_id = ?`,
			string(stagesJSON), account, region, name, vr.id,
		); err != nil {
			return err
		}
	}
	if v.Stages == nil {
		v.Stages = []string{"AWSCURRENT"}
	}
	stagesJSON, _ := json.Marshal(v.Stages)
	_, err = r.db.Exec(
		`INSERT INTO secretsmanager_versions (account_id, region, secret_name, version_id, secret_string, stages, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, region, name, v.VersionID, v.SecretString, string(stagesJSON), v.CreatedAt,
	)
	return mapInsertError(err)
}

// GetSecretValue returns the version with the given stage, defaulting
// to AWSCURRENT. Destroyed secrets behave as not-found (Codex pass 2
// BLOCKING #2 — "fully destroyed" contract).
func (r *Repository) GetSecretValue(account, region, name, versionStage, versionID string) (*SecretsManagerVersion, error) {
	if _, err := r.GetSecretActiveOrPending(account, region, name); err != nil {
		return nil, err
	}
	if versionStage == "" && versionID == "" {
		versionStage = "AWSCURRENT"
	}
	rows, err := r.db.Query(
		`SELECT version_id, secret_string, stages, created_at FROM secretsmanager_versions WHERE account_id = ? AND region = ? AND secret_name = ?`,
		account, region, name,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v SecretsManagerVersion
		var stagesJSON string
		v.SecretName = name
		v.Region = region
		if err := rows.Scan(&v.VersionID, &v.SecretString, &stagesJSON, &v.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(stagesJSON), &v.Stages)
		if versionID != "" && v.VersionID == versionID {
			return &v, nil
		}
		if versionStage != "" {
			for _, st := range v.Stages {
				if st == versionStage {
					return &v, nil
				}
			}
		}
	}
	return nil, models.ErrNotFound
}

// DeleteSecretImmediately is a maintenance hook for tests + the
// state-machine harness; production code goes through
// ScheduleSecretDeletion. Bypasses the recovery window.
func (r *Repository) DeleteSecretImmediately(account, region, name string) error {
	res, err := r.db.Exec(
		`DELETE FROM secretsmanager_secrets WHERE account_id = ? AND region = ? AND name = ?`,
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
