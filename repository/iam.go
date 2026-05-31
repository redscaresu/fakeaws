// Package repository — IAM tables and CRUD.
//
// Per concepts.md § "Service surface (v1) § IAM": IAM is global,
// uses Query-RPC + XML responses, and is foundational — every other
// service references roles, policies, and instance profiles. Tables
// land in S43-T5 (this file); handler/wire-format work lands in
// S43-T6 (handlers/iam.go).
//
// Schema:
//
//	iam_roles              (account_id, name)               — top-level
//	iam_policies           (account_id, name)               — top-level
//	iam_instance_profiles  (account_id, name)               — top-level,
//	                                                           optional role attachment
//	iam_users              (account_id, name)               — top-level
//	iam_access_keys        (account_id, user_name, id)      — child of iam_users,
//	                                                           ON DELETE CASCADE
//	role_policy_attachments(account_id, role_name, policy_arn)
//	                       — many-to-many between roles and policies,
//	                         ON DELETE CASCADE on role,
//	                         FK-blocked on policy delete (per real IAM:
//	                         you cannot delete an attached policy).
//	instance_profile_roles (account_id, profile_name, role_name)
//	                       — single role per profile (real IAM allows 1),
//	                         ON DELETE CASCADE on profile.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redscaresu/fakeaws/models"
)

// iamMigrations are appended to the universal migrate() statements via
// init() so the repository handles them on every Open. ON DELETE
// CASCADE on child tables keeps Reset() simple (no need to manually
// truncate child rows before parents). ON DELETE RESTRICT on
// role_policy_attachments(policy_arn) is the FK-blocked-delete contract
// — real IAM rejects DeletePolicy when the policy is still attached.
var iamMigrations = []string{
	`CREATE TABLE IF NOT EXISTS iam_roles (
		account_id TEXT NOT NULL,
		name       TEXT NOT NULL,
		path       TEXT NOT NULL DEFAULT '/',
		arn        TEXT NOT NULL,
		data       TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, name)
	)`,
	`CREATE TABLE IF NOT EXISTS iam_policies (
		account_id TEXT NOT NULL,
		name       TEXT NOT NULL,
		path       TEXT NOT NULL DEFAULT '/',
		arn        TEXT NOT NULL,
		data       TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, name)
	)`,
	`CREATE TABLE IF NOT EXISTS iam_instance_profiles (
		account_id TEXT NOT NULL,
		name       TEXT NOT NULL,
		path       TEXT NOT NULL DEFAULT '/',
		arn        TEXT NOT NULL,
		data       TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, name)
	)`,
	`CREATE TABLE IF NOT EXISTS iam_users (
		account_id TEXT NOT NULL,
		name       TEXT NOT NULL,
		path       TEXT NOT NULL DEFAULT '/',
		arn        TEXT NOT NULL,
		data       TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, name)
	)`,
	`CREATE TABLE IF NOT EXISTS iam_access_keys (
		account_id TEXT NOT NULL,
		user_name  TEXT NOT NULL,
		id         TEXT NOT NULL,
		secret     TEXT NOT NULL,
		status     TEXT NOT NULL DEFAULT 'Active',
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, user_name, id),
		FOREIGN KEY (account_id, user_name) REFERENCES iam_users(account_id, name) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS role_policy_attachments (
		account_id TEXT NOT NULL,
		role_name  TEXT NOT NULL,
		policy_arn TEXT NOT NULL,
		PRIMARY KEY (account_id, role_name, policy_arn),
		FOREIGN KEY (account_id, role_name) REFERENCES iam_roles(account_id, name) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS instance_profile_roles (
		account_id   TEXT NOT NULL,
		profile_name TEXT NOT NULL,
		role_name    TEXT NOT NULL,
		PRIMARY KEY (account_id, profile_name),
		FOREIGN KEY (account_id, profile_name) REFERENCES iam_instance_profiles(account_id, name) ON DELETE CASCADE,
		FOREIGN KEY (account_id, role_name)    REFERENCES iam_roles(account_id, name)              ON DELETE RESTRICT
	)`,
}

// init registers IAM tables with the universal migrate() loop and
// appends the truncation order to resetTables. Service tickets follow
// the same pattern.
func init() {
	registeredMigrations = append(registeredMigrations, iamMigrations...)
	// Truncation order: children before parents so even a future Reset
	// that runs FK-ON works. Universal bookkeeping (operations, audit)
	// stays last.
	prependResetTables([]string{
		"role_policy_attachments",
		"instance_profile_roles",
		"iam_access_keys",
		"iam_users",
		"iam_instance_profiles",
		"iam_policies",
		"iam_roles",
	})
}

// IAMRole is the typed wire shape stored in iam_roles.data. The repo
// returns it; handlers translate to the AWS-spec response shape via
// awsproto.WriteQueryRPCResponse.
type IAMRole struct {
	Name                     string            `json:"role_name"`
	Path                     string            `json:"path"`
	ARN                      string            `json:"arn"`
	AssumeRolePolicyDocument string            `json:"assume_role_policy_document"`
	Description              string            `json:"description,omitempty"`
	MaxSessionDuration       int               `json:"max_session_duration,omitempty"`
	Tags                     map[string]string `json:"tags,omitempty"`
	CreatedAt                string            `json:"created_at"`
	Extra                    map[string]any    `json:"extra,omitempty"` // for forward-compat
}

// IAMPolicy mirrors iam_policies.data.
type IAMPolicy struct {
	Name           string         `json:"policy_name"`
	Path           string         `json:"path"`
	ARN            string         `json:"arn"`
	PolicyDocument string         `json:"policy_document"`
	Description    string         `json:"description,omitempty"`
	CreatedAt      string         `json:"created_at"`
	Extra          map[string]any `json:"extra,omitempty"`
}

// IAMInstanceProfile mirrors iam_instance_profiles.data; AttachedRole
// is hydrated from instance_profile_roles on load.
type IAMInstanceProfile struct {
	Name         string `json:"instance_profile_name"`
	Path         string `json:"path"`
	ARN          string `json:"arn"`
	AttachedRole string `json:"attached_role,omitempty"`
	CreatedAt    string `json:"created_at"`
}

// IAMUser mirrors iam_users.data.
type IAMUser struct {
	Name      string `json:"user_name"`
	Path      string `json:"path"`
	ARN       string `json:"arn"`
	CreatedAt string `json:"created_at"`
}

// IAMAccessKey is a child of IAMUser — never returned without its
// parent. Status is "Active" or "Inactive".
type IAMAccessKey struct {
	ID        string `json:"access_key_id"`
	UserName  string `json:"user_name"`
	Secret    string `json:"secret_access_key,omitempty"`
	Status    string `json:"status"`
	CreatedAt string `json:"create_date"`
}

// ----- Roles -----

// CreateRole inserts a role. Returns models.ErrConflict if a role with
// the same name already exists in the account (real IAM rejects the
// duplicate with EntityAlreadyExists; we collapse to ErrConflict and
// let the handler emit the AWS-spec code).
func (r *Repository) CreateRole(account string, role *IAMRole) error {
	body, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("marshal role: %w", err)
	}
	_, err = r.db.Exec(
		`INSERT INTO iam_roles (account_id, name, path, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		account, role.Name, role.Path, role.ARN, string(body), role.CreatedAt,
	)
	if err != nil {
		return mapInsertError(err)
	}
	return nil
}

// GetRole returns the typed role or models.ErrNotFound.
func (r *Repository) GetRole(account, name string) (*IAMRole, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM iam_roles WHERE account_id = ? AND name = ?`, account, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var role IAMRole
	if err := json.Unmarshal([]byte(data), &role); err != nil {
		return nil, fmt.Errorf("unmarshal role: %w", err)
	}
	return &role, nil
}

// ListRoles returns every role in the account, ordered by name for
// deterministic output. Empty account returns an empty slice (not an
// error).
func (r *Repository) ListRoles(account string) ([]*IAMRole, error) {
	rows, err := r.db.Query(`SELECT data FROM iam_roles WHERE account_id = ? ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*IAMRole
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var role IAMRole
		if err := json.Unmarshal([]byte(data), &role); err != nil {
			return nil, fmt.Errorf("unmarshal role: %w", err)
		}
		out = append(out, &role)
	}
	return out, rows.Err()
}

// UpdateRole replaces the stored role. Returns ErrNotFound if no row
// matches. The role's identity columns (name, arn) are immutable —
// callers should run PatchMerge with skipImmutable before calling
// here.
func (r *Repository) UpdateRole(account string, role *IAMRole) error {
	body, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("marshal role: %w", err)
	}
	res, err := r.db.Exec(
		`UPDATE iam_roles SET path = ?, data = ? WHERE account_id = ? AND name = ?`,
		role.Path, string(body), account, role.Name,
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

// DeleteRole removes the role. CASCADE on role_policy_attachments
// drops attachments; instance_profile_roles uses RESTRICT (an instance
// profile referencing the role blocks delete with ErrInUse).
func (r *Repository) DeleteRole(account, name string) error {
	res, err := r.db.Exec(`DELETE FROM iam_roles WHERE account_id = ? AND name = ?`, account, name)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- Policies -----

// SeedManagedPolicy idempotently inserts an AWS-managed policy stub
// keyed by its `arn:aws:iam::aws:policy/<Name>` ARN. Used by the
// AttachRolePolicy handler to lazy-seed any managed ARN the caller
// references — real AWS pre-creates these; fakeaws creates them on
// first contact rather than enumerating the (large + growing) set
// upfront. Re-entry is harmless (INSERT OR IGNORE via the unique
// constraint on arn).
func (r *Repository) SeedManagedPolicy(account, policyARN string) error {
	const prefix = "arn:aws:iam::aws:policy/"
	if !strings.HasPrefix(policyARN, prefix) {
		return nil
	}
	name := strings.TrimPrefix(policyARN, prefix)
	p := &IAMPolicy{
		Name: name, Path: "/", ARN: policyARN,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.Marshal(p)
	_, _ = r.db.Exec(
		`INSERT OR IGNORE INTO iam_policies (account_id, name, path, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		account, p.Name, p.Path, p.ARN, string(body), p.CreatedAt,
	)
	return nil
}

func (r *Repository) CreatePolicy(account string, p *IAMPolicy) error {
	body, _ := json.Marshal(p)
	_, err := r.db.Exec(
		`INSERT INTO iam_policies (account_id, name, path, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		account, p.Name, p.Path, p.ARN, string(body), p.CreatedAt,
	)
	if err != nil {
		return mapInsertError(err)
	}
	return nil
}

func (r *Repository) GetPolicy(account, name string) (*IAMPolicy, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM iam_policies WHERE account_id = ? AND name = ?`, account, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var p IAMPolicy
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *Repository) ListPolicies(account string) ([]*IAMPolicy, error) {
	rows, err := r.db.Query(`SELECT data FROM iam_policies WHERE account_id = ? ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*IAMPolicy
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var p IAMPolicy
		if err := json.Unmarshal([]byte(data), &p); err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// DeletePolicy returns ErrInUse if the policy is still attached to a
// role (real IAM contract: you must DetachRolePolicy first). Returns
// ErrNotFound if the policy doesn't exist.
func (r *Repository) DeletePolicy(account, name string) error {
	// Look up the ARN so we can check role_policy_attachments.
	var arn string
	err := r.db.QueryRow(`SELECT arn FROM iam_policies WHERE account_id = ? AND name = ?`, account, name).Scan(&arn)
	if errors.Is(err, sql.ErrNoRows) {
		return models.ErrNotFound
	}
	if err != nil {
		return err
	}
	var n int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM role_policy_attachments WHERE account_id = ? AND policy_arn = ?`, account, arn).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return models.ErrInUse
	}
	res, err := r.db.Exec(`DELETE FROM iam_policies WHERE account_id = ? AND name = ?`, account, name)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- Instance Profiles -----

func (r *Repository) CreateInstanceProfile(account string, p *IAMInstanceProfile) error {
	body, _ := json.Marshal(p)
	_, err := r.db.Exec(
		`INSERT INTO iam_instance_profiles (account_id, name, path, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		account, p.Name, p.Path, p.ARN, string(body), p.CreatedAt,
	)
	if err != nil {
		return mapInsertError(err)
	}
	return nil
}

func (r *Repository) GetInstanceProfile(account, name string) (*IAMInstanceProfile, error) {
	var data string
	var roleName sql.NullString
	err := r.db.QueryRow(
		`SELECT p.data, r.role_name
		   FROM iam_instance_profiles p
		   LEFT JOIN instance_profile_roles r
		     ON p.account_id = r.account_id AND p.name = r.profile_name
		  WHERE p.account_id = ? AND p.name = ?`,
		account, name,
	).Scan(&data, &roleName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var profile IAMInstanceProfile
	if err := json.Unmarshal([]byte(data), &profile); err != nil {
		return nil, err
	}
	if roleName.Valid {
		profile.AttachedRole = roleName.String
	}
	return &profile, nil
}

func (r *Repository) ListInstanceProfiles(account string) ([]*IAMInstanceProfile, error) {
	rows, err := r.db.Query(
		`SELECT p.name FROM iam_instance_profiles p WHERE p.account_id = ? ORDER BY p.name`,
		account,
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
	out := make([]*IAMInstanceProfile, 0, len(names))
	for _, n := range names {
		p, err := r.GetInstanceProfile(account, n)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (r *Repository) DeleteInstanceProfile(account, name string) error {
	res, err := r.db.Exec(`DELETE FROM iam_instance_profiles WHERE account_id = ? AND name = ?`, account, name)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// AddRoleToInstanceProfile attaches a role to a profile (1:1 in real
// IAM). Returns ErrNotFound if the profile or role doesn't exist;
// ErrConflict if the profile already has a role attached.
func (r *Repository) AddRoleToInstanceProfile(account, profile, role string) error {
	// FK-validate explicitly so we return the right sentinel rather
	// than letting the FK error bubble up as a generic constraint.
	if _, err := r.GetInstanceProfile(account, profile); err != nil {
		return err
	}
	if _, err := r.GetRole(account, role); err != nil {
		return err
	}
	_, err := r.db.Exec(
		`INSERT INTO instance_profile_roles (account_id, profile_name, role_name) VALUES (?, ?, ?)`,
		account, profile, role,
	)
	if err != nil {
		// PRIMARY KEY (account_id, profile_name) — duplicate insert
		// means the profile already has a role attached.
		return mapInsertError(err)
	}
	return nil
}

func (r *Repository) RemoveRoleFromInstanceProfile(account, profile, role string) error {
	res, err := r.db.Exec(
		`DELETE FROM instance_profile_roles WHERE account_id = ? AND profile_name = ? AND role_name = ?`,
		account, profile, role,
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

// ----- Users + Access Keys -----

func (r *Repository) CreateUser(account string, u *IAMUser) error {
	body, _ := json.Marshal(u)
	_, err := r.db.Exec(
		`INSERT INTO iam_users (account_id, name, path, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		account, u.Name, u.Path, u.ARN, string(body), u.CreatedAt,
	)
	if err != nil {
		return mapInsertError(err)
	}
	return nil
}

func (r *Repository) GetUser(account, name string) (*IAMUser, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM iam_users WHERE account_id = ? AND name = ?`, account, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var u IAMUser
	if err := json.Unmarshal([]byte(data), &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *Repository) ListUsers(account string) ([]*IAMUser, error) {
	rows, err := r.db.Query(`SELECT data FROM iam_users WHERE account_id = ? ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*IAMUser
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var u IAMUser
		if err := json.Unmarshal([]byte(data), &u); err != nil {
			return nil, err
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

func (r *Repository) DeleteUser(account, name string) error {
	res, err := r.db.Exec(`DELETE FROM iam_users WHERE account_id = ? AND name = ?`, account, name)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

func (r *Repository) CreateAccessKey(account string, k *IAMAccessKey) error {
	if _, err := r.GetUser(account, k.UserName); err != nil {
		return err
	}
	_, err := r.db.Exec(
		`INSERT INTO iam_access_keys (account_id, user_name, id, secret, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		account, k.UserName, k.ID, k.Secret, k.Status, k.CreatedAt,
	)
	if err != nil {
		return mapInsertError(err)
	}
	return nil
}

// ListAccessKeys returns access keys for an account. Pass userName == ""
// to enumerate every user's keys (account-wide; used by /mock/state's
// IAM gather — Codex pass 10 BLOCKING #1 fix); pass a concrete userName
// to scope to that user (the existing IAM ListAccessKeys handler).
func (r *Repository) ListAccessKeys(account, userName string) ([]*IAMAccessKey, error) {
	var rows *sql.Rows
	var err error
	if userName == "" {
		rows, err = r.db.Query(
			`SELECT user_name, id, status, created_at FROM iam_access_keys WHERE account_id = ? ORDER BY user_name, id`,
			account,
		)
	} else {
		rows, err = r.db.Query(
			`SELECT user_name, id, status, created_at FROM iam_access_keys WHERE account_id = ? AND user_name = ? ORDER BY id`,
			account, userName,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*IAMAccessKey
	for rows.Next() {
		k := &IAMAccessKey{}
		if err := rows.Scan(&k.UserName, &k.ID, &k.Status, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (r *Repository) DeleteAccessKey(account, userName, id string) error {
	res, err := r.db.Exec(
		`DELETE FROM iam_access_keys WHERE account_id = ? AND user_name = ? AND id = ?`,
		account, userName, id,
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

// ----- Role / Policy attachments -----

// AttachRolePolicy inserts a row into role_policy_attachments. FK-
// validates role existence; policy existence is asserted via ARN
// lookup so callers can attach managed policies via ARN without
// knowing the policy's name.
func (r *Repository) AttachRolePolicy(account, role, policyARN string) error {
	if _, err := r.GetRole(account, role); err != nil {
		return err
	}
	// Confirm the policy exists in this account by ARN.
	var n int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM iam_policies WHERE account_id = ? AND arn = ?`, account, policyARN).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return models.ErrNotFound
	}
	_, err := r.db.Exec(
		`INSERT INTO role_policy_attachments (account_id, role_name, policy_arn) VALUES (?, ?, ?)`,
		account, role, policyARN,
	)
	if err != nil {
		return mapInsertError(err)
	}
	return nil
}

// DetachRolePolicy removes an attachment. Returns ErrNotFound if no
// row matches.
func (r *Repository) DetachRolePolicy(account, role, policyARN string) error {
	res, err := r.db.Exec(
		`DELETE FROM role_policy_attachments WHERE account_id = ? AND role_name = ? AND policy_arn = ?`,
		account, role, policyARN,
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

// ListAttachedRolePolicies returns the policy ARNs attached to a role.
func (r *Repository) ListAttachedRolePolicies(account, role string) ([]string, error) {
	rows, err := r.db.Query(
		`SELECT policy_arn FROM role_policy_attachments WHERE account_id = ? AND role_name = ? ORDER BY policy_arn`,
		account, role,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var arn string
		if err := rows.Scan(&arn); err != nil {
			return nil, err
		}
		out = append(out, arn)
	}
	return out, rows.Err()
}
