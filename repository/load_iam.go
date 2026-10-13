package repository

// load_iam.go — a load's writes and reads of IAM roles, their inline
// and attached policies and their instance profiles. A load holds one
// account, so a read names a row by its name alone.

import (
	"database/sql"
	"encoding/json"
	"errors"
)

// LoadRole stores a recorded role and its tags.
func (lt *LoadTx) LoadRole(account string, role *IAMRole, tags map[string]string) error {
	if err := insertRole(lt, account, role); err != nil {
		return err
	}
	for k, v := range tags {
		if _, err := lt.Exec(`INSERT INTO resource_tags (account_id, arn, key, value) VALUES (?, ?, ?, ?)`,
			account, role.ARN, k, v); err != nil {
			return err
		}
	}
	return nil
}

// RoleLoaded reports whether the load stored role, so a write naming it
// can refuse rather than fail its foreign key.
func (lt *LoadTx) RoleLoaded(account, role string) (bool, error) {
	var one int
	err := lt.QueryRow(`SELECT 1 FROM iam_roles WHERE account_id = ? AND name = ?`, account, role).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// LoadRolePolicy stores a role's inline policy, its document decoded.
func (lt *LoadTx) LoadRolePolicy(account, role, name, document string) error {
	_, err := lt.Exec(`INSERT INTO role_inline_policies (account_id, role_name, name, document) VALUES (?, ?, ?, ?)`,
		account, role, name, document)
	return err
}

// LoadRolePolicyAttachment attaches policyARN to role. It seeds no
// policy row: role_policy_attachments names a policy by ARN alone.
func (lt *LoadTx) LoadRolePolicyAttachment(account, role, policyARN string) error {
	_, err := lt.Exec(`INSERT INTO role_policy_attachments (account_id, role_name, policy_arn) VALUES (?, ?, ?)`,
		account, role, policyARN)
	return err
}

// LoadInstanceProfile stores a recorded profile and, unless role is "",
// its binding to role.
func (lt *LoadTx) LoadInstanceProfile(account string, p *IAMInstanceProfile, role string) error {
	if err := insertInstanceProfile(lt, account, p); err != nil || role == "" {
		return err
	}
	_, err := lt.Exec(`INSERT INTO instance_profile_roles (account_id, profile_name, role_name) VALUES (?, ?, ?)`,
		account, p.Name, role)
	return err
}

// LoadedRole reads a stored role and its tags back, nil when there is
// none.
func (lt *LoadTx) LoadedRole(name string) (*IAMRole, map[string]string, error) {
	var data string
	err := lt.QueryRow(`SELECT data FROM iam_roles WHERE name = ?`, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var role IAMRole
	if err := json.Unmarshal([]byte(data), &role); err != nil {
		return nil, nil, err
	}
	tags := map[string]string{}
	for scan, err := range lt.Query(`SELECT key, value FROM resource_tags WHERE arn = ?`, role.ARN) {
		if err != nil {
			return nil, nil, err
		}
		var k, v string
		if err := scan(&k, &v); err != nil {
			return nil, nil, err
		}
		tags[k] = v
	}
	return &role, tags, nil
}

// LoadedRolePolicy reads a stored inline policy's document back; ok is
// false when there is none.
func (lt *LoadTx) LoadedRolePolicy(role, name string) (document string, ok bool, err error) {
	err = lt.QueryRow(`SELECT document FROM role_inline_policies WHERE role_name = ? AND name = ?`, role, name).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return document, err == nil, err
}

// RolePolicyAttached reports whether policyARN is stored attached to
// role.
func (lt *LoadTx) RolePolicyAttached(role, policyARN string) (bool, error) {
	var one int
	err := lt.QueryRow(`SELECT 1 FROM role_policy_attachments WHERE role_name = ? AND policy_arn = ?`, role, policyARN).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// LoadedInstanceProfile reads a stored profile back with its bound
// role, nil when there is none.
func (lt *LoadTx) LoadedInstanceProfile(name string) (*IAMInstanceProfile, error) {
	p, err := scanInstanceProfile(lt.QueryRow(instanceProfileSelect+` WHERE p.name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return p, err
}
