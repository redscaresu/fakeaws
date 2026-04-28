// Package repository — EC2 compute tables and CRUD.
//
// Per fakeaws/PLAN.md § "Phase 2 — Networking + compute (S44)":
// compute lands in S44-T6 atop the networking schema from S44-T3.
//
// FK chain (compute side):
//   ec2_instances.subnet_id        → ec2_subnets.id     (FK, RESTRICT)
//   ec2_instances.iam_instance_profile_name
//                                  → iam_instance_profiles.name (cross-service FK, nullable)
//   ec2_instances.vpc_security_group_ids
//                                  JSON column — handler validates at create/modify time
//
// ON DELETE RESTRICT on subnet_id is the load-bearing bit: a subnet
// that still has running instances cannot be deleted; real EC2's
// DeleteSubnet returns DependencyViolation in that case.
//
// AMIs are read-only at v1 — handlers/ec2.go ships a fixture set
// (ami-0abcd1234 etc.) and the repository just stores the set so
// DescribeImages can echo it back. terraform-provider-aws's
// data.aws_ami is NOT supported; scenarios use literal AMI ids per
// the S44-T0 pitfall.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/redscaresu/fakeaws/models"
)

var ec2ComputeMigrations = []string{
	`CREATE TABLE IF NOT EXISTS ec2_instances (
		account_id              TEXT NOT NULL,
		region                  TEXT NOT NULL,
		id                      TEXT NOT NULL,
		subnet_id               TEXT NOT NULL,
		ami_id                  TEXT NOT NULL,
		instance_type           TEXT NOT NULL,
		iam_instance_profile_name TEXT,
		vpc_security_group_ids  TEXT NOT NULL DEFAULT '[]',
		state                   TEXT NOT NULL DEFAULT 'running',
		arn                     TEXT NOT NULL,
		data                    TEXT NOT NULL,
		created_at              TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, subnet_id) REFERENCES ec2_subnets(account_id, id) ON DELETE RESTRICT
	)`,
	// ec2_key_pairs is keyed by name (the AWS contract — names are
	// per-account-per-region unique).
	`CREATE TABLE IF NOT EXISTS ec2_key_pairs (
		account_id  TEXT NOT NULL,
		region      TEXT NOT NULL,
		name        TEXT NOT NULL,
		public_key  TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		data        TEXT NOT NULL,
		created_at  TEXT NOT NULL,
		PRIMARY KEY (account_id, region, name)
	)`,
	`CREATE TABLE IF NOT EXISTS ec2_amis (
		account_id           TEXT NOT NULL,
		region               TEXT NOT NULL,
		id                   TEXT NOT NULL,
		name                 TEXT NOT NULL,
		owner_id             TEXT NOT NULL,
		virtualization_type  TEXT NOT NULL DEFAULT 'hvm',
		root_device_name     TEXT NOT NULL DEFAULT '/dev/xvda',
		data                 TEXT NOT NULL,
		PRIMARY KEY (account_id, region, id)
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, ec2ComputeMigrations...)
	prependResetTables([]string{
		"ec2_instances",
		"ec2_key_pairs",
		"ec2_amis",
	})
}

// ----- Typed wire shapes -----

type EC2Instance struct {
	ID                      string   `json:"instance_id"`
	SubnetID                string   `json:"subnet_id"`
	AMIID                   string   `json:"ami_id"`
	InstanceType            string   `json:"instance_type"`
	IAMInstanceProfileName  string   `json:"iam_instance_profile_name,omitempty"`
	VPCSecurityGroupIDs     []string `json:"vpc_security_group_ids,omitempty"`
	State                   string   `json:"state"`
	Region                  string   `json:"region"`
	ARN                     string   `json:"arn"`
	CreatedAt               string   `json:"created_at"`
}

type EC2KeyPair struct {
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Region      string `json:"region"`
	CreatedAt   string `json:"created_at"`
}

type EC2AMI struct {
	ID                 string `json:"ami_id"`
	Name               string `json:"name"`
	OwnerID            string `json:"owner_id"`
	VirtualizationType string `json:"virtualization_type"`
	RootDeviceName     string `json:"root_device_name"`
	Region             string `json:"region"`
}

// ----- Instance CRUD -----

func (r *Repository) CreateInstance(account string, inst *EC2Instance) error {
	// Validate parent subnet (FK enforces, but the explicit lookup
	// produces a clean ErrNotFound rather than a SQLite constraint
	// violation that maps awkwardly). Codex pass 7 BLOCKING #1 — parent
	// must be in the same region.
	if _, err := r.GetSubnet(account, inst.Region, inst.SubnetID); err != nil {
		return err
	}
	if inst.IAMInstanceProfileName != "" {
		if _, err := r.GetInstanceProfile(account, inst.IAMInstanceProfileName); err != nil {
			return err
		}
	}
	for _, sgID := range inst.VPCSecurityGroupIDs {
		if _, err := r.GetSecurityGroup(account, inst.Region, sgID); err != nil {
			return err
		}
	}
	if inst.State == "" {
		inst.State = "running"
	}
	body, _ := json.Marshal(inst)
	sgJSON, _ := json.Marshal(inst.VPCSecurityGroupIDs)
	var profile *string
	if inst.IAMInstanceProfileName != "" {
		profile = &inst.IAMInstanceProfileName
	}
	_, err := r.db.Exec(
		`INSERT INTO ec2_instances (account_id, region, id, subnet_id, ami_id, instance_type, iam_instance_profile_name, vpc_security_group_ids, state, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, inst.Region, inst.ID, inst.SubnetID, inst.AMIID, inst.InstanceType,
		profile, string(sgJSON), inst.State, inst.ARN, string(body), inst.CreatedAt,
	)
	return mapInsertError(err)
}

// GetInstance looks up an instance by id, optionally scoped to a
// region (Codex pass 7 BLOCKING #1).
func (r *Repository) GetInstance(account, region, id string) (*EC2Instance, error) {
	var data string
	var err error
	if region == "" {
		err = r.db.QueryRow(`SELECT data FROM ec2_instances WHERE account_id = ? AND id = ?`, account, id).Scan(&data)
	} else {
		err = r.db.QueryRow(`SELECT data FROM ec2_instances WHERE account_id = ? AND region = ? AND id = ?`, account, region, id).Scan(&data)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var inst EC2Instance
	if err := json.Unmarshal([]byte(data), &inst); err != nil {
		return nil, err
	}
	return &inst, nil
}

func (r *Repository) ListInstances(account, region string) ([]*EC2Instance, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM ec2_instances WHERE account_id = ? ORDER BY id`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM ec2_instances WHERE account_id = ? AND region = ? ORDER BY id`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2Instance
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var inst EC2Instance
		if err := json.Unmarshal([]byte(data), &inst); err != nil {
			return nil, err
		}
		out = append(out, &inst)
	}
	return out, rows.Err()
}

// SetInstanceState is the only mutation supported on running
// instances at v1 — the state machine is collapsed to
// pending → running → shutting-down → terminated. ModifyInstanceAttribute
// is a no-op (concepts.md "Standing patterns" item 9 — terminal-state
// refusal is enforced here).
func (r *Repository) SetInstanceState(account, region, id, state string) error {
	current, err := r.GetInstance(account, region, id)
	if err != nil {
		return err
	}
	if current.State == "terminated" {
		return models.ErrConflict
	}
	current.State = state
	body, _ := json.Marshal(current)
	_, err = r.db.Exec(
		`UPDATE ec2_instances SET state = ?, data = ? WHERE account_id = ? AND id = ?`,
		state, string(body), account, id,
	)
	return err
}

func (r *Repository) DeleteInstance(account, region, id string) error {
	var res sql.Result
	var err error
	if region == "" {
		res, err = r.db.Exec(`DELETE FROM ec2_instances WHERE account_id = ? AND id = ?`, account, id)
	} else {
		res, err = r.db.Exec(`DELETE FROM ec2_instances WHERE account_id = ? AND region = ? AND id = ?`, account, region, id)
	}
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- KeyPair CRUD -----

func (r *Repository) CreateKeyPair(account string, kp *EC2KeyPair) error {
	body, _ := json.Marshal(kp)
	_, err := r.db.Exec(
		`INSERT INTO ec2_key_pairs (account_id, region, name, public_key, fingerprint, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, kp.Region, kp.Name, kp.PublicKey, kp.Fingerprint, string(body), kp.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetKeyPair(account, region, name string) (*EC2KeyPair, error) {
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM ec2_key_pairs WHERE account_id = ? AND region = ? AND name = ?`,
		account, region, name,
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var kp EC2KeyPair
	if err := json.Unmarshal([]byte(data), &kp); err != nil {
		return nil, err
	}
	return &kp, nil
}

func (r *Repository) ListKeyPairs(account, region string) ([]*EC2KeyPair, error) {
	rows, err := r.db.Query(
		`SELECT data FROM ec2_key_pairs WHERE account_id = ? AND region = ? ORDER BY name`,
		account, region,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2KeyPair
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var kp EC2KeyPair
		if err := json.Unmarshal([]byte(data), &kp); err != nil {
			return nil, err
		}
		out = append(out, &kp)
	}
	return out, rows.Err()
}

func (r *Repository) DeleteKeyPair(account, region, name string) error {
	res, err := r.db.Exec(
		`DELETE FROM ec2_key_pairs WHERE account_id = ? AND region = ? AND name = ?`,
		account, region, name,
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

// ----- AMI fixtures -----
//
// AMIs are read-only at v1. SeedAMI is called once at startup by the
// admin layer to populate the fixture set; handlers/ec2.go's
// DescribeImages just lists them. There is intentionally no DeleteAMI
// or CreateAMI exposed via Application — terraform-provider-aws never
// writes AMIs (it only reads them), so the fixture model is sufficient.

func (r *Repository) SeedAMI(account string, ami *EC2AMI) error {
	body, _ := json.Marshal(ami)
	_, err := r.db.Exec(
		`INSERT OR IGNORE INTO ec2_amis (account_id, region, id, name, owner_id, virtualization_type, root_device_name, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		account, ami.Region, ami.ID, ami.Name, ami.OwnerID, ami.VirtualizationType, ami.RootDeviceName, string(body),
	)
	return err
}

func (r *Repository) GetAMI(account, region, id string) (*EC2AMI, error) {
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM ec2_amis WHERE account_id = ? AND region = ? AND id = ?`,
		account, region, id,
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var ami EC2AMI
	if err := json.Unmarshal([]byte(data), &ami); err != nil {
		return nil, err
	}
	return &ami, nil
}

func (r *Repository) ListAMIs(account, region string) ([]*EC2AMI, error) {
	rows, err := r.db.Query(
		`SELECT data FROM ec2_amis WHERE account_id = ? AND region = ? ORDER BY id`,
		account, region,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2AMI
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var ami EC2AMI
		if err := json.Unmarshal([]byte(data), &ami); err != nil {
			return nil, err
		}
		out = append(out, &ami)
	}
	return out, rows.Err()
}
