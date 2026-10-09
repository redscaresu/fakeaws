// Package repository — EC2 compute tables and CRUD.
//
// Per fakeaws/PLAN.md § "Phase 2 — Networking + compute (S44)":
// compute lands in S44-T6 atop the networking schema from S44-T3.
//
// FK chain (compute side):
//
//	ec2_instances.subnet_id        → ec2_subnets.id     (FK, RESTRICT)
//	ec2_instances.iam_instance_profile_name
//	                               → iam_instance_profiles.name (cross-service FK, nullable)
//	ec2_network_interfaces.instance_id
//	                               → ec2_instances.id   (FK, CASCADE)
//
// Each instance has one primary ENI, which owns its private and public
// IPs and its security groups (the instance's groupSet is read from
// it). UNIQUE (subnet_id, private_ip) keeps private IPs distinct.
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
	"fmt"
	"net/netip"

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
		state                   TEXT NOT NULL DEFAULT 'running',
		arn                     TEXT NOT NULL,
		data                    TEXT NOT NULL,
		created_at              TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, subnet_id) REFERENCES ec2_subnets(account_id, id) ON DELETE RESTRICT
	)`,
	`CREATE TABLE IF NOT EXISTS ec2_network_interfaces (
		account_id  TEXT NOT NULL,
		region      TEXT NOT NULL,
		id          TEXT NOT NULL,
		instance_id TEXT NOT NULL,
		subnet_id   TEXT NOT NULL,
		private_ip  TEXT NOT NULL,
		data        TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		UNIQUE (account_id, subnet_id, private_ip),
		FOREIGN KEY (account_id, instance_id) REFERENCES ec2_instances(account_id, id) ON DELETE CASCADE
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
		"ec2_network_interfaces",
		"ec2_instances",
		"ec2_key_pairs",
		"ec2_amis",
	})
}

// ----- Typed wire shapes -----

type EC2Instance struct {
	ID                     string `json:"instance_id"`
	SubnetID               string `json:"subnet_id"`
	AMIID                  string `json:"ami_id"`
	InstanceType           string `json:"instance_type"`
	IAMInstanceProfileName string `json:"iam_instance_profile_name,omitempty"`
	UserData               string `json:"user_data,omitempty"` // base64, as RunInstances sent it
	State                  string `json:"state"`
	Region                 string `json:"region"`
	ARN                    string `json:"arn"`
	CreatedAt              string `json:"created_at"`
}

// EC2NetworkInterface is an instance's primary ENI (device index 0),
// deleted when the instance terminates. PublicIP is empty unless the
// launch asked for one.
type EC2NetworkInterface struct {
	ID               string   `json:"network_interface_id"`
	AttachmentID     string   `json:"attachment_id"`
	InstanceID       string   `json:"instance_id"`
	SubnetID         string   `json:"subnet_id"`
	VPCID            string   `json:"vpc_id"`
	PrivateIP        string   `json:"private_ip"`
	PublicIP         string   `json:"public_ip,omitempty"`
	SecurityGroupIDs []string `json:"security_group_ids"`
	SourceDestCheck  bool     `json:"source_dest_check"`
	Region           string   `json:"region"`
}

type EC2KeyPair struct {
	ID          string `json:"key_pair_id,omitempty"`
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

// CreateInstance inserts inst and its primary ENI in one transaction.
// It fills the ENI's instance, subnet, VPC and region from inst. The
// ENI keeps a requested PrivateIP if that address is free, and
// otherwise gets the lowest free one in the subnet.
func (r *Repository) CreateInstance(account string, inst *EC2Instance, eni *EC2NetworkInterface) error {
	// Validate parent subnet (FK enforces, but the explicit lookup
	// produces a clean ErrNotFound rather than a SQLite constraint
	// violation that maps awkwardly). Codex pass 7 BLOCKING #1 — parent
	// must be in the same region.
	subnet, err := r.GetSubnet(account, inst.Region, inst.SubnetID)
	if err != nil {
		return err
	}
	// AMI must exist in this region (Codex pass 9 BLOCKING #1: real
	// EC2 rejects RunInstances with an unknown ImageId; we previously
	// inserted whatever AMIID string was supplied).
	if inst.AMIID != "" {
		if _, err := r.GetAMI(account, inst.Region, inst.AMIID); err != nil {
			return err
		}
	}
	if inst.IAMInstanceProfileName != "" {
		if _, err := r.GetInstanceProfile(account, inst.IAMInstanceProfileName); err != nil {
			return err
		}
	}
	for _, sgID := range eni.SecurityGroupIDs {
		if _, err := r.GetSecurityGroup(account, inst.Region, sgID); err != nil {
			return err
		}
	}
	if inst.State == "" {
		inst.State = "running"
	}
	eni.InstanceID, eni.SubnetID, eni.VPCID, eni.Region = inst.ID, subnet.ID, subnet.VPCID, inst.Region

	// SetMaxOpenConns(1): only tx may touch the db until Commit.
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	body, _ := json.Marshal(inst)
	var profile *string
	if inst.IAMInstanceProfileName != "" {
		profile = &inst.IAMInstanceProfileName
	}
	if _, err := tx.Exec(
		`INSERT INTO ec2_instances (account_id, region, id, subnet_id, ami_id, instance_type, iam_instance_profile_name, state, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, inst.Region, inst.ID, inst.SubnetID, inst.AMIID, inst.InstanceType,
		profile, inst.State, inst.ARN, string(body), inst.CreatedAt,
	); err != nil {
		return mapInsertError(err)
	}
	used, err := usedPrivateIPs(tx, account, subnet.ID)
	if err != nil {
		return err
	}
	if eni.PrivateIP, err = privateIP(subnet.CidrBlock, eni.PrivateIP, used); err != nil {
		return err
	}
	eniBody, _ := json.Marshal(eni)
	if _, err := tx.Exec(
		`INSERT INTO ec2_network_interfaces (account_id, region, id, instance_id, subnet_id, private_ip, data) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, eni.Region, eni.ID, eni.InstanceID, eni.SubnetID, eni.PrivateIP, string(eniBody),
	); err != nil {
		return mapInsertError(err)
	}
	return tx.Commit()
}

func usedPrivateIPs(tx *sql.Tx, account, subnetID string) (map[string]bool, error) {
	rows, err := tx.Query(`SELECT private_ip FROM ec2_network_interfaces WHERE account_id = ? AND subnet_id = ?`, account, subnetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		used[ip] = true
	}
	return used, rows.Err()
}

// privateIP returns want if it is a free usable address in cidr or,
// with want empty, the lowest free one. AWS reserves the first four
// addresses and the last one of every subnet.
func privateIP(cidr, want string, used map[string]bool) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return "", fmt.Errorf("subnet cidr %q is not an IPv4 prefix: %w", cidr, models.ErrConflict)
	}
	prefix = prefix.Masked()
	addr := prefix.Addr().Next().Next().Next().Next()
	for next := addr.Next(); prefix.Contains(next); addr, next = next, next.Next() {
		if !used[addr.String()] && (want == "" || want == addr.String()) {
			return addr.String(), nil
		}
	}
	if want != "" {
		return "", fmt.Errorf("private IP %q is not a free, usable address in %s: %w", want, cidr, models.ErrConflict)
	}
	return "", fmt.Errorf("InsufficientFreeAddressesInSubnet: no free address in %s: %w", cidr, models.ErrConflict)
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
// refusal is enforced here). Terminating deletes the instance's ENIs
// in the same transaction.
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
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`UPDATE ec2_instances SET state = ?, data = ? WHERE account_id = ? AND id = ?`,
		state, string(body), account, id,
	); err != nil {
		return err
	}
	if state == "terminated" {
		if _, err := tx.Exec(`DELETE FROM ec2_network_interfaces WHERE account_id = ? AND instance_id = ?`, account, id); err != nil {
			return err
		}
	}
	return tx.Commit()
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

// ----- NetworkInterface CRUD -----

// ListNetworkInterfaces returns ENIs for the account, optionally
// scoped to a region (empty = all regions).
func (r *Repository) ListNetworkInterfaces(account, region string) ([]*EC2NetworkInterface, error) {
	rows, err := r.db.Query(
		`SELECT data FROM ec2_network_interfaces WHERE account_id = ? AND (? = '' OR region = ?) ORDER BY id`,
		account, region, region,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2NetworkInterface
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var eni EC2NetworkInterface
		if err := json.Unmarshal([]byte(data), &eni); err != nil {
			return nil, err
		}
		out = append(out, &eni)
	}
	return out, rows.Err()
}

func (r *Repository) GetNetworkInterface(account, region, id string) (*EC2NetworkInterface, error) {
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM ec2_network_interfaces WHERE account_id = ? AND region = ? AND id = ?`,
		account, region, id,
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var eni EC2NetworkInterface
	if err := json.Unmarshal([]byte(data), &eni); err != nil {
		return nil, err
	}
	return &eni, nil
}

// UpdateNetworkInterface applies change to the ENI and saves it. The
// caller validates the new values (e.g. groups in the ENI's VPC).
func (r *Repository) UpdateNetworkInterface(account, region, id string, change func(*EC2NetworkInterface)) error {
	eni, err := r.GetNetworkInterface(account, region, id)
	if err != nil {
		return err
	}
	change(eni)
	body, _ := json.Marshal(eni)
	_, err = r.db.Exec(
		`UPDATE ec2_network_interfaces SET data = ? WHERE account_id = ? AND region = ? AND id = ?`,
		string(body), account, region, id,
	)
	return err
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

// GetKeyPairByID returns the key pair with this KeyPairId, the id EC2's
// CreateTags and DeleteTags name it by.
func (r *Repository) GetKeyPairByID(account, region, id string) (*EC2KeyPair, error) {
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM ec2_key_pairs WHERE account_id = ? AND region = ? AND json_extract(data, '$.key_pair_id') = ?`,
		account, region, id,
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

// ListKeyPairs returns key pairs for the account, optionally scoped
// to a region. Empty region = all regions (Codex pass 8 BLOCKING #2:
// /mock/state previously walked a hard-coded region slice).
func (r *Repository) ListKeyPairs(account, region string) ([]*EC2KeyPair, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(
			`SELECT data FROM ec2_key_pairs WHERE account_id = ? ORDER BY region, name`,
			account,
		)
	} else {
		rows, err = r.db.Query(
			`SELECT data FROM ec2_key_pairs WHERE account_id = ? AND region = ? ORDER BY name`,
			account, region,
		)
	}
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
// AMIs are read-only to the AWS surface. SeedAMI populates the fixture
// set at startup and backs the admin POST /mock/images; handlers/ec2.go's
// DescribeImages just lists them. There is intentionally no DeleteAMI
// or CreateAMI on the EC2 API — terraform-provider-aws never writes
// AMIs (it only reads them).

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
