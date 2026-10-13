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
//	                               → ec2_instances.id   (FK, CASCADE, nullable)
//	ec2_network_interfaces.subnet_id
//	                               → ec2_subnets.id     (FK, RESTRICT)
//
// Each instance has one primary ENI, which owns its private and public
// IPs and its security groups (the instance's groupSet is read from
// it). A loaded ENI may have no instance (instance_id NULL). UNIQUE
// (subnet_id, private_ip) keeps private IPs distinct.
//
// ON DELETE RESTRICT on subnet_id is the load-bearing bit: a subnet
// that still has running instances, or a loaded ENI with no instance,
// cannot be deleted; real EC2's DeleteSubnet returns DependencyViolation
// in that case.
//
// AMIs are read-only at v1 — handlers/ec2.go ships a fixture set
// (ami-0abcd1234 etc.), or a load stores recorded images (EC2AMIRecorded),
// and DescribeImages answers the rows by id, owner and the filters
// data.aws_ami sends (handlers/ec2.go's imageFilters).
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
		instance_id TEXT,
		subnet_id   TEXT NOT NULL,
		private_ip  TEXT NOT NULL,
		data        TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		UNIQUE (account_id, subnet_id, private_ip),
		FOREIGN KEY (account_id, instance_id) REFERENCES ec2_instances(account_id, id) ON DELETE CASCADE,
		FOREIGN KEY (account_id, subnet_id) REFERENCES ec2_subnets(account_id, id) ON DELETE RESTRICT
	)`,
	// ec2_volumes (ec2_volumes.go) holds its attachments in data.
	`CREATE TABLE IF NOT EXISTS ec2_volumes (
		account_id TEXT NOT NULL,
		region     TEXT NOT NULL,
		id         TEXT NOT NULL,
		data       TEXT NOT NULL,
		PRIMARY KEY (account_id, id)
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
	// ec2_volumes before ec2_instances: a load writes volumes after the
	// instances their attachments name (LoadRank).
	prependResetTables([]string{
		"ec2_volumes",
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
	KeyName                string `json:"key_name,omitempty"`
	IAMInstanceProfileName string `json:"iam_instance_profile_name,omitempty"`
	// IAMInstanceProfileARN and IAMInstanceProfileID are the profile's
	// as stored when the instance launched, or as recorded for a loaded
	// instance; empty for a row stored before they were kept.
	IAMInstanceProfileARN string `json:"iam_instance_profile_arn,omitempty"`
	IAMInstanceProfileID  string `json:"iam_instance_profile_id,omitempty"`
	UserData              string `json:"user_data,omitempty"` // base64, as RunInstances sent it or DescribeInstanceAttribute answered it
	State                 string `json:"state"`
	Region                string `json:"region"`
	ARN                   string `json:"arn"`
	CreatedAt             string `json:"created_at"` // DescribeInstances' launchTime
	ReservationID         string `json:"reservation_id,omitempty"`
	// Recorded is a loaded instance's DescribeInstances fields that
	// nothing else holds, encoded by handlers/ec2.go; a launched instance
	// has none.
	Recorded json.RawMessage `json:"recorded,omitempty"`
	EC2InstanceAttributes
}

// EC2InstanceAttributes are the attributes RunInstances and
// ModifyInstanceAttribute set and DescribeInstanceAttribute answers
// (sourceDestCheck lives on the primary ENI). Each lives only in the
// row's data, so UpdateInstanceAttributes cannot desync a column. The
// zero value is AWS's default.
type EC2InstanceAttributes struct {
	DisableAPITermination bool   `json:"disable_api_termination,omitempty"`
	DisableAPIStop        bool   `json:"disable_api_stop,omitempty"`
	EBSOptimized          bool   `json:"ebs_optimized,omitempty"`
	ShutdownBehavior      string `json:"shutdown_behavior,omitempty"`
}

// EC2NetworkInterface is an instance's primary ENI (device index 0),
// deleted when the instance terminates, or a loaded ENI, which may have
// no instance (InstanceID and AttachmentID empty). PublicIP is empty
// unless the launch asked for one (AutoPublicIP) or an Elastic IP is
// associated. The fields from Description on are a loaded ENI's, as
// recorded; a launched ENI leaves them empty and answers the defaults
// handlers/ec2.go's ec2ENIToXML gives.
type EC2NetworkInterface struct {
	ID               string   `json:"network_interface_id"`
	AttachmentID     string   `json:"attachment_id,omitempty"`
	InstanceID       string   `json:"instance_id,omitempty"`
	SubnetID         string   `json:"subnet_id"`
	VPCID            string   `json:"vpc_id"`
	PrivateIP        string   `json:"private_ip"`
	PublicIP         string   `json:"public_ip,omitempty"`
	AutoPublicIP     bool     `json:"auto_public_ip,omitempty"`
	SecurityGroupIDs []string `json:"security_group_ids"`
	SourceDestCheck  bool     `json:"source_dest_check"`
	Region           string   `json:"region"`

	Description        string                `json:"description,omitempty"`
	MacAddress         string                `json:"mac_address,omitempty"`
	PrivateDNSName     string                `json:"private_dns_name,omitempty"`
	AvailabilityZone   string                `json:"availability_zone,omitempty"`
	RequesterManaged   bool                  `json:"requester_managed,omitempty"`
	InterfaceType      string                `json:"interface_type,omitempty"`
	OwnerID            string                `json:"owner_id,omitempty"`
	Status             string                `json:"status,omitempty"`
	PrivateIPAddresses []EC2PrivateIPAddress `json:"private_ip_addresses,omitempty"`
	// KeepOnTermination is a loaded attached ENI's recorded
	// deleteOnTermination false: terminating its instance detaches it
	// (SetInstanceState). A launched ENI is deleted with its instance.
	KeepOnTermination bool `json:"keep_on_termination,omitempty"`
}

// EC2PrivateIPAddress is one of a loaded ENI's private IPv4 addresses.
type EC2PrivateIPAddress struct {
	Address        string `json:"address"`
	Primary        bool   `json:"primary,omitempty"`
	PrivateDNSName string `json:"private_dns_name,omitempty"`
}

type EC2KeyPair struct {
	ID          string `json:"key_pair_id,omitempty"`
	Name        string `json:"name"`
	KeyType     string `json:"key_type,omitempty"` // a loaded key's; ImportKeyPair sets none
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
	// EC2AMIRecorded is a loaded image's; a fixture or a /mock/images
	// image has none.
	*EC2AMIRecorded
}

// EC2AMIRecorded is what a loaded image's DescribeImages item holds
// besides EC2AMI's own fields, as recorded: the fields
// terraform-provider-aws's aws_ami reads. Its xml tags are that item's,
// which handlers/ec2.go's ec2ImageXML embeds it in; its owner alias is
// answered there, beside the fixtures' derived one.
type EC2AMIRecorded struct {
	OwnerAlias         string              `json:"owner_alias,omitempty" xml:"-"`
	ImageLocation      string              `json:"image_location,omitempty" xml:"imageLocation,omitempty"`
	CreationDate       string              `json:"creation_date,omitempty" xml:"creationDate,omitempty"`
	DeprecationTime    string              `json:"deprecation_time,omitempty" xml:"deprecationTime,omitempty"`
	LastLaunchedTime   string              `json:"last_launched_time,omitempty" xml:"lastLaunchedTime,omitempty"`
	Public             string              `json:"public,omitempty" xml:"isPublic,omitempty"`
	Architecture       string              `json:"architecture,omitempty" xml:"architecture,omitempty"`
	Platform           string              `json:"platform,omitempty" xml:"platform,omitempty"`
	PlatformDetails    string              `json:"platform_details,omitempty" xml:"platformDetails,omitempty"`
	UsageOperation     string              `json:"usage_operation,omitempty" xml:"usageOperation,omitempty"`
	Description        string              `json:"description,omitempty" xml:"description,omitempty"`
	KernelID           string              `json:"kernel_id,omitempty" xml:"kernelId,omitempty"`
	RamdiskID          string              `json:"ramdisk_id,omitempty" xml:"ramdiskId,omitempty"`
	RootDeviceType     string              `json:"root_device_type,omitempty" xml:"rootDeviceType,omitempty"`
	BlockDeviceMapping []EC2AMIBlockDevice `json:"block_device_mapping,omitempty" xml:"blockDeviceMapping>item,omitempty"`
	ProductCodes       []EC2AMIProductCode `json:"product_codes,omitempty" xml:"productCodes>item,omitempty"`
	StateReason        *EC2AMIStateReason  `json:"state_reason,omitempty" xml:"stateReason,omitempty"`
	Hypervisor         string              `json:"hypervisor,omitempty" xml:"hypervisor,omitempty"`
	EnaSupport         string              `json:"ena_support,omitempty" xml:"enaSupport,omitempty"`
	SriovNetSupport    string              `json:"sriov_net_support,omitempty" xml:"sriovNetSupport,omitempty"`
	BootMode           string              `json:"boot_mode,omitempty" xml:"bootMode,omitempty"`
	TpmSupport         string              `json:"tpm_support,omitempty" xml:"tpmSupport,omitempty"`
	ImdsSupport        string              `json:"imds_support,omitempty" xml:"imdsSupport,omitempty"`
}

// EC2AMIBlockDevice is one item of an image's blockDeviceMapping.
type EC2AMIBlockDevice struct {
	DeviceName  string     `json:"device_name,omitempty" xml:"deviceName,omitempty"`
	VirtualName string     `json:"virtual_name,omitempty" xml:"virtualName,omitempty"`
	EBS         *EC2AMIEBS `json:"ebs,omitempty" xml:"ebs,omitempty"`
}

// EC2AMIEBS is a block device's ebs.
type EC2AMIEBS struct {
	SnapshotID          string `json:"snapshot_id,omitempty" xml:"snapshotId,omitempty"`
	VolumeSize          string `json:"volume_size,omitempty" xml:"volumeSize,omitempty"`
	DeleteOnTermination string `json:"delete_on_termination,omitempty" xml:"deleteOnTermination,omitempty"`
	VolumeType          string `json:"volume_type,omitempty" xml:"volumeType,omitempty"`
	Iops                string `json:"iops,omitempty" xml:"iops,omitempty"`
	Throughput          string `json:"throughput,omitempty" xml:"throughput,omitempty"`
	Encrypted           string `json:"encrypted,omitempty" xml:"encrypted,omitempty"`
}

// EC2AMIProductCode is one item of an image's productCodes.
type EC2AMIProductCode struct {
	ProductCode string `json:"product_code,omitempty" xml:"productCode,omitempty"`
	Type        string `json:"type,omitempty" xml:"type,omitempty"`
}

// EC2AMIStateReason is an image's stateReason.
type EC2AMIStateReason struct {
	Code    string `json:"code,omitempty" xml:"code,omitempty"`
	Message string `json:"message,omitempty" xml:"message,omitempty"`
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
	if err := insertInstance(tx, account, inst); err != nil {
		return err
	}
	used, err := stringSet(tx, subnetPrivateIPs, account, subnet.ID, account, subnet.ID)
	if err != nil {
		return err
	}
	if eni.PrivateIP, err = privateIP(subnet.CidrBlock, eni.PrivateIP, used); err != nil {
		return err
	}
	if err := claimPublicIP(tx, account, eni); err != nil {
		return err
	}
	if err := insertENI(tx, account, eni); err != nil {
		return err
	}
	return tx.Commit()
}

// insertInstance stores inst under account, with no
// iam_instance_profile_name when it has no profile.
func insertInstance(ex execer, account string, inst *EC2Instance) error {
	body, _ := json.Marshal(inst)
	_, err := ex.Exec(
		`INSERT INTO ec2_instances (account_id, region, id, subnet_id, ami_id, instance_type, iam_instance_profile_name, state, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, inst.Region, inst.ID, inst.SubnetID, inst.AMIID, inst.InstanceType,
		nullIfEmpty(inst.IAMInstanceProfileName), inst.State, inst.ARN, string(body), inst.CreatedAt,
	)
	return mapInsertError(err)
}

// insertENI stores eni under account, with no instance_id when it has
// no instance.
func insertENI(ex execer, account string, eni *EC2NetworkInterface) error {
	body, _ := json.Marshal(eni)
	_, err := ex.Exec(
		`INSERT INTO ec2_network_interfaces (account_id, region, id, instance_id, subnet_id, private_ip, data) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, eni.Region, eni.ID, nullIfEmpty(eni.InstanceID), eni.SubnetID, eni.PrivateIP, string(body),
	)
	return mapInsertError(err)
}

// subnetPrivateIPs selects every private IP the ENIs of a subnet hold:
// each primary one, and each a loaded ENI's private_ip_addresses names.
// Its args are the account and subnet, twice.
const subnetPrivateIPs = `SELECT private_ip FROM ec2_network_interfaces WHERE account_id = ? AND subnet_id = ?
	UNION SELECT json_extract(ip.value, '$.address') FROM ec2_network_interfaces eni, json_each(eni.data, '$.private_ip_addresses') ip
	WHERE eni.account_id = ? AND eni.subnet_id = ?`

// stringSet returns the set of the one text column query selects.
func stringSet(tx *sql.Tx, query string, args ...any) (map[string]bool, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		set[v] = true
	}
	return set, rows.Err()
}

// claimPublicIP moves eni's wanted public IP, if any, to the first one
// from it up, wrapping within its /24, that no other ENI in its account
// and region holds, so ip-address selects one instance. Its callers
// set PublicIP only to an auto-assigned address: an Elastic IP is
// already the region's own, from another /24.
// ponytail: one /24 caps a region at 256 auto-assigned addresses.
func claimPublicIP(tx *sql.Tx, account string, eni *EC2NetworkInterface) error {
	if eni.PublicIP == "" {
		return nil
	}
	held, err := stringSet(tx, `SELECT COALESCE(json_extract(data, '$.public_ip'), '') FROM ec2_network_interfaces
		WHERE account_id = ? AND region = ? AND id != ?`, account, eni.Region, eni.ID)
	if err != nil {
		return err
	}
	eni.PublicIP, err = freeIP(eni.PublicIP, held)
	return err
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
	if region == "" {
		return scanInstance(r.db.QueryRow(`SELECT data FROM ec2_instances WHERE account_id = ? AND id = ?`, account, id))
	}
	return scanInstance(r.db.QueryRow(`SELECT data FROM ec2_instances WHERE account_id = ? AND region = ? AND id = ?`, account, region, id))
}

// getInstanceTx is GetInstance inside tx, for a read its write depends on.
func getInstanceTx(tx *sql.Tx, account, region, id string) (*EC2Instance, error) {
	return scanInstance(tx.QueryRow(`SELECT data FROM ec2_instances WHERE account_id = ? AND region = ? AND id = ?`, account, region, id))
}

func scanInstance(row *sql.Row) (*EC2Instance, error) {
	var data string
	err := row.Scan(&data)
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

// EC2InstanceAttributeChange is one ModifyInstanceAttribute: Set
// changes the instance's attributes, and SourceDestCheck, when not
// nil, is stored on its primary ENI.
type EC2InstanceAttributeChange struct {
	Set             func(*EC2InstanceAttributes)
	SourceDestCheck *bool
}

// UpdateInstanceAttributes applies change in one transaction, so a
// failure applies none of it. The read is in the transaction too
// (SetMaxOpenConns(1): only tx may touch the db until Commit), so a
// state change can neither land between the read and the write and be
// overwritten by the stale state in data, nor overwrite this change. A
// terminated instance is refused with models.ErrTerminalState before
// anything is written.
func (r *Repository) UpdateInstanceAttributes(account, region, id string, change EC2InstanceAttributeChange) error {
	return r.inTx(func(tx *sql.Tx) error {
		inst, err := getInstanceTx(tx, account, region, id)
		if err != nil {
			return err
		}
		if inst.State == "terminated" {
			return fmt.Errorf("instance %s is terminated: %w", id, models.ErrTerminalState)
		}
		if change.Set != nil {
			change.Set(&inst.EC2InstanceAttributes)
		}
		body, err := json.Marshal(inst)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE ec2_instances SET data = ? WHERE account_id = ? AND id = ?`, string(body), account, id); err != nil {
			return err
		}
		if change.SourceDestCheck == nil {
			return nil
		}
		res, err := tx.Exec(`UPDATE ec2_network_interfaces SET data = json_set(data, '$.source_dest_check', json(?)) WHERE account_id = ? AND instance_id = ?`,
			fmt.Sprint(*change.SourceDestCheck), account, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("instance %s has no network interface: %w", id, models.ErrConflict)
		}
		return nil
	})
}

// ErrTerminationProtected is why SetInstanceState refuses to
// terminate an instance whose DisableAPITermination is set.
var ErrTerminationProtected = fmt.Errorf("disableApiTermination is set: %w", models.ErrConflict)

// InstanceError is SetInstanceState's refusal of one instance. Err is
// models.ErrNotFound, models.ErrConflict (a move out of terminated),
// ErrTerminationProtected or the database's error.
type InstanceError struct {
	InstanceID string
	Err        error
}

func (e *InstanceError) Error() string { return "instance " + e.InstanceID + ": " + e.Err.Error() }

func (e *InstanceError) Unwrap() error { return e.Err }

// SetInstanceState moves each of ids to state in one transaction, so
// all move or none does, and returns the state each was in, in the
// order of ids. Each decision is made on the row read in the
// transaction (SetMaxOpenConns(1): only tx may touch the db until
// Commit), so nothing committed meanwhile is overwritten or missed.
// The state machine is collapsed to pending → running → shutting-down
// → terminated. Terminating an instance already terminated leaves it
// so, as in AWS, a repeated id included; any other move out of
// terminated is refused (concepts.md "Standing patterns" item 9 —
// terminal-state refusal is enforced here). An id with no row, and the
// termination of an instance whose DisableAPITermination is set, are
// refused too, each as an *InstanceError, moving none. Terminating
// deletes the instance's ENIs, but for one a load kept on termination,
// which it detaches, and clears the associations of its EIPs on the
// ENIs it deletes; it deletes or detaches its volumes the same way
// (terminateVolumesTx).
func (r *Repository) SetInstanceState(account, region, state string, ids ...string) ([]string, error) {
	previous := make([]string, len(ids))
	err := r.inTx(func(tx *sql.Tx) error {
		for i, id := range ids {
			was, err := setInstanceStateTx(tx, account, region, id, state)
			if err != nil {
				return &InstanceError{InstanceID: id, Err: err}
			}
			previous[i] = was
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return previous, nil
}

func setInstanceStateTx(tx *sql.Tx, account, region, id, state string) (string, error) {
	inst, err := getInstanceTx(tx, account, region, id)
	if err != nil {
		return "", err
	}
	was := inst.State
	switch {
	case was == "terminated" && state == "terminated":
		return was, nil
	case was == "terminated":
		return "", models.ErrConflict
	case state == "terminated" && inst.DisableAPITermination:
		return "", ErrTerminationProtected
	}
	inst.State = state
	body, err := json.Marshal(inst)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE ec2_instances SET state = ?, data = ? WHERE account_id = ? AND id = ?`, state, string(body), account, id); err != nil {
		return "", err
	}
	if state != "terminated" {
		return was, nil
	}
	if err := terminateVolumesTx(tx, account, id); err != nil {
		return "", err
	}
	// An ENI attached with deleteOnTermination false stays, detached and
	// available, as on EC2, and so does an Elastic IP's association with
	// it; the instance's other ENIs go with it.
	if _, err := tx.Exec(`UPDATE ec2_network_interfaces SET instance_id = NULL,
		   data = json_set(json_remove(data, '$.instance_id', '$.attachment_id', '$.keep_on_termination'), '$.status', 'available')
		 WHERE account_id = ? AND instance_id = ? AND json_extract(data, '$.keep_on_termination')`, account, id); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`DELETE FROM ec2_network_interfaces WHERE account_id = ? AND instance_id = ?`, account, id); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE ec2_eips SET instance_id = NULL, data = json_remove(data, '$.instance_id')
		 WHERE account_id = ? AND instance_id = ? AND network_interface_id IN (SELECT id FROM ec2_network_interfaces WHERE account_id = ?)`,
		account, id, account); err != nil {
		return "", err
	}
	// EC2 disassociates an instance's other Elastic IPs when it terminates.
	_, err = tx.Exec(
		`UPDATE ec2_eips SET network_interface_id = NULL, instance_id = NULL, association_id = NULL,
		   data = json_remove(data, '$.network_interface_id', '$.instance_id', '$.association_id', '$.private_ip')
		 WHERE account_id = ? AND instance_id = ?`, account, id)
	return was, err
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
	return insertKeyPair(r.db, account, kp)
}

func insertKeyPair(ex execer, account string, kp *EC2KeyPair) error {
	body, _ := json.Marshal(kp)
	_, err := ex.Exec(
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
	return insertAMI(r.db, "INSERT OR IGNORE", account, ami)
}

// insertAMI stores ami under account with verb: INSERT OR IGNORE for a
// seed, which leaves a stored id alone, or INSERT for a load.
func insertAMI(ex execer, verb, account string, ami *EC2AMI) error {
	body, _ := json.Marshal(ami)
	_, err := ex.Exec(
		verb+` INTO ec2_amis (account_id, region, id, name, owner_id, virtualization_type, root_device_name, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
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
