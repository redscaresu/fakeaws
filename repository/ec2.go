// Package repository — EC2 networking tables and CRUD.
//
// Per fakeaws/PLAN.md § "Phase 2 — Networking + compute (S44)" — the
// FK chain that gates correctness:
//
//	                 ec2_vpcs
//	                    │
//	     ┌──────────────┼─────────────┐
//	     │              │             │
//	ec2_subnets  ec2_route_tables  ec2_security_groups
//	     │              │             │
//	ec2_instances  ec2_routes   ec2_security_group_rules
//
// This file ships networking only: VPCs, Subnets, InternetGateways,
// RouteTables, RouteTableAssociations, Routes, SecurityGroups and their
// rules, EIPs.
// Compute (instances, key pairs, AMI fixtures) lands in S44-T6 in
// repository/ec2_compute.go.
//
// Server-stamped IDs follow AWS convention:
//
//	vpc-, subnet-, sg-, sgr-, rtb-, igw-, rtbassoc-, eipalloc-, eni-
//
// Each handler synthesises an id at create time; the repo never
// honours an id smuggled in from the client (per concepts.md
// "Standing patterns" item 14 — server-stamped fields never trusted).
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/redscaresu/fakeaws/models"
)

var ec2NetworkMigrations = []string{
	`CREATE TABLE IF NOT EXISTS ec2_vpcs (
		account_id TEXT NOT NULL,
		region     TEXT NOT NULL,
		id         TEXT NOT NULL,
		cidr_block TEXT NOT NULL,
		arn        TEXT NOT NULL,
		data       TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, id)
	)`,
	`CREATE TABLE IF NOT EXISTS ec2_subnets (
		account_id        TEXT NOT NULL,
		region            TEXT NOT NULL,
		id                TEXT NOT NULL,
		vpc_id            TEXT NOT NULL,
		cidr_block        TEXT NOT NULL,
		availability_zone TEXT NOT NULL,
		arn               TEXT NOT NULL,
		data              TEXT NOT NULL,
		created_at        TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, vpc_id) REFERENCES ec2_vpcs(account_id, id) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS ec2_internet_gateways (
		account_id TEXT NOT NULL,
		region     TEXT NOT NULL,
		id         TEXT NOT NULL,
		vpc_id     TEXT,
		arn        TEXT NOT NULL,
		data       TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, id)
		-- Composite FK with ON DELETE SET NULL would NULL account_id
		-- too (NOT NULL constraint trips). DeleteVPC handles IGW
		-- detach manually via UPDATE before deleting the parent.
	)`,
	`CREATE TABLE IF NOT EXISTS ec2_route_tables (
		account_id TEXT NOT NULL,
		region     TEXT NOT NULL,
		id         TEXT NOT NULL,
		vpc_id     TEXT NOT NULL,
		arn        TEXT NOT NULL,
		data       TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, vpc_id) REFERENCES ec2_vpcs(account_id, id) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS ec2_route_table_associations (
		account_id     TEXT NOT NULL,
		id             TEXT NOT NULL,
		route_table_id TEXT NOT NULL,
		vpc_id         TEXT NOT NULL, -- the route table's, for the one-main index
		subnet_id      TEXT,          -- NULL on a main or an edge association
		gateway_id     TEXT,          -- an edge association's gateway, else NULL
		main           INTEGER NOT NULL DEFAULT 0,
		state          TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, route_table_id) REFERENCES ec2_route_tables(account_id, id) ON DELETE CASCADE,
		FOREIGN KEY (account_id, subnet_id)      REFERENCES ec2_subnets(account_id, id)      ON DELETE CASCADE,
		UNIQUE (account_id, subnet_id) -- one association per subnet (real EC2 contract)
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS ec2_route_table_associations_one_main
		ON ec2_route_table_associations (account_id, vpc_id) WHERE main = 1`,
	`CREATE TABLE IF NOT EXISTS ec2_routes (
		account_id              TEXT NOT NULL,
		route_table_id          TEXT NOT NULL,
		destination_cidr_block  TEXT NOT NULL,
		gateway_id              TEXT,
		nat_gateway_id          TEXT,
		instance_id             TEXT,
		network_interface_id    TEXT,
		origin                  TEXT NOT NULL,
		state                   TEXT NOT NULL,
		PRIMARY KEY (account_id, route_table_id, destination_cidr_block),
		FOREIGN KEY (account_id, route_table_id) REFERENCES ec2_route_tables(account_id, id) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS ec2_security_groups (
		account_id   TEXT NOT NULL,
		region       TEXT NOT NULL,
		id           TEXT NOT NULL,
		vpc_id       TEXT NOT NULL,
		group_name   TEXT NOT NULL,
		description  TEXT NOT NULL,
		arn          TEXT NOT NULL,
		data         TEXT NOT NULL,
		created_at   TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, vpc_id) REFERENCES ec2_vpcs(account_id, id) ON DELETE CASCADE,
		UNIQUE (account_id, vpc_id, group_name)
	)`,
	// One row per source of a permission: AWS's security group rule.
	// referenced_group_id has no FK: a pair may name another account's
	// group, and deleting a group a rule references leaves that rule.
	`CREATE TABLE IF NOT EXISTS ec2_security_group_rules (
		account_id          TEXT NOT NULL,
		region              TEXT NOT NULL,
		id                  TEXT NOT NULL,
		group_id            TEXT NOT NULL,
		group_owner_id      TEXT NOT NULL,
		is_egress           INTEGER NOT NULL,
		perm_ord            INTEGER NOT NULL, -- the permission's position in its direction
		src_ord             INTEGER NOT NULL, -- the source's position in its permission
		ip_protocol         TEXT NOT NULL,
		from_port           INTEGER NOT NULL,
		to_port             INTEGER NOT NULL,
		cidr_ipv4           TEXT,
		cidr_ipv6           TEXT,
		prefix_list_id      TEXT,
		referenced_group_id TEXT,
		referenced_user_id  TEXT,
		description         TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, group_id) REFERENCES ec2_security_groups(account_id, id) ON DELETE CASCADE,
		UNIQUE (account_id, group_id, is_egress, perm_ord, src_ord),
		CHECK ((cidr_ipv4 IS NOT NULL) + (cidr_ipv6 IS NOT NULL) + (prefix_list_id IS NOT NULL) + (referenced_group_id IS NOT NULL) = 1),
		CHECK (referenced_user_id IS NULL OR referenced_group_id IS NOT NULL)
	)`,
	`CREATE TABLE IF NOT EXISTS ec2_eips (
		account_id           TEXT NOT NULL,
		region               TEXT NOT NULL,
		allocation_id        TEXT NOT NULL,
		domain               TEXT NOT NULL DEFAULT 'vpc',
		public_ip            TEXT NOT NULL,
		network_interface_id TEXT,
		instance_id          TEXT,
		association_id       TEXT,
		data                 TEXT NOT NULL,
		created_at           TEXT NOT NULL,
		PRIMARY KEY (account_id, allocation_id)
	)`,
	`CREATE TABLE IF NOT EXISTS availability_zones (
		account_id           TEXT NOT NULL,
		region               TEXT NOT NULL,
		zone_name            TEXT NOT NULL,
		zone_id              TEXT NOT NULL,
		state                TEXT NOT NULL,
		opt_in_status        TEXT NOT NULL,
		zone_type            TEXT NOT NULL,
		group_name           TEXT NOT NULL,
		network_border_group TEXT NOT NULL,
		PRIMARY KEY (account_id, region, zone_name)
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, ec2NetworkMigrations...)
	prependResetTables([]string{
		"ec2_routes",
		"ec2_route_table_associations",
		"ec2_route_tables",
		"ec2_internet_gateways",
		"ec2_eips",
		"ec2_security_group_rules",
		"ec2_security_groups",
		"ec2_subnets",
		"ec2_vpcs",
		"availability_zones",
	})
}

// ----- Typed wire shapes -----

type EC2VPC struct {
	ID        string `json:"vpc_id"`
	CidrBlock string `json:"cidr_block"`
	Region    string `json:"region"`
	ARN       string `json:"arn"`
	State     string `json:"state"` // "available" — collapsed state machine
	CreatedAt string `json:"created_at"`
	// OwnerID is the account DescribeVpcs answers, the stored account
	// for a created VPC and the recorded one for a loaded VPC, which may
	// be another's (a shared VPC).
	OwnerID                   string                    `json:"owner_id"`
	IsDefault                 bool                      `json:"is_default"`
	DhcpOptionsID             string                    `json:"dhcp_options_id"`
	InstanceTenancy           string                    `json:"instance_tenancy"`
	CidrBlockAssociations     []EC2CidrBlockAssociation `json:"cidr_block_associations"`
	Ipv6CidrBlockAssociations []EC2CidrBlockAssociation `json:"ipv6_cidr_block_associations,omitempty"`
	// EnableDNSSupport and EnableDNSHostnames are what
	// DescribeVpcAttribute answers and ModifyVpcAttribute sets.
	EnableDNSSupport   bool `json:"enable_dns_support"`
	EnableDNSHostnames bool `json:"enable_dns_hostnames"`
}

// EC2CidrBlockAssociation is one CIDR block a VPC or subnet holds: an
// IPv4 block, or an IPv6 one with, on a VPC, its pool, network border
// group, source and address attribute.
type EC2CidrBlockAssociation struct {
	AssociationID        string `json:"association_id"`
	CidrBlock            string `json:"cidr_block"`
	State                string `json:"state"`
	StatusMessage        string `json:"status_message,omitempty"`
	Ipv6Pool             string `json:"ipv6_pool,omitempty"`
	NetworkBorderGroup   string `json:"network_border_group,omitempty"`
	IPSource             string `json:"ip_source,omitempty"`
	Ipv6AddressAttribute string `json:"ipv6_address_attribute,omitempty"`
}

type EC2Subnet struct {
	ID               string `json:"subnet_id"`
	VPCID            string `json:"vpc_id"`
	CidrBlock        string `json:"cidr_block"`
	AvailabilityZone string `json:"availability_zone"`
	Region           string `json:"region"`
	ARN              string `json:"arn"`
	State            string `json:"state"`
	CreatedAt        string `json:"created_at"`
	// MapPublicIPOnLaunch gives a launch that does not set
	// AssociatePublicIpAddress a public IP.
	MapPublicIPOnLaunch         bool   `json:"map_public_ip_on_launch"`
	OwnerID                     string `json:"owner_id"`
	AvailableIPAddressCount     int    `json:"available_ip_address_count"`
	DefaultForAz                bool   `json:"default_for_az"`
	AssignIpv6AddressOnCreation bool   `json:"assign_ipv6_address_on_creation"`
	// The fields below are left out of some answers (the API
	// reference's), so nil or empty answers none.
	MapCustomerOwnedIPOnLaunch    *bool                     `json:"map_customer_owned_ip_on_launch,omitempty"`
	EnableDNS64                   *bool                     `json:"enable_dns64,omitempty"`
	Ipv6Native                    *bool                     `json:"ipv6_native,omitempty"`
	EnableLniAtDeviceIndex        *int                      `json:"enable_lni_at_device_index,omitempty"`
	CustomerOwnedIpv4Pool         string                    `json:"customer_owned_ipv4_pool,omitempty"`
	OutpostARN                    string                    `json:"outpost_arn,omitempty"`
	Ipv6CidrBlockAssociations     []EC2CidrBlockAssociation `json:"ipv6_cidr_block_associations,omitempty"`
	PrivateDNSNameOptionsOnLaunch *EC2PrivateDNSNameOptions `json:"private_dns_name_options_on_launch,omitempty"`
}

// EC2PrivateDNSNameOptions is a subnet's privateDnsNameOptionsOnLaunch.
type EC2PrivateDNSNameOptions struct {
	HostnameType                    string `json:"hostname_type"`
	EnableResourceNameDNSARecord    bool   `json:"enable_resource_name_dns_a_record"`
	EnableResourceNameDNSAAAARecord bool   `json:"enable_resource_name_dns_aaaa_record"`
}

type EC2InternetGateway struct {
	ID        string `json:"internet_gateway_id"`
	VPCID     string `json:"vpc_id,omitempty"` // nullable — IGW may be detached
	Region    string `json:"region"`
	ARN       string `json:"arn"`
	CreatedAt string `json:"created_at"`
	OwnerID   string `json:"owner_id"`
	// AttachmentState is the attachment's state while VPCID is set:
	// AttachInternetGateway sets it to available, and a detach drops it.
	AttachmentState string `json:"attachment_state,omitempty"`
}

type EC2RouteTable struct {
	ID        string `json:"route_table_id"`
	VPCID     string `json:"vpc_id"`
	Region    string `json:"region"`
	ARN       string `json:"arn"`
	CreatedAt string `json:"created_at"`
	OwnerID   string `json:"owner_id"`
}

// EC2RouteTableAssociation links a route table to a subnet; to a
// gateway (an edge association: GatewayID, no subnet); or, when Main,
// to its VPC, with no subnet. State is the associationState's state, ""
// for an answer that holds none.
type EC2RouteTableAssociation struct {
	ID           string `json:"association_id"`
	RouteTableID string `json:"route_table_id"`
	SubnetID     string `json:"subnet_id"`
	GatewayID    string `json:"gateway_id"`
	Main         bool   `json:"main"`
	State        string `json:"state"`
}

// EC2Route is one route. Origin is how it was made (CreateRouteTable
// for a table's local route, CreateRoute) and State active or
// blackhole.
type EC2Route struct {
	RouteTableID         string `json:"route_table_id"`
	DestinationCidrBlock string `json:"destination_cidr_block"`
	GatewayID            string `json:"gateway_id,omitempty"`
	NatGatewayID         string `json:"nat_gateway_id,omitempty"`
	InstanceID           string `json:"instance_id,omitempty"`
	NetworkInterfaceID   string `json:"network_interface_id,omitempty"`
	Origin               string `json:"origin"`
	State                string `json:"state"`
}

type EC2SecurityGroup struct {
	ID          string `json:"group_id"`
	VPCID       string `json:"vpc_id"`
	GroupName   string `json:"group_name"`
	Description string `json:"description"`
	Region      string `json:"region"`
	ARN         string `json:"arn"`
	CreatedAt   string `json:"created_at"`
	// OwnerID is the account DescribeSecurityGroups answers: the stored
	// account for a created group and the recorded one for a loaded
	// group. A row stored before it was kept has none.
	OwnerID string `json:"owner_id"`
}

// EC2SecurityGroupRule is one source of one permission of a security
// group, a row of ec2_security_group_rules. Exactly one of CidrIPv4,
// CidrIPv6, PrefixListID and ReferencedGroupID is set, and
// ReferencedUserID only beside ReferencedGroupID.
type EC2SecurityGroupRule struct {
	ID                string
	GroupID           string
	GroupOwnerID      string
	IsEgress          bool
	PermOrd           int // the permission's position in its direction
	SrcOrd            int // the source's position in its permission
	IPProtocol        string
	FromPort          int
	ToPort            int
	CidrIPv4          string
	CidrIPv6          string
	PrefixListID      string
	ReferencedGroupID string
	ReferencedUserID  string
	Description       string
}

type EC2EIP struct {
	AllocationID       string `json:"allocation_id"`
	Domain             string `json:"domain"`
	PublicIP           string `json:"public_ip"`
	NetworkInterfaceID string `json:"network_interface_id,omitempty"`
	InstanceID         string `json:"instance_id,omitempty"`
	AssociationID      string `json:"association_id,omitempty"`
	PrivateIP          string `json:"private_ip,omitempty"`
	PublicIPv4Pool     string `json:"public_ipv4_pool,omitempty"`     // a loaded address's; AllocateAddress sets none
	NetworkBorderGroup string `json:"network_border_group,omitempty"` // likewise
	Region             string `json:"region"`
	CreatedAt          string `json:"created_at"`
}

// ----- VPC -----

// execer is the Exec *sql.DB and *sql.Tx share, so one insert serves a
// lone write and a transaction's.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// DefaultGroupName is the security group every VPC has. AWS reserves
// it: no other group may take the name, and it cannot be deleted.
const DefaultGroupName = "default"

// CreateVPCWithDefaultGroup stores v and sg, its security group named
// DefaultGroupName, in one transaction: EC2's CreateVpc makes both, so
// no read sees the VPC without its default group.
func (r *Repository) CreateVPCWithDefaultGroup(account string, v *EC2VPC, sg *EC2SecurityGroup) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertVPC(tx, account, v); err != nil {
		return mapInsertError(err)
	}
	if err := insertSecurityGroup(tx, account, sg); err != nil {
		return err
	}
	return tx.Commit()
}

// insertVPC stores v under account.
func insertVPC(ex execer, account string, v *EC2VPC) error {
	body, _ := json.Marshal(v)
	_, err := ex.Exec(
		`INSERT INTO ec2_vpcs (account_id, region, id, cidr_block, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, v.Region, v.ID, v.CidrBlock, v.ARN, string(body), v.CreatedAt,
	)
	return err
}

// UpdateVPC applies change to the VPC and saves it.
func (r *Repository) UpdateVPC(account, region, id string, change func(*EC2VPC)) error {
	v, err := r.GetVPC(account, region, id)
	if err != nil {
		return err
	}
	change(v)
	body, _ := json.Marshal(v)
	_, err = r.db.Exec(`UPDATE ec2_vpcs SET data = ? WHERE account_id = ? AND id = ?`, string(body), account, id)
	return err
}

// BackfillDefaultGroups gives each VPC that has no group named
// DefaultGroupName the one newGroup makes, unless the database is
// loaded, whose rows are answered as they are. A VPC stored before
// CreateVpc made its default group (a file database, a snapshot) would
// otherwise answer group-name=default with nothing. The loaded read,
// the list and the inserts share one transaction, so a failure adds
// no group.
func (r *Repository) BackfillDefaultGroups(newGroup func(account, region, vpcID string) *EC2SecurityGroup) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	loaded, err := readLoaded(tx)
	if err != nil {
		return fmt.Errorf("read loaded flag: %w", err)
	}
	if loaded {
		return nil
	}
	rows, err := tx.Query(`SELECT v.account_id, v.region, v.id FROM ec2_vpcs v
		WHERE NOT EXISTS (SELECT 1 FROM ec2_security_groups g
		                  WHERE g.account_id = v.account_id AND g.vpc_id = v.id AND g.group_name = ?)`, DefaultGroupName)
	if err != nil {
		return err
	}
	var bare [][3]string
	for rows.Next() {
		var v [3]string
		if err := rows.Scan(&v[0], &v[1], &v[2]); err != nil {
			rows.Close()
			return err
		}
		bare = append(bare, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, v := range bare {
		if err := insertSecurityGroup(tx, v[0], newGroup(v[0], v[1], v[2])); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetVPC looks up a VPC by id, optionally scoped to a region. Pass
// region == "" to span every region (used by /mock/state gather and
// audit-time helpers); pass a concrete region to enforce that the
// VPC lives in that region (Codex pass 7 BLOCKING #1 — cross-region
// FK refs must reject with ErrNotFound).
func (r *Repository) GetVPC(account, region, id string) (*EC2VPC, error) {
	var data string
	var err error
	if region == "" {
		err = r.db.QueryRow(`SELECT data FROM ec2_vpcs WHERE account_id = ? AND id = ?`, account, id).Scan(&data)
	} else {
		err = r.db.QueryRow(`SELECT data FROM ec2_vpcs WHERE account_id = ? AND region = ? AND id = ?`, account, region, id).Scan(&data)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var v EC2VPC
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (r *Repository) ListVPCs(account, region string) ([]*EC2VPC, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM ec2_vpcs WHERE account_id = ? ORDER BY id`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM ec2_vpcs WHERE account_id = ? AND region = ? ORDER BY id`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2VPC
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var v EC2VPC
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return nil, err
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

// DeleteVPC removes a VPC, optionally scoped to a region. Empty
// region acts as account-wide (matches the Get* contract).
func (r *Repository) DeleteVPC(account, region, id string) error {
	// Detach any attached internet gateways manually — composite FK
	// SET NULL would NULL account_id too. Real EC2's contract is
	// detach-on-vpc-delete (the IGW survives, just unattached).
	if _, err := r.db.Exec(
		`UPDATE ec2_internet_gateways SET `+igwDetach+` WHERE account_id = ? AND vpc_id = ?`,
		account, id,
	); err != nil {
		return fmt.Errorf("detach igws before vpc delete: %w", err)
	}
	var res sql.Result
	var err error
	if region == "" {
		res, err = r.db.Exec(`DELETE FROM ec2_vpcs WHERE account_id = ? AND id = ?`, account, id)
	} else {
		res, err = r.db.Exec(`DELETE FROM ec2_vpcs WHERE account_id = ? AND region = ? AND id = ?`, account, region, id)
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

// ----- Subnet -----

// ErrSubnetConflict is why CreateSubnet refuses a CIDR overlapping a
// subnet of the same VPC.
var ErrSubnetConflict = errors.New("subnet CIDR conflicts with another subnet")

// CreateSubnet stores s unless its VPC is missing (ErrNotFound) or its
// CIDR overlaps a sibling's (ErrSubnetConflict). The lookups and the
// INSERT share one tx so two creates cannot both pass the check; they go
// through tx, never r.db, which would deadlock under SetMaxOpenConns(1).
func (r *Repository) CreateSubnet(account string, s *EC2Subnet) error {
	cidr, err := netip.ParsePrefix(s.CidrBlock)
	if err != nil {
		return fmt.Errorf("subnet cidr %q: %w", s.CidrBlock, err)
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Codex pass 7 BLOCKING #1 — parent must be in the SAME region as
	// the child, not just same account. Empty region is account-wide,
	// as GetVPC.
	var one int
	err = tx.QueryRow(`SELECT 1 FROM ec2_vpcs WHERE account_id = ? AND id = ? AND (? = '' OR region = ?)`,
		account, s.VPCID, s.Region, s.Region).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return models.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := subnetOverlap(tx, account, s.VPCID, cidr); err != nil {
		return err
	}
	if err := insertSubnet(tx, account, s); err != nil {
		return mapInsertError(err)
	}
	return tx.Commit()
}

// insertSubnet stores s under account.
func insertSubnet(ex execer, account string, s *EC2Subnet) error {
	body, _ := json.Marshal(s)
	_, err := ex.Exec(
		`INSERT INTO ec2_subnets (account_id, region, id, vpc_id, cidr_block, availability_zone, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, s.Region, s.ID, s.VPCID, s.CidrBlock, s.AvailabilityZone, s.ARN, string(body), s.CreatedAt,
	)
	return err
}

// subnetOverlap returns ErrSubnetConflict when cidr overlaps a subnet of
// vpcID.
func subnetOverlap(tx *sql.Tx, account, vpcID string, cidr netip.Prefix) error {
	rows, err := tx.Query(`SELECT cidr_block FROM ec2_subnets WHERE account_id = ? AND vpc_id = ?`, account, vpcID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sibling string
		if err := rows.Scan(&sibling); err != nil {
			return err
		}
		p, err := netip.ParsePrefix(sibling)
		if err != nil {
			return fmt.Errorf("stored subnet cidr %q: %w", sibling, err)
		}
		if p.Overlaps(cidr) {
			return ErrSubnetConflict
		}
	}
	return rows.Err()
}

// GetSubnet looks up a subnet by id, optionally scoped to a region.
// Empty region behaves like account-wide (Codex pass 7 BLOCKING #1).
func (r *Repository) GetSubnet(account, region, id string) (*EC2Subnet, error) {
	var data string
	var err error
	if region == "" {
		err = r.db.QueryRow(`SELECT data FROM ec2_subnets WHERE account_id = ? AND id = ?`, account, id).Scan(&data)
	} else {
		err = r.db.QueryRow(`SELECT data FROM ec2_subnets WHERE account_id = ? AND region = ? AND id = ?`, account, region, id).Scan(&data)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var s EC2Subnet
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ListSubnets returns the account's subnets. Empty region = all
// regions (state-gather path); non-empty region scopes results to a
// single region (Codex pass 8 BLOCKING #1 — DescribeSubnets must not
// leak across regions).
func (r *Repository) ListSubnets(account, region string) ([]*EC2Subnet, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM ec2_subnets WHERE account_id = ? ORDER BY id`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM ec2_subnets WHERE account_id = ? AND region = ? ORDER BY id`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2Subnet
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var s EC2Subnet
		if err := json.Unmarshal([]byte(data), &s); err != nil {
			return nil, err
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// UpdateSubnet applies change to the subnet and saves it.
func (r *Repository) UpdateSubnet(account, region, id string, change func(*EC2Subnet)) error {
	s, err := r.GetSubnet(account, region, id)
	if err != nil {
		return err
	}
	change(s)
	body, _ := json.Marshal(s)
	_, err = r.db.Exec(
		`UPDATE ec2_subnets SET data = ? WHERE account_id = ? AND region = ? AND id = ?`,
		string(body), account, s.Region, id,
	)
	return err
}

func (r *Repository) DeleteSubnet(account, region, id string) error {
	var res sql.Result
	var err error
	if region == "" {
		res, err = r.db.Exec(`DELETE FROM ec2_subnets WHERE account_id = ? AND id = ?`, account, id)
	} else {
		res, err = r.db.Exec(`DELETE FROM ec2_subnets WHERE account_id = ? AND region = ? AND id = ?`, account, region, id)
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

// ----- InternetGateway -----

func (r *Repository) CreateInternetGateway(account string, igw *EC2InternetGateway) error {
	return mapInsertError(insertInternetGateway(r.db, account, igw))
}

// insertInternetGateway stores igw under account, its vpc_id NULL when
// it is detached.
func insertInternetGateway(ex execer, account string, igw *EC2InternetGateway) error {
	body, _ := json.Marshal(igw)
	_, err := ex.Exec(
		`INSERT INTO ec2_internet_gateways (account_id, region, id, vpc_id, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, igw.Region, igw.ID, nullIfEmpty(igw.VPCID), igw.ARN, string(body), igw.CreatedAt,
	)
	return err
}

// igwDetach is the SET clause of every detach: vpc_id and the
// attachment's state go together.
const igwDetach = `vpc_id = NULL, data = json_remove(data, '$.attachment_state')`

// AttachInternetGateway attaches an IGW to a VPC. Both must live in
// the same region as the request (Codex pass 7 BLOCKING #1).
func (r *Repository) AttachInternetGateway(account, region, igwID, vpcID string) error {
	if _, err := r.GetVPC(account, region, vpcID); err != nil {
		return err
	}
	// IGW itself must also be in the requested region.
	if _, err := r.GetInternetGateway(account, region, igwID); err != nil {
		return err
	}
	res, err := r.db.Exec(
		`UPDATE ec2_internet_gateways SET vpc_id = ?, data = json_set(data, '$.attachment_state', 'available') WHERE account_id = ? AND id = ?`,
		vpcID, account, igwID,
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

func (r *Repository) DetachInternetGateway(account, region, igwID string) error {
	if _, err := r.GetInternetGateway(account, region, igwID); err != nil {
		return err
	}
	res, err := r.db.Exec(
		`UPDATE ec2_internet_gateways SET `+igwDetach+` WHERE account_id = ? AND id = ?`,
		account, igwID,
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

// GetInternetGateway looks up an IGW by id, optionally scoped to a
// region. Empty region behaves like account-wide.
func (r *Repository) GetInternetGateway(account, region, id string) (*EC2InternetGateway, error) {
	var data string
	var vpcID sql.NullString
	var err error
	if region == "" {
		err = r.db.QueryRow(
			`SELECT data, vpc_id FROM ec2_internet_gateways WHERE account_id = ? AND id = ?`,
			account, id,
		).Scan(&data, &vpcID)
	} else {
		err = r.db.QueryRow(
			`SELECT data, vpc_id FROM ec2_internet_gateways WHERE account_id = ? AND region = ? AND id = ?`,
			account, region, id,
		).Scan(&data, &vpcID)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var igw EC2InternetGateway
	if err := json.Unmarshal([]byte(data), &igw); err != nil {
		return nil, err
	}
	if vpcID.Valid {
		igw.VPCID = vpcID.String
	} else {
		igw.VPCID = ""
	}
	return &igw, nil
}

// ListInternetGateways returns IGWs for the account, optionally
// scoped to a region (Codex pass 8 BLOCKING #1 — DescribeInternetGateways
// must not leak across regions). Empty region = all regions for the
// state-gather path.
func (r *Repository) ListInternetGateways(account, region string) ([]*EC2InternetGateway, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(
			`SELECT id, region FROM ec2_internet_gateways WHERE account_id = ? ORDER BY id`,
			account,
		)
	} else {
		rows, err = r.db.Query(
			`SELECT id, region FROM ec2_internet_gateways WHERE account_id = ? AND region = ? ORDER BY id`,
			account, region,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type idReg struct{ id, reg string }
	var pairs []idReg
	for rows.Next() {
		var p idReg
		if err := rows.Scan(&p.id, &p.reg); err != nil {
			return nil, err
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	out := make([]*EC2InternetGateway, 0, len(pairs))
	for _, p := range pairs {
		igw, err := r.GetInternetGateway(account, p.reg, p.id)
		if errors.Is(err, models.ErrNotFound) {
			continue // deleted since the list
		}
		if err != nil {
			return nil, err
		}
		out = append(out, igw)
	}
	return out, nil
}

func (r *Repository) DeleteInternetGateway(account, region, id string) error {
	var res sql.Result
	var err error
	if region == "" {
		res, err = r.db.Exec(`DELETE FROM ec2_internet_gateways WHERE account_id = ? AND id = ?`, account, id)
	} else {
		res, err = r.db.Exec(`DELETE FROM ec2_internet_gateways WHERE account_id = ? AND region = ? AND id = ?`, account, region, id)
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

// ----- RouteTable + RouteTableAssociation + Route -----

func (r *Repository) CreateRouteTable(account string, rt *EC2RouteTable) error {
	// Codex pass 7 BLOCKING #1 — parent VPC must be in the same region.
	if _, err := r.GetVPC(account, rt.Region, rt.VPCID); err != nil {
		return err
	}
	return mapInsertError(insertRouteTable(r.db, account, rt))
}

func insertRouteTable(ex execer, account string, rt *EC2RouteTable) error {
	body, _ := json.Marshal(rt)
	_, err := ex.Exec(
		`INSERT INTO ec2_route_tables (account_id, region, id, vpc_id, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, rt.Region, rt.ID, rt.VPCID, rt.ARN, string(body), rt.CreatedAt,
	)
	return err
}

// GetRouteTable looks up a route table by id, optionally scoped to a
// region.
func (r *Repository) GetRouteTable(account, region, id string) (*EC2RouteTable, error) {
	var data string
	var err error
	if region == "" {
		err = r.db.QueryRow(`SELECT data FROM ec2_route_tables WHERE account_id = ? AND id = ?`, account, id).Scan(&data)
	} else {
		err = r.db.QueryRow(`SELECT data FROM ec2_route_tables WHERE account_id = ? AND region = ? AND id = ?`, account, region, id).Scan(&data)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var rt EC2RouteTable
	if err := json.Unmarshal([]byte(data), &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}

// ErrMainRouteTable refuses deleting a VPC's main route table, which
// would drop its main association with it.
var ErrMainRouteTable = errors.New("the route table is its VPC's main route table")

// DeleteRouteTable deletes route table id, optionally scoped to a
// region, answering models.ErrNotFound when there is none and
// ErrMainRouteTable, deleting nothing, when it holds a main association.
func (r *Repository) DeleteRouteTable(account, region, id string) error {
	const notMain = ` AND NOT EXISTS (SELECT 1 FROM ec2_route_table_associations a
		WHERE a.account_id = ec2_route_tables.account_id AND a.route_table_id = ec2_route_tables.id AND a.main = 1)`
	var res sql.Result
	var err error
	if region == "" {
		res, err = r.db.Exec(`DELETE FROM ec2_route_tables WHERE account_id = ? AND id = ?`+notMain, account, id)
	} else {
		res, err = r.db.Exec(`DELETE FROM ec2_route_tables WHERE account_id = ? AND region = ? AND id = ?`+notMain, account, region, id)
	}
	if err != nil {
		return mapDeleteError(err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	if _, err := r.GetRouteTable(account, region, id); err != nil {
		return err
	}
	return ErrMainRouteTable
}

// AssociateRouteTable links a route table to a subnet. Both must
// exist in the request's region (Codex pass 7 BLOCKING #1).
func (r *Repository) AssociateRouteTable(account, region string, assoc *EC2RouteTableAssociation) error {
	rt, err := r.GetRouteTable(account, region, assoc.RouteTableID)
	if err != nil {
		return err
	}
	if _, err := r.GetSubnet(account, region, assoc.SubnetID); err != nil {
		return err
	}
	return mapInsertError(insertAssociation(r.db, account, rt.VPCID, assoc))
}

// insertAssociation stores a under account, in route table vpcID's VPC,
// its subnet_id NULL when it has none (a main or an edge association)
// and its gateway_id NULL when it has none.
func insertAssociation(ex execer, account, vpcID string, a *EC2RouteTableAssociation) error {
	_, err := ex.Exec(
		`INSERT INTO ec2_route_table_associations (account_id, id, route_table_id, vpc_id, subnet_id, gateway_id, main, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		account, a.ID, a.RouteTableID, vpcID, nullIfEmpty(a.SubnetID), nullIfEmpty(a.GatewayID), a.Main, a.State,
	)
	return err
}

// ErrMainAssociation refuses disassociating a VPC's main association:
// AWS moves it with ReplaceRouteTableAssociation, never drops it.
var ErrMainAssociation = errors.New("cannot disassociate the main route table association")

// DisassociateRouteTable deletes association associationID, answering
// models.ErrNotFound when there is none and ErrMainAssociation, deleting
// nothing, when it is a main association.
func (r *Repository) DisassociateRouteTable(account, associationID string) error {
	var main bool
	err := r.db.QueryRow(`SELECT main FROM ec2_route_table_associations WHERE account_id = ? AND id = ?`,
		account, associationID).Scan(&main)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return models.ErrNotFound
	case err != nil:
		return err
	case main:
		return ErrMainAssociation
	}
	_, err = r.db.Exec(`DELETE FROM ec2_route_table_associations WHERE account_id = ? AND id = ?`, account, associationID)
	return err
}

// CreateRoute inserts a route into the parent route table; the
// route table must live in the request's region (Codex pass 7
// BLOCKING #1).
func (r *Repository) CreateRoute(account, region string, rt *EC2Route) error {
	if _, err := r.GetRouteTable(account, region, rt.RouteTableID); err != nil {
		return err
	}
	return mapInsertError(insertRoute(r.db, account, rt))
}

func insertRoute(ex execer, account string, rt *EC2Route) error {
	_, err := ex.Exec(
		`INSERT INTO ec2_routes (account_id, route_table_id, destination_cidr_block, gateway_id, nat_gateway_id, instance_id, network_interface_id, origin, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, rt.RouteTableID, rt.DestinationCidrBlock,
		nullIfEmpty(rt.GatewayID), nullIfEmpty(rt.NatGatewayID),
		nullIfEmpty(rt.InstanceID), nullIfEmpty(rt.NetworkInterfaceID), rt.Origin, rt.State,
	)
	return err
}

// DeleteRoute removes a single route from a route table. The route
// table is required to live in the request's region when region is
// non-empty (Codex pass 7 BLOCKING #1).
func (r *Repository) DeleteRoute(account, region, routeTableID, destination string) error {
	if region != "" {
		if _, err := r.GetRouteTable(account, region, routeTableID); err != nil {
			return err
		}
	}
	res, err := r.db.Exec(
		`DELETE FROM ec2_routes WHERE account_id = ? AND route_table_id = ? AND destination_cidr_block = ?`,
		account, routeTableID, destination,
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

// ----- SecurityGroup -----

func (r *Repository) CreateSecurityGroup(account string, sg *EC2SecurityGroup) error {
	// Codex pass 7 BLOCKING #1 — parent VPC must be in the same region.
	if _, err := r.GetVPC(account, sg.Region, sg.VPCID); err != nil {
		return err
	}
	return insertSecurityGroup(r.db, account, sg)
}

func insertSecurityGroup(ex execer, account string, sg *EC2SecurityGroup) error {
	body, _ := json.Marshal(sg)
	_, err := ex.Exec(
		`INSERT INTO ec2_security_groups (account_id, region, id, vpc_id, group_name, description, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, sg.Region, sg.ID, sg.VPCID, sg.GroupName, sg.Description, sg.ARN, string(body), sg.CreatedAt,
	)
	return mapInsertError(err)
}

// GetSecurityGroup looks up an SG by id, optionally scoped to a
// region. Empty region behaves like account-wide.
func (r *Repository) GetSecurityGroup(account, region, id string) (*EC2SecurityGroup, error) {
	var data string
	var err error
	if region == "" {
		err = r.db.QueryRow(`SELECT data FROM ec2_security_groups WHERE account_id = ? AND id = ?`, account, id).Scan(&data)
	} else {
		err = r.db.QueryRow(`SELECT data FROM ec2_security_groups WHERE account_id = ? AND region = ? AND id = ?`, account, region, id).Scan(&data)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var sg EC2SecurityGroup
	if err := json.Unmarshal([]byte(data), &sg); err != nil {
		return nil, err
	}
	return &sg, nil
}

// ListSecurityGroups returns every SG for the account, optionally
// scoped to a region. Used by /mock/state's EC2 gather (Codex pass 4
// BLOCKING #1 fix — was previously inferring SGs only from instance
// VPCSecurityGroupIDs which missed standalone SGs and duplicated
// shared ones).
func (r *Repository) ListSecurityGroups(account, region string) ([]*EC2SecurityGroup, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM ec2_security_groups WHERE account_id = ? ORDER BY id`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM ec2_security_groups WHERE account_id = ? AND region = ? ORDER BY id`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2SecurityGroup
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var sg EC2SecurityGroup
		if err := json.Unmarshal([]byte(data), &sg); err != nil {
			return nil, err
		}
		out = append(out, &sg)
	}
	return out, rows.Err()
}

// securityGroupRegion returns the region of the group id, which must be
// in region unless region is "" (ErrNotFound).
func securityGroupRegion(q interface {
	QueryRow(string, ...any) *sql.Row
}, account, region, id string) (string, error) {
	var got string
	err := q.QueryRow(`SELECT region FROM ec2_security_groups WHERE account_id = ? AND id = ? AND (? = '' OR region = ?)`,
		account, id, region, region).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return "", models.ErrNotFound
	}
	return got, err
}

// ruleColumns are the ec2_security_group_rules columns scanRule reads,
// in order.
const ruleColumns = `id, group_id, group_owner_id, is_egress, perm_ord, src_ord, ip_protocol, from_port, to_port,
	cidr_ipv4, cidr_ipv6, prefix_list_id, referenced_group_id, referenced_user_id, description`

// ruleMatch picks a group's rules of one permission (?1-?6: account,
// group, is_egress, protocol, from and to port); ruleSourceMatch narrows
// it to one source (?7-?10: the four source columns, NULL but one).
const (
	ruleMatch       = `account_id = ?1 AND group_id = ?2 AND is_egress = ?3 AND ip_protocol = ?4 AND from_port = ?5 AND to_port = ?6`
	ruleSourceMatch = `cidr_ipv4 IS ?7 AND cidr_ipv6 IS ?8 AND prefix_list_id IS ?9 AND referenced_group_id IS ?10`
)

// ruleOrdinals selects, by ruleMatchArgs, where a rule goes: its
// permission's perm_ord (after the direction's last permission when it
// has none), the src_ord after the permission's last source, and
// whether the permission already holds the rule's source.
const ruleOrdinals = `SELECT
	COALESCE(MIN(perm_ord), (SELECT COALESCE(MAX(perm_ord) + 1, 0) FROM ec2_security_group_rules
	                         WHERE account_id = ?1 AND group_id = ?2 AND is_egress = ?3)),
	COALESCE(MAX(src_ord) + 1, 0),
	COALESCE(MAX(` + ruleSourceMatch + `), 0)
	FROM ec2_security_group_rules WHERE ` + ruleMatch

// ruleMatchArgs are ruleMatch's and ruleSourceMatch's args for rule.
func ruleMatchArgs(account string, rule EC2SecurityGroupRule) []any {
	return []any{account, rule.GroupID, rule.IsEgress, rule.IPProtocol, rule.FromPort, rule.ToPort,
		nullIfEmpty(rule.CidrIPv4), nullIfEmpty(rule.CidrIPv6), nullIfEmpty(rule.PrefixListID), nullIfEmpty(rule.ReferencedGroupID)}
}

// scanRule reads one ruleColumns row through scan.
func scanRule(scan func(dest ...any) error) (EC2SecurityGroupRule, error) {
	var r EC2SecurityGroupRule
	var v4, v6, pl, group, user sql.NullString
	err := scan(&r.ID, &r.GroupID, &r.GroupOwnerID, &r.IsEgress, &r.PermOrd, &r.SrcOrd, &r.IPProtocol, &r.FromPort, &r.ToPort,
		&v4, &v6, &pl, &group, &user, &r.Description)
	r.CidrIPv4, r.CidrIPv6, r.PrefixListID, r.ReferencedGroupID, r.ReferencedUserID = v4.String, v6.String, pl.String, group.String, user.String
	return r, err
}

// ListSecurityGroupRules returns the rules of the group id, which must
// be in region unless region is "" (ErrNotFound), ordered by direction
// (ingress first), permission and source.
func (r *Repository) ListSecurityGroupRules(account, region, id string) ([]EC2SecurityGroupRule, error) {
	if _, err := securityGroupRegion(r.db, account, region, id); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(`SELECT `+ruleColumns+` FROM ec2_security_group_rules WHERE account_id = ? AND group_id = ?
		ORDER BY is_egress, perm_ord, src_ord`, account, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EC2SecurityGroupRule
	for rows.Next() {
		rule, err := scanRule(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

// ListRegionSecurityGroupRules returns the account's rules in region,
// every region when region is "", ordered by group, direction,
// permission and source.
func (r *Repository) ListRegionSecurityGroupRules(account, region string) ([]EC2SecurityGroupRule, error) {
	rows, err := r.db.Query(`SELECT `+ruleColumns+` FROM ec2_security_group_rules WHERE account_id = ? AND (? = '' OR region = ?)
		ORDER BY group_id, is_egress, perm_ord, src_ord`, account, region, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EC2SecurityGroupRule
	for rows.Next() {
		rule, err := scanRule(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

// GetSecurityGroupRule returns the rule id, which must be in region
// unless region is "" (RuleNotFoundError).
func (r *Repository) GetSecurityGroupRule(account, region, id string) (EC2SecurityGroupRule, error) {
	rule, err := scanRule(r.db.QueryRow(`SELECT `+ruleColumns+` FROM ec2_security_group_rules
		WHERE account_id = ? AND id = ? AND (? = '' OR region = ?)`, account, id, region, region).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return rule, RuleNotFoundError{ID: id}
	}
	return rule, err
}

// RuleNotFoundError is a security group rule id that names no rule
// where it was looked for. It is models.ErrNotFound.
type RuleNotFoundError struct{ ID string }

func (e RuleNotFoundError) Error() string { return "security group rule " + e.ID + " not found" }
func (e RuleNotFoundError) Unwrap() error { return models.ErrNotFound }

// AuthorizeSecurityGroupRules adds to the group id each of rules, in
// order, whose source its permission (direction, protocol and ports)
// lacks, after the permission's last source, or as a new permission
// after the direction's last. It returns the rules it added; one whose
// source is held is skipped, so authorizing is idempotent. The group
// must be in region unless region is "" (ErrNotFound). The reads and
// writes share one transaction.
func (r *Repository) AuthorizeSecurityGroupRules(account, region, id string, rules []EC2SecurityGroupRule) ([]EC2SecurityGroupRule, error) {
	var added []EC2SecurityGroupRule
	err := r.inTx(func(tx *sql.Tx) error {
		groupRegion, err := securityGroupRegion(tx, account, region, id)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			rule.GroupID = id
			var held bool
			if err := tx.QueryRow(ruleOrdinals, ruleMatchArgs(account, rule)...).Scan(&rule.PermOrd, &rule.SrcOrd, &held); err != nil {
				return err
			}
			if held {
				continue
			}
			if err := insertRule(tx, account, groupRegion, rule); err != nil {
				return err
			}
			added = append(added, rule)
		}
		return nil
	})
	return added, err
}

func insertRule(ex execer, account, region string, rule EC2SecurityGroupRule) error {
	_, err := ex.Exec(`INSERT INTO ec2_security_group_rules (account_id, region, `+ruleColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, region, rule.ID, rule.GroupID, rule.GroupOwnerID, rule.IsEgress, rule.PermOrd, rule.SrcOrd,
		rule.IPProtocol, rule.FromPort, rule.ToPort,
		nullIfEmpty(rule.CidrIPv4), nullIfEmpty(rule.CidrIPv6), nullIfEmpty(rule.PrefixListID),
		nullIfEmpty(rule.ReferencedGroupID), nullIfEmpty(rule.ReferencedUserID), rule.Description)
	return mapInsertError(err)
}

// RevokeSecurityGroupRules deletes the group id's rules with the
// direction, protocol, ports and source of one of rules; one it lacks
// is no error. A rule with an ID deletes the rule of that id and
// direction instead, and one the group lacks is RuleNotFoundError,
// which deletes nothing. A permission keeps its position while it has
// a source. The group must be in region unless region is ""
// (ErrNotFound).
func (r *Repository) RevokeSecurityGroupRules(account, region, id string, rules []EC2SecurityGroupRule) error {
	return r.inTx(func(tx *sql.Tx) error {
		if _, err := securityGroupRegion(tx, account, region, id); err != nil {
			return err
		}
		for _, rule := range rules {
			rule.GroupID = id
			if rule.ID != "" {
				if err := revokeRuleByID(tx, account, rule); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.Exec(`DELETE FROM ec2_security_group_rules WHERE `+ruleMatch+` AND `+ruleSourceMatch,
				ruleMatchArgs(account, rule)...); err != nil {
				return err
			}
		}
		return nil
	})
}

// revokeRuleByID deletes the rule rule.ID of rule's group and direction.
func revokeRuleByID(ex execer, account string, rule EC2SecurityGroupRule) error {
	res, err := ex.Exec(`DELETE FROM ec2_security_group_rules WHERE account_id = ? AND group_id = ? AND is_egress = ? AND id = ?`,
		account, rule.GroupID, rule.IsEgress, rule.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		err = RuleNotFoundError{ID: rule.ID}
	}
	return err
}

func (r *Repository) DeleteSecurityGroup(account, region, id string) error {
	var res sql.Result
	var err error
	if region == "" {
		res, err = r.db.Exec(`DELETE FROM ec2_security_groups WHERE account_id = ? AND id = ?`, account, id)
	} else {
		res, err = r.db.Exec(`DELETE FROM ec2_security_groups WHERE account_id = ? AND region = ? AND id = ?`, account, region, id)
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

// ----- EIP -----

// CreateEIP stores eip with the first public IP, from eip.PublicIP up
// and wrapping within its /24, that no address in its account and
// region holds, and sets eip.PublicIP to it: AWS never gives two
// allocations one IP. It is ErrConflict when the /24 is full.
// ponytail: one /24 caps a region at 256 addresses; widen the range if
// a test needs more.
func (r *Repository) CreateEIP(account string, eip *EC2EIP) error {
	// SetMaxOpenConns(1): only tx may touch the db until Commit, so two
	// allocations cannot pick the same free IP.
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	held, err := stringSet(tx, `SELECT public_ip FROM ec2_eips WHERE account_id = ? AND region = ?`, account, eip.Region)
	if err != nil {
		return err
	}
	if eip.PublicIP, err = freeIP(eip.PublicIP, held); err != nil {
		return err
	}
	if err := insertEIP(tx, account, eip); err != nil {
		return err
	}
	return tx.Commit()
}

// insertEIP stores eip under account with its association, if any.
func insertEIP(ex execer, account string, eip *EC2EIP) error {
	body, _ := json.Marshal(eip)
	_, err := ex.Exec(
		`INSERT INTO ec2_eips (account_id, region, allocation_id, domain, public_ip, network_interface_id, instance_id, association_id, data, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, eip.Region, eip.AllocationID, eip.Domain, eip.PublicIP, nullIfEmpty(eip.NetworkInterfaceID),
		nullIfEmpty(eip.InstanceID), nullIfEmpty(eip.AssociationID), string(body), eip.CreatedAt,
	)
	return mapInsertError(err)
}

// freeIP returns the first IPv4 address from want up, wrapping within
// its /24, not in held.
func freeIP(want string, held map[string]bool) (string, error) {
	i := strings.LastIndex(want, ".")
	last, err := strconv.Atoi(want[i+1:])
	if i < 0 || err != nil {
		return "", fmt.Errorf("public IP %q is not IPv4", want)
	}
	for step := range 256 {
		if ip := want[:i+1] + strconv.Itoa((last+step)%256); !held[ip] {
			return ip, nil
		}
	}
	return "", fmt.Errorf("every address in %s0/24 is allocated: %w", want[:i+1], models.ErrConflict)
}

// GetEIP looks up an EIP by allocation id, optionally scoped to a
// region (Codex pass 7 BLOCKING #1).
func (r *Repository) GetEIP(account, region, allocationID string) (*EC2EIP, error) {
	var data string
	var err error
	if region == "" {
		err = r.db.QueryRow(`SELECT data FROM ec2_eips WHERE account_id = ? AND allocation_id = ?`, account, allocationID).Scan(&data)
	} else {
		err = r.db.QueryRow(`SELECT data FROM ec2_eips WHERE account_id = ? AND region = ? AND allocation_id = ?`, account, region, allocationID).Scan(&data)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var eip EC2EIP
	if err := json.Unmarshal([]byte(data), &eip); err != nil {
		return nil, err
	}
	return &eip, nil
}

// AssociateEIP saves eip's new association and eni's public IP in one
// transaction: EC2 shows an associated address as its ENI's public IP.
// The UPDATE itself refuses an address that is already associated, or
// an ENI that already has an address, with ErrConflict, so of two
// racing associates only one commits.
func (r *Repository) AssociateEIP(account string, eip *EC2EIP, eni *EC2NetworkInterface) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	body, _ := json.Marshal(eip)
	res, err := tx.Exec(
		`UPDATE ec2_eips SET network_interface_id = ?, instance_id = ?, association_id = ?, data = ?
		   WHERE account_id = ? AND allocation_id = ? AND association_id IS NULL
		     AND NOT EXISTS (SELECT 1 FROM ec2_eips WHERE account_id = ? AND network_interface_id = ?)`,
		eip.NetworkInterfaceID, nullIfEmpty(eip.InstanceID), eip.AssociationID, string(body), account, eip.AllocationID,
		account, eip.NetworkInterfaceID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM ec2_eips WHERE account_id = ? AND allocation_id = ?`, account, eip.AllocationID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return models.ErrNotFound
		}
		return models.ErrConflict
	}
	if err := updateENITx(tx, account, eni); err != nil {
		return err
	}
	return tx.Commit()
}

// DisassociateEIP saves eip, its association cleared, and eni's public
// IP in one transaction, claimPublicIP moving a public IP eni gets back
// past one another ENI holds. eni may be nil.
func (r *Repository) DisassociateEIP(account string, eip *EC2EIP, eni *EC2NetworkInterface) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	body, _ := json.Marshal(eip)
	res, err := tx.Exec(
		`UPDATE ec2_eips SET network_interface_id = NULL, instance_id = NULL, association_id = NULL, data = ?
		   WHERE account_id = ? AND allocation_id = ?`,
		string(body), account, eip.AllocationID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return models.ErrNotFound
	}
	if eni != nil {
		if err := claimPublicIP(tx, account, eni); err != nil {
			return err
		}
		if err := updateENITx(tx, account, eni); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func updateENITx(tx *sql.Tx, account string, eni *EC2NetworkInterface) error {
	body, _ := json.Marshal(eni)
	res, err := tx.Exec(`UPDATE ec2_network_interfaces SET data = ? WHERE account_id = ? AND id = ?`, string(body), account, eni.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// DeleteEIP releases an address. An associated address is ErrInUse,
// as EC2 refuses to release it.
func (r *Repository) DeleteEIP(account, region, allocationID string) error {
	res, err := r.db.Exec(
		`DELETE FROM ec2_eips WHERE account_id = ? AND (? = '' OR region = ?) AND allocation_id = ? AND association_id IS NULL`,
		account, region, region, allocationID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	if _, err := r.GetEIP(account, region, allocationID); err != nil {
		return err
	}
	return models.ErrInUse
}

// ListRouteTables returns every route table for the account, optionally
// scoped to a region. Empty region == account-wide. Used by /mock/state
// (Codex pass 10 BLOCKING #2 fix).
func (r *Repository) ListRouteTables(account, region string) ([]*EC2RouteTable, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM ec2_route_tables WHERE account_id = ? ORDER BY id`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM ec2_route_tables WHERE account_id = ? AND region = ? ORDER BY id`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2RouteTable
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var rt EC2RouteTable
		if err := json.Unmarshal([]byte(data), &rt); err != nil {
			return nil, err
		}
		out = append(out, &rt)
	}
	return out, rows.Err()
}

// ListRoutes returns every route for the account, ordered by route
// table id. Used by /mock/state (Codex pass 10 BLOCKING #2 fix).
// Account-wide; routes are not region-scoped at this layer (the parent
// route_table is, and the FK propagates).
func (r *Repository) ListRoutes(account string) ([]*EC2Route, error) {
	rows, err := r.db.Query(`SELECT `+routeColumns+` FROM ec2_routes WHERE account_id = ?
		   ORDER BY route_table_id, destination_cidr_block`,
		account,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2Route
	for rows.Next() {
		rt, err := scanRoute(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, rt)
	}
	return out, rows.Err()
}

// routeColumns are the ec2_routes columns scanRoute reads, in order.
const routeColumns = `route_table_id, destination_cidr_block, gateway_id, nat_gateway_id, instance_id, network_interface_id, origin, state`

// scanRoute reads one routeColumns row through scan.
func scanRoute(scan func(dest ...any) error) (*EC2Route, error) {
	var rt EC2Route
	var gw, nat, inst, eni sql.NullString
	if err := scan(&rt.RouteTableID, &rt.DestinationCidrBlock, &gw, &nat, &inst, &eni, &rt.Origin, &rt.State); err != nil {
		return nil, err
	}
	rt.GatewayID, rt.NatGatewayID, rt.InstanceID, rt.NetworkInterfaceID = gw.String, nat.String, inst.String, eni.String
	return &rt, nil
}

// ListRouteTableAssociations returns every route-table association for
// the account. Used by /mock/state (Codex pass 10 BLOCKING #2 fix).
func (r *Repository) ListRouteTableAssociations(account string) ([]*EC2RouteTableAssociation, error) {
	rows, err := r.db.Query(`SELECT `+associationColumns+` FROM ec2_route_table_associations
		   WHERE account_id = ? ORDER BY id`,
		account,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2RouteTableAssociation
	for rows.Next() {
		a, err := scanAssociation(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// associationColumns are the ec2_route_table_associations columns
// scanAssociation reads, in order.
const associationColumns = `id, route_table_id, subnet_id, gateway_id, main, state`

// scanAssociation reads one associationColumns row through scan, a
// NULL subnet_id or gateway_id as "".
func scanAssociation(scan func(dest ...any) error) (*EC2RouteTableAssociation, error) {
	var a EC2RouteTableAssociation
	var subnet, gateway sql.NullString
	if err := scan(&a.ID, &a.RouteTableID, &subnet, &gateway, &a.Main, &a.State); err != nil {
		return nil, err
	}
	a.SubnetID, a.GatewayID = subnet.String, gateway.String
	return &a, nil
}

// ListEIPs returns every EIP for the account, optionally scoped to a
// region. Empty region == account-wide. Used by /mock/state
// (Codex pass 10 BLOCKING #2 fix).
func (r *Repository) ListEIPs(account, region string) ([]*EC2EIP, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM ec2_eips WHERE account_id = ? ORDER BY allocation_id`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM ec2_eips WHERE account_id = ? AND region = ? ORDER BY allocation_id`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2EIP
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var eip EC2EIP
		if err := json.Unmarshal([]byte(data), &eip); err != nil {
			return nil, err
		}
		out = append(out, &eip)
	}
	return out, rows.Err()
}

// ----- Availability zones -----

// AvailabilityZone is one zone of an account's region, as fakeaws-
// loader records it from DescribeAvailabilityZones. The table is
// account data, so isEmpty counts its rows.
type AvailabilityZone struct {
	Region             string
	ZoneName           string
	ZoneID             string
	State              string
	OptInStatus        string
	ZoneType           string
	GroupName          string
	NetworkBorderGroup string
}

// PutAvailabilityZone stores z under account, replacing the row for
// the same region and zone name.
func (r *Repository) PutAvailabilityZone(account string, z AvailabilityZone) error {
	return putAvailabilityZone(r.db, account, z)
}

func putAvailabilityZone(ex execer, account string, z AvailabilityZone) error {
	_, err := ex.Exec(`INSERT OR REPLACE INTO availability_zones
		(account_id, region, zone_name, zone_id, state, opt_in_status, zone_type, group_name, network_border_group)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, z.Region, z.ZoneName, z.ZoneID, z.State, z.OptInStatus, z.ZoneType, z.GroupName, z.NetworkBorderGroup)
	return err
}

// ListAvailabilityZones returns account's zones in region by zone name.
func (r *Repository) ListAvailabilityZones(account, region string) ([]AvailabilityZone, error) {
	rows, err := r.db.Query(`SELECT region, zone_name, zone_id, state, opt_in_status, zone_type, group_name, network_border_group
		FROM availability_zones WHERE account_id = ? AND region = ? ORDER BY zone_name`, account, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AvailabilityZone
	for rows.Next() {
		var z AvailabilityZone
		if err := rows.Scan(&z.Region, &z.ZoneName, &z.ZoneID, &z.State, &z.OptInStatus, &z.ZoneType, &z.GroupName, &z.NetworkBorderGroup); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// ----- helpers -----

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
