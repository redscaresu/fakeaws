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
//	     │              │
//	ec2_instances  ec2_routes
//
// This file ships networking only: VPCs, Subnets, InternetGateways,
// RouteTables, RouteTableAssociations, Routes, SecurityGroups, EIPs.
// Compute (instances, key pairs, AMI fixtures) lands in S44-T6 in
// repository/ec2_compute.go.
//
// Server-stamped IDs follow AWS convention:
//
//	vpc-, subnet-, sg-, rtb-, igw-, rtbassoc-, eipalloc-, eni-
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
		subnet_id      TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, route_table_id) REFERENCES ec2_route_tables(account_id, id) ON DELETE CASCADE,
		FOREIGN KEY (account_id, subnet_id)      REFERENCES ec2_subnets(account_id, id)      ON DELETE CASCADE,
		UNIQUE (account_id, subnet_id) -- one association per subnet (real EC2 contract)
	)`,
	`CREATE TABLE IF NOT EXISTS ec2_routes (
		account_id              TEXT NOT NULL,
		route_table_id          TEXT NOT NULL,
		destination_cidr_block  TEXT NOT NULL,
		gateway_id              TEXT,
		nat_gateway_id          TEXT,
		instance_id             TEXT,
		network_interface_id    TEXT,
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
		ingress      TEXT NOT NULL DEFAULT '[]',
		egress       TEXT NOT NULL DEFAULT '[]',
		arn          TEXT NOT NULL,
		data         TEXT NOT NULL,
		created_at   TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, vpc_id) REFERENCES ec2_vpcs(account_id, id) ON DELETE CASCADE,
		UNIQUE (account_id, vpc_id, group_name)
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
	MapPublicIPOnLaunch bool `json:"map_public_ip_on_launch"`
}

type EC2InternetGateway struct {
	ID        string `json:"internet_gateway_id"`
	VPCID     string `json:"vpc_id,omitempty"` // nullable — IGW may be detached
	Region    string `json:"region"`
	ARN       string `json:"arn"`
	CreatedAt string `json:"created_at"`
}

type EC2RouteTable struct {
	ID        string `json:"route_table_id"`
	VPCID     string `json:"vpc_id"`
	Region    string `json:"region"`
	ARN       string `json:"arn"`
	CreatedAt string `json:"created_at"`
}

type EC2RouteTableAssociation struct {
	ID           string `json:"association_id"`
	RouteTableID string `json:"route_table_id"`
	SubnetID     string `json:"subnet_id"`
}

type EC2Route struct {
	RouteTableID         string `json:"route_table_id"`
	DestinationCidrBlock string `json:"destination_cidr_block"`
	GatewayID            string `json:"gateway_id,omitempty"`
	NatGatewayID         string `json:"nat_gateway_id,omitempty"`
	InstanceID           string `json:"instance_id,omitempty"`
	NetworkInterfaceID   string `json:"network_interface_id,omitempty"`
}

type EC2SecurityGroup struct {
	ID          string `json:"group_id"`
	VPCID       string `json:"vpc_id"`
	GroupName   string `json:"group_name"`
	Description string `json:"description"`
	Region      string `json:"region"`
	ARN         string `json:"arn"`
	// Ingress / Egress are stored as JSON in the corresponding columns;
	// the JSON shape is opaque at this layer — handlers parse / emit
	// the documented IpPermissions structure.
	CreatedAt string `json:"created_at"`
}

type EC2EIP struct {
	AllocationID       string `json:"allocation_id"`
	Domain             string `json:"domain"`
	PublicIP           string `json:"public_ip"`
	NetworkInterfaceID string `json:"network_interface_id,omitempty"`
	InstanceID         string `json:"instance_id,omitempty"`
	AssociationID      string `json:"association_id,omitempty"`
	PrivateIP          string `json:"private_ip,omitempty"`
	Region             string `json:"region"`
	CreatedAt          string `json:"created_at"`
}

// ----- VPC -----

// execer is the Exec *sql.DB and *sql.Tx share, so one insert serves a
// lone write and a transaction's.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func (r *Repository) CreateVPC(account string, v *EC2VPC) error {
	return insertVPC(r.db, account, v)
}

// CreateVPCWithDefaultGroup stores v and sg, its security group named
// default, in one transaction: EC2's CreateVpc makes both, so no read
// sees the VPC without its default group.
func (r *Repository) CreateVPCWithDefaultGroup(account string, v *EC2VPC, sg *EC2SecurityGroup) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertVPC(tx, account, v); err != nil {
		return err
	}
	if err := insertSecurityGroup(tx, account, sg); err != nil {
		return err
	}
	return tx.Commit()
}

func insertVPC(ex execer, account string, v *EC2VPC) error {
	body, _ := json.Marshal(v)
	_, err := ex.Exec(
		`INSERT INTO ec2_vpcs (account_id, region, id, cidr_block, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, v.Region, v.ID, v.CidrBlock, v.ARN, string(body), v.CreatedAt,
	)
	return mapInsertError(err)
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
		`UPDATE ec2_internet_gateways SET vpc_id = NULL WHERE account_id = ? AND vpc_id = ?`,
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
	body, _ := json.Marshal(s)
	if _, err := tx.Exec(
		`INSERT INTO ec2_subnets (account_id, region, id, vpc_id, cidr_block, availability_zone, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, s.Region, s.ID, s.VPCID, s.CidrBlock, s.AvailabilityZone, s.ARN, string(body), s.CreatedAt,
	); err != nil {
		return mapInsertError(err)
	}
	return tx.Commit()
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
	body, _ := json.Marshal(igw)
	var vpcID *string
	if igw.VPCID != "" {
		vpcID = &igw.VPCID
	}
	_, err := r.db.Exec(
		`INSERT INTO ec2_internet_gateways (account_id, region, id, vpc_id, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, igw.Region, igw.ID, vpcID, igw.ARN, string(body), igw.CreatedAt,
	)
	return mapInsertError(err)
}

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
		`UPDATE ec2_internet_gateways SET vpc_id = ? WHERE account_id = ? AND id = ?`,
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
		`UPDATE ec2_internet_gateways SET vpc_id = NULL WHERE account_id = ? AND id = ?`,
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
	body, _ := json.Marshal(rt)
	_, err := r.db.Exec(
		`INSERT INTO ec2_route_tables (account_id, region, id, vpc_id, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, rt.Region, rt.ID, rt.VPCID, rt.ARN, string(body), rt.CreatedAt,
	)
	return mapInsertError(err)
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

func (r *Repository) DeleteRouteTable(account, region, id string) error {
	var res sql.Result
	var err error
	if region == "" {
		res, err = r.db.Exec(`DELETE FROM ec2_route_tables WHERE account_id = ? AND id = ?`, account, id)
	} else {
		res, err = r.db.Exec(`DELETE FROM ec2_route_tables WHERE account_id = ? AND region = ? AND id = ?`, account, region, id)
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

// AssociateRouteTable links a route table to a subnet. Both must
// exist in the request's region (Codex pass 7 BLOCKING #1).
func (r *Repository) AssociateRouteTable(account, region string, assoc *EC2RouteTableAssociation) error {
	if _, err := r.GetRouteTable(account, region, assoc.RouteTableID); err != nil {
		return err
	}
	if _, err := r.GetSubnet(account, region, assoc.SubnetID); err != nil {
		return err
	}
	_, err := r.db.Exec(
		`INSERT INTO ec2_route_table_associations (account_id, id, route_table_id, subnet_id) VALUES (?, ?, ?, ?)`,
		account, assoc.ID, assoc.RouteTableID, assoc.SubnetID,
	)
	return mapInsertError(err)
}

func (r *Repository) DisassociateRouteTable(account, associationID string) error {
	res, err := r.db.Exec(
		`DELETE FROM ec2_route_table_associations WHERE account_id = ? AND id = ?`,
		account, associationID,
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

// CreateRoute inserts a route into the parent route table; the
// route table must live in the request's region (Codex pass 7
// BLOCKING #1).
func (r *Repository) CreateRoute(account, region string, rt *EC2Route) error {
	if _, err := r.GetRouteTable(account, region, rt.RouteTableID); err != nil {
		return err
	}
	_, err := r.db.Exec(
		`INSERT INTO ec2_routes (account_id, route_table_id, destination_cidr_block, gateway_id, nat_gateway_id, instance_id, network_interface_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, rt.RouteTableID, rt.DestinationCidrBlock,
		nullIfEmpty(rt.GatewayID), nullIfEmpty(rt.NatGatewayID),
		nullIfEmpty(rt.InstanceID), nullIfEmpty(rt.NetworkInterfaceID),
	)
	return mapInsertError(err)
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

// GetSecurityGroupRules reads the ingress/egress JSON for an SG,
// optionally scoped to a region (Codex pass 7 BLOCKING #1).
func (r *Repository) GetSecurityGroupRules(account, region, id string) (ingress, egress []byte, err error) {
	var row *sql.Row
	if region == "" {
		row = r.db.QueryRow(
			`SELECT ingress, egress FROM ec2_security_groups WHERE account_id = ? AND id = ?`,
			account, id,
		)
	} else {
		row = r.db.QueryRow(
			`SELECT ingress, egress FROM ec2_security_groups WHERE account_id = ? AND region = ? AND id = ?`,
			account, region, id,
		)
	}
	var ingS, egS string
	if err := row.Scan(&ingS, &egS); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, models.ErrNotFound
		}
		return nil, nil, err
	}
	return []byte(ingS), []byte(egS), nil
}

func (r *Repository) UpdateSecurityGroupRules(account, region, id, direction string, rulesJSON []byte) error {
	if _, err := r.GetSecurityGroup(account, region, id); err != nil {
		return err
	}
	col := "ingress"
	if direction == "egress" {
		col = "egress"
	}
	_, err := r.db.Exec(
		fmt.Sprintf(`UPDATE ec2_security_groups SET %s = ? WHERE account_id = ? AND id = ?`, col),
		string(rulesJSON), account, id,
	)
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
	body, _ := json.Marshal(eip)
	if _, err := tx.Exec(
		`INSERT INTO ec2_eips (account_id, region, allocation_id, domain, public_ip, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, eip.Region, eip.AllocationID, eip.Domain, eip.PublicIP, string(body), eip.CreatedAt,
	); err != nil {
		return mapInsertError(err)
	}
	return tx.Commit()
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
		eip.NetworkInterfaceID, eip.InstanceID, eip.AssociationID, string(body), account, eip.AllocationID,
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
	rows, err := r.db.Query(
		`SELECT route_table_id, destination_cidr_block, gateway_id, nat_gateway_id, instance_id, network_interface_id
		   FROM ec2_routes WHERE account_id = ?
		   ORDER BY route_table_id, destination_cidr_block`,
		account,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2Route
	for rows.Next() {
		var rt EC2Route
		var gw, nat, inst, eni sql.NullString
		if err := rows.Scan(&rt.RouteTableID, &rt.DestinationCidrBlock, &gw, &nat, &inst, &eni); err != nil {
			return nil, err
		}
		rt.GatewayID = gw.String
		rt.NatGatewayID = nat.String
		rt.InstanceID = inst.String
		rt.NetworkInterfaceID = eni.String
		out = append(out, &rt)
	}
	return out, rows.Err()
}

// ListRouteTableAssociations returns every route-table association for
// the account. Used by /mock/state (Codex pass 10 BLOCKING #2 fix).
func (r *Repository) ListRouteTableAssociations(account string) ([]*EC2RouteTableAssociation, error) {
	rows, err := r.db.Query(
		`SELECT id, route_table_id, subnet_id FROM ec2_route_table_associations
		   WHERE account_id = ? ORDER BY id`,
		account,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2RouteTableAssociation
	for rows.Next() {
		var a EC2RouteTableAssociation
		if err := rows.Scan(&a.ID, &a.RouteTableID, &a.SubnetID); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
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
// the same region and zone name. fakeaws-loader is its caller.
func (r *Repository) PutAvailabilityZone(account string, z AvailabilityZone) error {
	_, err := r.db.Exec(`INSERT OR REPLACE INTO availability_zones
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
