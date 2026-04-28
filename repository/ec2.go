// Package repository — EC2 networking tables and CRUD.
//
// Per fakeaws/PLAN.md § "Phase 2 — Networking + compute (S44)" — the
// FK chain that gates correctness:
//
//                    ec2_vpcs
//                       │
//        ┌──────────────┼─────────────┐
//        │              │             │
//   ec2_subnets  ec2_route_tables  ec2_security_groups
//        │              │
//   ec2_instances  ec2_routes
//
// This file ships networking only: VPCs, Subnets, InternetGateways,
// RouteTables, RouteTableAssociations, Routes, SecurityGroups, EIPs.
// Compute (instances, key pairs, AMI fixtures) lands in S44-T6 in
// repository/ec2_compute.go.
//
// Server-stamped IDs follow AWS convention:
//   vpc-, subnet-, sg-, rtb-, igw-, rtbassoc-, eipalloc-, eni-
// Each handler synthesises an id at create time; the repo never
// honours an id smuggled in from the client (per concepts.md
// "Standing patterns" item 14 — server-stamped fields never trusted).
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

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
	Region             string `json:"region"`
	CreatedAt          string `json:"created_at"`
}

// ----- VPC -----

func (r *Repository) CreateVPC(account string, v *EC2VPC) error {
	body, _ := json.Marshal(v)
	_, err := r.db.Exec(
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

func (r *Repository) CreateSubnet(account string, s *EC2Subnet) error {
	// Codex pass 7 BLOCKING #1 — parent must be in the SAME region as
	// the child, not just same account. Cross-region refs reject with
	// ErrNotFound from GetVPC.
	if _, err := r.GetVPC(account, s.Region, s.VPCID); err != nil {
		return err
	}
	body, _ := json.Marshal(s)
	_, err := r.db.Exec(
		`INSERT INTO ec2_subnets (account_id, region, id, vpc_id, cidr_block, availability_zone, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, s.Region, s.ID, s.VPCID, s.CidrBlock, s.AvailabilityZone, s.ARN, string(body), s.CreatedAt,
	)
	return mapInsertError(err)
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

func (r *Repository) ListSubnets(account, vpcID string) ([]*EC2Subnet, error) {
	var rows *sql.Rows
	var err error
	if vpcID == "" {
		rows, err = r.db.Query(`SELECT data FROM ec2_subnets WHERE account_id = ? ORDER BY id`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM ec2_subnets WHERE account_id = ? AND vpc_id = ? ORDER BY id`, account, vpcID)
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

func (r *Repository) ListInternetGateways(account string) ([]*EC2InternetGateway, error) {
	rows, err := r.db.Query(
		`SELECT id FROM ec2_internet_gateways WHERE account_id = ? ORDER BY id`,
		account,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := make([]*EC2InternetGateway, 0, len(ids))
	for _, id := range ids {
		// Account-wide list — pass empty region so the lookup spans
		// every region.
		igw, err := r.GetInternetGateway(account, "", id)
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
	body, _ := json.Marshal(sg)
	_, err := r.db.Exec(
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

func (r *Repository) CreateEIP(account string, eip *EC2EIP) error {
	body, _ := json.Marshal(eip)
	_, err := r.db.Exec(
		`INSERT INTO ec2_eips (account_id, region, allocation_id, domain, public_ip, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account, eip.Region, eip.AllocationID, eip.Domain, eip.PublicIP, string(body), eip.CreatedAt,
	)
	return mapInsertError(err)
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

func (r *Repository) DeleteEIP(account, region, allocationID string) error {
	var res sql.Result
	var err error
	if region == "" {
		res, err = r.db.Exec(`DELETE FROM ec2_eips WHERE account_id = ? AND allocation_id = ?`, account, allocationID)
	} else {
		res, err = r.db.Exec(`DELETE FROM ec2_eips WHERE account_id = ? AND region = ? AND allocation_id = ?`, account, region, allocationID)
	}
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- helpers -----

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
