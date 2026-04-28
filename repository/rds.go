// Package repository — RDS tables and CRUD.
//
// Per fakeaws/PLAN.md § "Phase 3 — Stateful data (S45)" — the FK chain:
//
//   rds_db_instances ──┬──► rds_db_subnet_groups ──► ec2_subnets (handler-validated)
//                      ├──► rds_db_clusters
//                      ├──► rds_db_parameter_groups
//                      └──► rds_db_instances (replicate_source_db; RESTRICT on source-with-replicas)
//   rds_db_clusters ──┬──► rds_db_subnet_groups
//                     └──► rds_db_cluster_parameter_groups
//
// The subnet-group ↔ ec2_subnets link is enforced at the handler
// layer (rds.go::CreateDBSubnetGroup) rather than via SQLite FK,
// because SQLite can't FK into a JSON column. The handler walks
// the subnet_ids list, validates each via ec2_subnets, AND asserts
// they share the same VPC (S45-T0 pitfall: "subnets must be in
// the same VPC").
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
)

var rdsMigrations = []string{
	`CREATE TABLE IF NOT EXISTS rds_db_subnet_groups (
		account_id   TEXT NOT NULL,
		region       TEXT NOT NULL,
		name         TEXT NOT NULL,
		description  TEXT NOT NULL DEFAULT '',
		vpc_id       TEXT NOT NULL,
		subnet_ids   TEXT NOT NULL DEFAULT '[]',
		arn          TEXT NOT NULL,
		data         TEXT NOT NULL,
		created_at   TEXT NOT NULL,
		PRIMARY KEY (account_id, name)
	)`,
	`CREATE TABLE IF NOT EXISTS rds_db_parameter_groups (
		account_id  TEXT NOT NULL,
		region      TEXT NOT NULL,
		name        TEXT NOT NULL,
		family      TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		arn         TEXT NOT NULL,
		data        TEXT NOT NULL,
		created_at  TEXT NOT NULL,
		PRIMARY KEY (account_id, name)
	)`,
	`CREATE TABLE IF NOT EXISTS rds_db_cluster_parameter_groups (
		account_id  TEXT NOT NULL,
		region      TEXT NOT NULL,
		name        TEXT NOT NULL,
		family      TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		arn         TEXT NOT NULL,
		data        TEXT NOT NULL,
		created_at  TEXT NOT NULL,
		PRIMARY KEY (account_id, name)
	)`,
	`CREATE TABLE IF NOT EXISTS rds_db_clusters (
		account_id                       TEXT NOT NULL,
		region                           TEXT NOT NULL,
		id                               TEXT NOT NULL,
		engine                           TEXT NOT NULL,
		engine_version                   TEXT NOT NULL DEFAULT '',
		subnet_group_name                TEXT,
		cluster_parameter_group_name     TEXT,
		master_username                  TEXT NOT NULL DEFAULT '',
		deletion_protection              INTEGER NOT NULL DEFAULT 0,
		state                            TEXT NOT NULL DEFAULT 'available',
		arn                              TEXT NOT NULL,
		data                             TEXT NOT NULL,
		created_at                       TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, subnet_group_name) REFERENCES rds_db_subnet_groups(account_id, name) ON DELETE RESTRICT,
		FOREIGN KEY (account_id, cluster_parameter_group_name) REFERENCES rds_db_cluster_parameter_groups(account_id, name) ON DELETE RESTRICT
	)`,
	`CREATE TABLE IF NOT EXISTS rds_db_instances (
		account_id              TEXT NOT NULL,
		region                  TEXT NOT NULL,
		id                      TEXT NOT NULL,
		engine                  TEXT NOT NULL,
		engine_version          TEXT NOT NULL DEFAULT '',
		instance_class          TEXT NOT NULL,
		subnet_group_name       TEXT,
		cluster_id              TEXT,
		parameter_group_name    TEXT,
		replicate_source_db     TEXT,
		deletion_protection     INTEGER NOT NULL DEFAULT 0,
		skip_final_snapshot     INTEGER NOT NULL DEFAULT 1,
		state                   TEXT NOT NULL DEFAULT 'available',
		arn                     TEXT NOT NULL,
		data                    TEXT NOT NULL,
		created_at              TEXT NOT NULL,
		PRIMARY KEY (account_id, id),
		FOREIGN KEY (account_id, subnet_group_name)    REFERENCES rds_db_subnet_groups(account_id, name)    ON DELETE RESTRICT,
		FOREIGN KEY (account_id, cluster_id)           REFERENCES rds_db_clusters(account_id, id)           ON DELETE RESTRICT,
		FOREIGN KEY (account_id, parameter_group_name) REFERENCES rds_db_parameter_groups(account_id, name) ON DELETE RESTRICT,
		FOREIGN KEY (account_id, replicate_source_db)  REFERENCES rds_db_instances(account_id, id)          ON DELETE RESTRICT
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, rdsMigrations...)
	prependResetTables([]string{
		// instances first (FK on cluster + replicate_source_db),
		// clusters next (FK on subnet group + cluster param group),
		// then the parent groups.
		"rds_db_instances",
		"rds_db_clusters",
		"rds_db_subnet_groups",
		"rds_db_parameter_groups",
		"rds_db_cluster_parameter_groups",
	})
}

// ----- Typed wire shapes -----

type RDSSubnetGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	VPCID       string   `json:"vpc_id"`
	SubnetIDs   []string `json:"subnet_ids"`
	Region      string   `json:"region"`
	ARN         string   `json:"arn"`
	CreatedAt   string   `json:"created_at"`
}

type RDSParameterGroup struct {
	Name        string `json:"name"`
	Family      string `json:"family"`
	Description string `json:"description"`
	Region      string `json:"region"`
	ARN         string `json:"arn"`
	CreatedAt   string `json:"created_at"`
}

type RDSClusterParameterGroup = RDSParameterGroup

type RDSCluster struct {
	ID                        string `json:"id"`
	Engine                    string `json:"engine"`
	EngineVersion             string `json:"engine_version"`
	SubnetGroupName           string `json:"subnet_group_name,omitempty"`
	ClusterParameterGroupName string `json:"cluster_parameter_group_name,omitempty"`
	MasterUsername            string `json:"master_username"`
	DeletionProtection        bool   `json:"deletion_protection"`
	State                     string `json:"state"`
	Region                    string `json:"region"`
	ARN                       string `json:"arn"`
	CreatedAt                 string `json:"created_at"`
}

type RDSInstance struct {
	ID                  string `json:"id"`
	Engine              string `json:"engine"`
	EngineVersion       string `json:"engine_version"`
	InstanceClass       string `json:"instance_class"`
	SubnetGroupName     string `json:"subnet_group_name,omitempty"`
	ClusterID           string `json:"cluster_id,omitempty"`
	ParameterGroupName  string `json:"parameter_group_name,omitempty"`
	ReplicateSourceDB   string `json:"replicate_source_db,omitempty"`
	DeletionProtection  bool   `json:"deletion_protection"`
	SkipFinalSnapshot   bool   `json:"skip_final_snapshot"`
	State               string `json:"state"`
	Region              string `json:"region"`
	ARN                 string `json:"arn"`
	CreatedAt           string `json:"created_at"`
}

// ----- DB Subnet Group -----

func (r *Repository) CreateDBSubnetGroup(account string, sg *RDSSubnetGroup) error {
	// Validate every subnet exists and belongs to the same VPC
	// (S45-T0 pitfall: "subnets must be in the same VPC"). Caller
	// passes the vpc_id derived from the first subnet; we re-check
	// the rest match.
	if len(sg.SubnetIDs) == 0 {
		return fmt.Errorf("subnet_ids empty: %w", models.ErrConflict)
	}
	for _, sid := range sg.SubnetIDs {
		s, err := r.GetSubnet(account, sid)
		if err != nil {
			return err
		}
		if sg.VPCID == "" {
			sg.VPCID = s.VPCID
		} else if s.VPCID != sg.VPCID {
			return fmt.Errorf("subnet %q is in vpc %q but subnet group expects %q: %w",
				sid, s.VPCID, sg.VPCID, models.ErrConflict)
		}
	}
	body, _ := json.Marshal(sg)
	subnetIDsJSON, _ := json.Marshal(sg.SubnetIDs)
	_, err := r.db.Exec(
		`INSERT INTO rds_db_subnet_groups (account_id, region, name, description, vpc_id, subnet_ids, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, sg.Region, sg.Name, sg.Description, sg.VPCID, string(subnetIDsJSON), sg.ARN, string(body), sg.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetDBSubnetGroup(account, name string) (*RDSSubnetGroup, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM rds_db_subnet_groups WHERE account_id = ? AND name = ?`, account, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var sg RDSSubnetGroup
	if err := json.Unmarshal([]byte(data), &sg); err != nil {
		return nil, err
	}
	return &sg, nil
}

func (r *Repository) DeleteDBSubnetGroup(account, name string) error {
	res, err := r.db.Exec(`DELETE FROM rds_db_subnet_groups WHERE account_id = ? AND name = ?`, account, name)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ListDBSubnetGroups returns every DB subnet group for the account.
// Codex pass 4 BLOCKING #2 fix.
func (r *Repository) ListDBSubnetGroups(account string) ([]*RDSSubnetGroup, error) {
	rows, err := r.db.Query(`SELECT data FROM rds_db_subnet_groups WHERE account_id = ? ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RDSSubnetGroup
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var sg RDSSubnetGroup
		if err := json.Unmarshal([]byte(data), &sg); err != nil {
			return nil, err
		}
		out = append(out, &sg)
	}
	return out, rows.Err()
}

// ListDBParameterGroups returns every instance parameter group.
func (r *Repository) ListDBParameterGroups(account string) ([]*RDSParameterGroup, error) {
	rows, err := r.db.Query(`SELECT data FROM rds_db_parameter_groups WHERE account_id = ? ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RDSParameterGroup
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var pg RDSParameterGroup
		if err := json.Unmarshal([]byte(data), &pg); err != nil {
			return nil, err
		}
		out = append(out, &pg)
	}
	return out, rows.Err()
}

// ListDBClusterParameterGroups returns every cluster parameter group.
func (r *Repository) ListDBClusterParameterGroups(account string) ([]*RDSClusterParameterGroup, error) {
	rows, err := r.db.Query(`SELECT data FROM rds_db_cluster_parameter_groups WHERE account_id = ? ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RDSClusterParameterGroup
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var pg RDSClusterParameterGroup
		if err := json.Unmarshal([]byte(data), &pg); err != nil {
			return nil, err
		}
		out = append(out, &pg)
	}
	return out, rows.Err()
}

// ListDBClusters returns every DB cluster for the account.
func (r *Repository) ListDBClusters(account, region string) ([]*RDSCluster, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM rds_db_clusters WHERE account_id = ? ORDER BY id`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM rds_db_clusters WHERE account_id = ? AND region = ? ORDER BY id`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RDSCluster
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c RDSCluster
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// ----- DB Parameter Group + Cluster Parameter Group -----

func (r *Repository) CreateDBParameterGroup(account string, pg *RDSParameterGroup) error {
	body, _ := json.Marshal(pg)
	_, err := r.db.Exec(
		`INSERT INTO rds_db_parameter_groups (account_id, region, name, family, description, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		account, pg.Region, pg.Name, pg.Family, pg.Description, pg.ARN, string(body), pg.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetDBParameterGroup(account, name string) (*RDSParameterGroup, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM rds_db_parameter_groups WHERE account_id = ? AND name = ?`, account, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var pg RDSParameterGroup
	if err := json.Unmarshal([]byte(data), &pg); err != nil {
		return nil, err
	}
	return &pg, nil
}

func (r *Repository) DeleteDBParameterGroup(account, name string) error {
	res, err := r.db.Exec(`DELETE FROM rds_db_parameter_groups WHERE account_id = ? AND name = ?`, account, name)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

func (r *Repository) CreateDBClusterParameterGroup(account string, pg *RDSClusterParameterGroup) error {
	body, _ := json.Marshal(pg)
	_, err := r.db.Exec(
		`INSERT INTO rds_db_cluster_parameter_groups (account_id, region, name, family, description, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		account, pg.Region, pg.Name, pg.Family, pg.Description, pg.ARN, string(body), pg.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetDBClusterParameterGroup(account, name string) (*RDSClusterParameterGroup, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM rds_db_cluster_parameter_groups WHERE account_id = ? AND name = ?`, account, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var pg RDSClusterParameterGroup
	if err := json.Unmarshal([]byte(data), &pg); err != nil {
		return nil, err
	}
	return &pg, nil
}

func (r *Repository) DeleteDBClusterParameterGroup(account, name string) error {
	res, err := r.db.Exec(`DELETE FROM rds_db_cluster_parameter_groups WHERE account_id = ? AND name = ?`, account, name)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- DB Cluster -----

func (r *Repository) CreateDBCluster(account string, c *RDSCluster) error {
	if c.SubnetGroupName != "" {
		if _, err := r.GetDBSubnetGroup(account, c.SubnetGroupName); err != nil {
			return err
		}
	}
	if c.ClusterParameterGroupName != "" {
		if _, err := r.GetDBClusterParameterGroup(account, c.ClusterParameterGroupName); err != nil {
			return err
		}
	}
	if c.State == "" {
		c.State = "available"
	}
	body, _ := json.Marshal(c)
	_, err := r.db.Exec(
		`INSERT INTO rds_db_clusters (account_id, region, id, engine, engine_version, subnet_group_name, cluster_parameter_group_name, master_username, deletion_protection, state, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, c.Region, c.ID, c.Engine, c.EngineVersion,
		nullIfEmpty(c.SubnetGroupName), nullIfEmpty(c.ClusterParameterGroupName),
		c.MasterUsername, boolToInt(c.DeletionProtection),
		c.State, c.ARN, string(body), c.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetDBCluster(account, id string) (*RDSCluster, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM rds_db_clusters WHERE account_id = ? AND id = ?`, account, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var c RDSCluster
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *Repository) DeleteDBCluster(account, id string) error {
	c, err := r.GetDBCluster(account, id)
	if err != nil {
		return err
	}
	if c.DeletionProtection {
		// concepts.md "Standing patterns" item 9 — terminal-state /
		// protected-resource refusal.
		return fmt.Errorf("cluster %q has deletion_protection enabled: %w", id, models.ErrConflict)
	}
	res, err := r.db.Exec(`DELETE FROM rds_db_clusters WHERE account_id = ? AND id = ?`, account, id)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- DB Instance -----

func (r *Repository) CreateDBInstance(account string, inst *RDSInstance) error {
	if inst.SubnetGroupName != "" {
		if _, err := r.GetDBSubnetGroup(account, inst.SubnetGroupName); err != nil {
			return err
		}
	}
	if inst.ClusterID != "" {
		if _, err := r.GetDBCluster(account, inst.ClusterID); err != nil {
			return err
		}
	}
	if inst.ParameterGroupName != "" {
		if _, err := r.GetDBParameterGroup(account, inst.ParameterGroupName); err != nil {
			return err
		}
	}
	if inst.ReplicateSourceDB != "" {
		if _, err := r.GetDBInstance(account, inst.ReplicateSourceDB); err != nil {
			return err
		}
	}
	if inst.State == "" {
		inst.State = "available"
	}
	body, _ := json.Marshal(inst)
	_, err := r.db.Exec(
		`INSERT INTO rds_db_instances (account_id, region, id, engine, engine_version, instance_class, subnet_group_name, cluster_id, parameter_group_name, replicate_source_db, deletion_protection, skip_final_snapshot, state, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, inst.Region, inst.ID, inst.Engine, inst.EngineVersion, inst.InstanceClass,
		nullIfEmpty(inst.SubnetGroupName), nullIfEmpty(inst.ClusterID),
		nullIfEmpty(inst.ParameterGroupName), nullIfEmpty(inst.ReplicateSourceDB),
		boolToInt(inst.DeletionProtection), boolToInt(inst.SkipFinalSnapshot),
		inst.State, inst.ARN, string(body), inst.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetDBInstance(account, id string) (*RDSInstance, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM rds_db_instances WHERE account_id = ? AND id = ?`, account, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var inst RDSInstance
	if err := json.Unmarshal([]byte(data), &inst); err != nil {
		return nil, err
	}
	return &inst, nil
}

// ListDBInstances returns all RDS instances for the account, optionally
// filtered by region (empty string = all regions).
func (r *Repository) ListDBInstances(account, region string) ([]*RDSInstance, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM rds_db_instances WHERE account_id = ? ORDER BY id`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM rds_db_instances WHERE account_id = ? AND region = ? ORDER BY id`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RDSInstance
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var inst RDSInstance
		if err := json.Unmarshal([]byte(data), &inst); err != nil {
			return nil, err
		}
		out = append(out, &inst)
	}
	return out, rows.Err()
}

func (r *Repository) DeleteDBInstance(account, id string) error {
	inst, err := r.GetDBInstance(account, id)
	if err != nil {
		return err
	}
	if inst.DeletionProtection {
		return fmt.Errorf("instance %q has deletion_protection enabled: %w", id, models.ErrConflict)
	}
	// Source-with-replicas RESTRICT — if any other instance has
	// replicate_source_db pointing at us, refuse the delete (S45-T0
	// pitfall: "deleting source while replicas exist fails").
	var n int
	if err := r.db.QueryRow(
		`SELECT COUNT(*) FROM rds_db_instances WHERE account_id = ? AND replicate_source_db = ?`,
		account, id,
	).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("instance %q has %d replica(s); promote or delete them first: %w",
			id, n, models.ErrConflict)
	}
	res, err := r.db.Exec(`DELETE FROM rds_db_instances WHERE account_id = ? AND id = ?`, account, id)
	if err != nil {
		return mapDeleteError(err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- helpers -----

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
