// Package repository — EKS cluster + node group + addon tables.
//
// Per fakeaws/PLAN.md § "Phase 4 — Containers + queues (S46)" — the
// load-bearing FK chain:
//
//   eks_clusters ──► eks_node_groups (CASCADE)
//                ──► eks_addons      (CASCADE)
//                ──► role_arn (cross-service IAM check)
//                ──► subnet_ids (cross-service EC2 check)
//
// node_groups also carry a node_role_arn (different IAM role from
// cluster role per S46-T0 pitfall — cluster trust principal is
// eks.amazonaws.com, nodegroup trust is ec2.amazonaws.com) and a
// subnet_ids list that MUST be a subset of the parent cluster's
// subnet_ids — enforced at handler create time.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
)

var eksMigrations = []string{
	`CREATE TABLE IF NOT EXISTS eks_clusters (
		account_id        TEXT NOT NULL,
		region            TEXT NOT NULL,
		name              TEXT NOT NULL,
		role_arn          TEXT NOT NULL,
		subnet_ids        TEXT NOT NULL DEFAULT '[]',
		security_group_ids TEXT NOT NULL DEFAULT '[]',
		kubernetes_version TEXT NOT NULL DEFAULT '',
		status            TEXT NOT NULL DEFAULT 'ACTIVE',
		arn               TEXT NOT NULL,
		data              TEXT NOT NULL,
		created_at        TEXT NOT NULL,
		PRIMARY KEY (account_id, name)
	)`,
	`CREATE TABLE IF NOT EXISTS eks_node_groups (
		account_id     TEXT NOT NULL,
		region         TEXT NOT NULL,
		cluster_name   TEXT NOT NULL,
		name           TEXT NOT NULL,
		node_role_arn  TEXT NOT NULL,
		subnet_ids     TEXT NOT NULL DEFAULT '[]',
		instance_types TEXT NOT NULL DEFAULT '[]',
		scaling_config TEXT NOT NULL DEFAULT '{}',
		status         TEXT NOT NULL DEFAULT 'ACTIVE',
		arn            TEXT NOT NULL,
		data           TEXT NOT NULL,
		created_at     TEXT NOT NULL,
		PRIMARY KEY (account_id, cluster_name, name),
		FOREIGN KEY (account_id, cluster_name) REFERENCES eks_clusters(account_id, name) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS eks_addons (
		account_id    TEXT NOT NULL,
		region        TEXT NOT NULL,
		cluster_name  TEXT NOT NULL,
		name          TEXT NOT NULL,
		version       TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL DEFAULT 'ACTIVE',
		arn           TEXT NOT NULL,
		data          TEXT NOT NULL,
		created_at    TEXT NOT NULL,
		PRIMARY KEY (account_id, cluster_name, name),
		FOREIGN KEY (account_id, cluster_name) REFERENCES eks_clusters(account_id, name) ON DELETE CASCADE
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, eksMigrations...)
	prependResetTables([]string{
		"eks_addons",
		"eks_node_groups",
		"eks_clusters",
	})
}

// ----- Typed wire shapes -----

type EKSCluster struct {
	Name              string   `json:"name"`
	RoleARN           string   `json:"role_arn"`
	SubnetIDs         []string `json:"subnet_ids"`
	SecurityGroupIDs  []string `json:"security_group_ids,omitempty"`
	KubernetesVersion string   `json:"kubernetes_version,omitempty"`
	Status            string   `json:"status"`
	Region            string   `json:"region"`
	ARN               string   `json:"arn"`
	CreatedAt         string   `json:"created_at"`
}

type EKSNodeGroup struct {
	ClusterName   string   `json:"cluster_name"`
	Name          string   `json:"name"`
	NodeRoleARN   string   `json:"node_role_arn"`
	SubnetIDs     []string `json:"subnet_ids"`
	InstanceTypes []string `json:"instance_types,omitempty"`
	ScalingConfig string   `json:"scaling_config,omitempty"` // raw JSON
	Status        string   `json:"status"`
	Region        string   `json:"region"`
	ARN           string   `json:"arn"`
	CreatedAt     string   `json:"created_at"`
}

type EKSAddon struct {
	ClusterName string `json:"cluster_name"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Status      string `json:"status"`
	Region      string `json:"region"`
	ARN         string `json:"arn"`
	CreatedAt   string `json:"created_at"`
}

// ----- Cluster -----

func (r *Repository) CreateEKSCluster(account string, c *EKSCluster) error {
	// Cross-service: role_arn must reference an IAM role this account owns.
	// The ARN format is arn:aws:iam::<account>:role/<name>; we extract
	// the trailing name and resolve via IAM. Cross-account refs are
	// rejected (fakegcp pass-27 pattern).
	roleName := iamRoleNameFromARN(account, c.RoleARN)
	if roleName == "" {
		return fmt.Errorf("invalid role_arn %q: %w", c.RoleARN, models.ErrNotFound)
	}
	if _, err := r.GetRole(account, roleName); err != nil {
		return err
	}
	// Each subnet must exist AND share the same VPC as the rest of
	// the cluster (Codex pass 1 BLOCKING #1 — single-VPC contract).
	// The cluster VPC is derived from the first subnet; subsequent
	// subnets must match. Cross-VPC subnets reject with ErrConflict.
	if len(c.SubnetIDs) == 0 {
		return fmt.Errorf("subnet_ids empty: %w", models.ErrConflict)
	}
	var clusterVPC string
	for _, sid := range c.SubnetIDs {
		s, err := r.GetSubnet(account, sid)
		if err != nil {
			return err
		}
		if clusterVPC == "" {
			clusterVPC = s.VPCID
		} else if s.VPCID != clusterVPC {
			return fmt.Errorf("subnet %q is in vpc %q but cluster expects %q: %w",
				sid, s.VPCID, clusterVPC, models.ErrConflict)
		}
	}
	// Each SG (if specified) must exist AND belong to the cluster VPC.
	for _, sgid := range c.SecurityGroupIDs {
		sg, err := r.GetSecurityGroup(account, sgid)
		if err != nil {
			return err
		}
		if sg.VPCID != clusterVPC {
			return fmt.Errorf("security group %q is in vpc %q but cluster expects %q: %w",
				sgid, sg.VPCID, clusterVPC, models.ErrConflict)
		}
	}
	if c.Status == "" {
		c.Status = "ACTIVE"
	}
	body, _ := json.Marshal(c)
	subnetJSON, _ := json.Marshal(c.SubnetIDs)
	sgJSON, _ := json.Marshal(c.SecurityGroupIDs)
	_, err := r.db.Exec(
		`INSERT INTO eks_clusters (account_id, region, name, role_arn, subnet_ids, security_group_ids, kubernetes_version, status, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, c.Region, c.Name, c.RoleARN, string(subnetJSON), string(sgJSON),
		c.KubernetesVersion, c.Status, c.ARN, string(body), c.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetEKSCluster(account, name string) (*EKSCluster, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM eks_clusters WHERE account_id = ? AND name = ?`, account, name).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var c EKSCluster
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *Repository) ListEKSClusters(account, region string) ([]*EKSCluster, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM eks_clusters WHERE account_id = ? ORDER BY name`, account)
	} else {
		rows, err = r.db.Query(`SELECT data FROM eks_clusters WHERE account_id = ? AND region = ? ORDER BY name`, account, region)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EKSCluster
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c EKSCluster
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (r *Repository) DeleteEKSCluster(account, name string) error {
	res, err := r.db.Exec(`DELETE FROM eks_clusters WHERE account_id = ? AND name = ?`, account, name)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- NodeGroup -----

func (r *Repository) CreateEKSNodeGroup(account string, ng *EKSNodeGroup) error {
	cluster, err := r.GetEKSCluster(account, ng.ClusterName)
	if err != nil {
		return err
	}
	roleName := iamRoleNameFromARN(account, ng.NodeRoleARN)
	if roleName == "" {
		return fmt.Errorf("invalid node_role_arn %q: %w", ng.NodeRoleARN, models.ErrNotFound)
	}
	if _, err := r.GetRole(account, roleName); err != nil {
		return err
	}
	// Subnets MUST be a subset of the parent cluster's subnets
	// (S46-T0 pitfall: "subnet does not belong to cluster VPC").
	clusterSubnets := map[string]bool{}
	for _, sid := range cluster.SubnetIDs {
		clusterSubnets[sid] = true
	}
	for _, sid := range ng.SubnetIDs {
		if !clusterSubnets[sid] {
			return fmt.Errorf("nodegroup subnet %q is not in cluster's subnet_ids: %w", sid, models.ErrConflict)
		}
	}
	if ng.Status == "" {
		ng.Status = "ACTIVE"
	}
	body, _ := json.Marshal(ng)
	subnetJSON, _ := json.Marshal(ng.SubnetIDs)
	itypesJSON, _ := json.Marshal(ng.InstanceTypes)
	scaling := ng.ScalingConfig
	if scaling == "" {
		scaling = "{}"
	}
	_, err = r.db.Exec(
		`INSERT INTO eks_node_groups (account_id, region, cluster_name, name, node_role_arn, subnet_ids, instance_types, scaling_config, status, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, ng.Region, ng.ClusterName, ng.Name, ng.NodeRoleARN,
		string(subnetJSON), string(itypesJSON), scaling, ng.Status, ng.ARN, string(body), ng.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetEKSNodeGroup(account, clusterName, name string) (*EKSNodeGroup, error) {
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM eks_node_groups WHERE account_id = ? AND cluster_name = ? AND name = ?`,
		account, clusterName, name,
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var ng EKSNodeGroup
	if err := json.Unmarshal([]byte(data), &ng); err != nil {
		return nil, err
	}
	return &ng, nil
}

func (r *Repository) DeleteEKSNodeGroup(account, clusterName, name string) error {
	res, err := r.db.Exec(
		`DELETE FROM eks_node_groups WHERE account_id = ? AND cluster_name = ? AND name = ?`,
		account, clusterName, name,
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

// ----- Addon -----

func (r *Repository) CreateEKSAddon(account string, a *EKSAddon) error {
	if _, err := r.GetEKSCluster(account, a.ClusterName); err != nil {
		return err
	}
	if a.Status == "" {
		a.Status = "ACTIVE"
	}
	body, _ := json.Marshal(a)
	_, err := r.db.Exec(
		`INSERT INTO eks_addons (account_id, region, cluster_name, name, version, status, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, a.Region, a.ClusterName, a.Name, a.Version, a.Status, a.ARN, string(body), a.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetEKSAddon(account, clusterName, name string) (*EKSAddon, error) {
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM eks_addons WHERE account_id = ? AND cluster_name = ? AND name = ?`,
		account, clusterName, name,
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var a EKSAddon
	if err := json.Unmarshal([]byte(data), &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *Repository) DeleteEKSAddon(account, clusterName, name string) error {
	res, err := r.db.Exec(
		`DELETE FROM eks_addons WHERE account_id = ? AND cluster_name = ? AND name = ?`,
		account, clusterName, name,
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

// ----- helpers -----

// iamRoleNameFromARN extracts the role name from an ARN of the
// shape `arn:aws:iam::<account>:role/<name>`. Returns "" if the
// account doesn't match the caller (cross-account ref) or the
// shape is wrong.
func iamRoleNameFromARN(account, arn string) string {
	const prefix = "arn:aws:iam::"
	if len(arn) < len(prefix) || arn[:len(prefix)] != prefix {
		return ""
	}
	rest := arn[len(prefix):]
	// rest is "<account>:role/<name>"
	colon := -1
	for i, c := range rest {
		if c == ':' {
			colon = i
			break
		}
	}
	if colon == -1 {
		return ""
	}
	if rest[:colon] != account {
		return ""
	}
	tail := rest[colon+1:]
	const roleSep = "role/"
	if len(tail) < len(roleSep) || tail[:len(roleSep)] != roleSep {
		return ""
	}
	return tail[len(roleSep):]
}
