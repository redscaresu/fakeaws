package repository

import (
	"errors"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

// setupEKSPrereqs seeds an IAM role + 2 subnets that EKS tests use
// as the cross-service references.
func setupEKSPrereqs(t *testing.T, r *Repository) (clusterRoleARN, nodeRoleARN string, subnetIDs []string) {
	t.Helper()
	cr := &IAMRole{Name: "eks-cluster-role", Path: "/", ARN: "arn:aws:iam::000000000000:role/eks-cluster-role", AssumeRolePolicyDocument: "{}", CreatedAt: "t"}
	r.CreateRole(testAccount, cr)
	nr := &IAMRole{Name: "eks-node-role", Path: "/", ARN: "arn:aws:iam::000000000000:role/eks-node-role", AssumeRolePolicyDocument: "{}", CreatedAt: "t"}
	r.CreateRole(testAccount, nr)
	_, subnets := setupVPCWith2Subnets(t, r)
	return cr.ARN, nr.ARN, subnets
}

func TestEKSCluster_CrossServiceRoleARN(t *testing.T) {
	r := setupRepo(t)
	clusterRole, _, subnets := setupEKSPrereqs(t, r)

	// Cluster with valid role + subnets succeeds.
	c := &EKSCluster{
		Name: "demo", RoleARN: clusterRole, SubnetIDs: subnets,
		Region: testRegion, ARN: "arn:cluster", CreatedAt: "t",
	}
	if err := r.CreateEKSCluster(testAccount, c); err != nil {
		t.Fatalf("CreateEKSCluster: %v", err)
	}

	// Cross-account role ARN rejects.
	bad := &EKSCluster{
		Name: "x", RoleARN: "arn:aws:iam::999999999999:role/eks-cluster-role",
		SubnetIDs: subnets, Region: testRegion, ARN: "arn:cluster", CreatedAt: "t",
	}
	if err := r.CreateEKSCluster(testAccount, bad); err == nil {
		t.Errorf("cross-account role ARN: expected error, got nil")
	}

	// Missing role rejects.
	bad2 := &EKSCluster{
		Name: "y", RoleARN: "arn:aws:iam::000000000000:role/missing",
		SubnetIDs: subnets, Region: testRegion, ARN: "arn:cluster", CreatedAt: "t",
	}
	if err := r.CreateEKSCluster(testAccount, bad2); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("missing role: want ErrNotFound, got %v", err)
	}

	// Missing subnet rejects.
	bad3 := &EKSCluster{
		Name: "z", RoleARN: clusterRole, SubnetIDs: []string{"subnet-missing"},
		Region: testRegion, ARN: "arn:cluster", CreatedAt: "t",
	}
	if err := r.CreateEKSCluster(testAccount, bad3); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("missing subnet: want ErrNotFound, got %v", err)
	}
}

func TestEKSNodeGroup_SubnetMustBeInClusterVPC(t *testing.T) {
	r := setupRepo(t)
	clusterRole, nodeRole, subnets := setupEKSPrereqs(t, r)
	r.CreateEKSCluster(testAccount, &EKSCluster{
		Name: "demo", RoleARN: clusterRole, SubnetIDs: subnets[:1], // only first subnet
		Region: testRegion, ARN: "arn:cluster", CreatedAt: "t",
	})

	// Nodegroup with subnet IN cluster's set succeeds.
	good := &EKSNodeGroup{
		ClusterName: "demo", Name: "ng-1", NodeRoleARN: nodeRole,
		SubnetIDs: subnets[:1], Region: testRegion, ARN: "arn:ng", CreatedAt: "t",
	}
	if err := r.CreateEKSNodeGroup(testAccount, good); err != nil {
		t.Fatalf("CreateEKSNodeGroup: %v", err)
	}

	// Nodegroup with subnet NOT in cluster's set rejects.
	bad := &EKSNodeGroup{
		ClusterName: "demo", Name: "ng-2", NodeRoleARN: nodeRole,
		SubnetIDs: []string{subnets[1]}, // second subnet, not in cluster
		Region: testRegion, ARN: "arn:ng", CreatedAt: "t",
	}
	if err := r.CreateEKSNodeGroup(testAccount, bad); !errors.Is(err, models.ErrConflict) {
		t.Errorf("nodegroup subnet outside cluster: want ErrConflict, got %v", err)
	}
}

// TestEKSCluster_SubnetsMustShareVPC pins the load-bearing single-VPC
// contract: cluster's subnet_ids must all be in the same VPC, and
// every security_group_id (if specified) must belong to that VPC.
// Codex pass 1 BLOCKING #1.
func TestEKSCluster_SubnetsMustShareVPC(t *testing.T) {
	r := setupRepo(t)
	clusterRole, _, subnets := setupEKSPrereqs(t, r)

	// Add a second VPC with its own subnet.
	r.CreateVPC(testAccount, &EC2VPC{ID: "vpc-other", CidrBlock: "10.1.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"})
	r.CreateSubnet(testAccount, &EC2Subnet{ID: "subnet-other", VPCID: "vpc-other", CidrBlock: "10.1.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"})

	// Mixing subnets from vpc-1 and vpc-other rejects.
	bad := &EKSCluster{
		Name: "x", RoleARN: clusterRole,
		SubnetIDs: []string{subnets[0], "subnet-other"},
		Region: testRegion, ARN: "arn:c", CreatedAt: "t",
	}
	if err := r.CreateEKSCluster(testAccount, bad); !errors.Is(err, models.ErrConflict) {
		t.Errorf("mixed-VPC subnets: want ErrConflict, got %v", err)
	}

	// SG from a different VPC also rejects.
	r.CreateSecurityGroup(testAccount, &EC2SecurityGroup{
		ID: "sg-other", VPCID: "vpc-other", GroupName: "x", Description: "x",
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	})
	bad2 := &EKSCluster{
		Name: "y", RoleARN: clusterRole,
		SubnetIDs: subnets, // both in vpc-1
		SecurityGroupIDs: []string{"sg-other"},
		Region: testRegion, ARN: "arn:c", CreatedAt: "t",
	}
	if err := r.CreateEKSCluster(testAccount, bad2); !errors.Is(err, models.ErrConflict) {
		t.Errorf("SG from different VPC: want ErrConflict, got %v", err)
	}

	// SG from cluster VPC succeeds.
	r.CreateSecurityGroup(testAccount, &EC2SecurityGroup{
		ID: "sg-vpc1", VPCID: "vpc-1", GroupName: "y", Description: "y",
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	})
	good := &EKSCluster{
		Name: "z", RoleARN: clusterRole,
		SubnetIDs: subnets, SecurityGroupIDs: []string{"sg-vpc1"},
		Region: testRegion, ARN: "arn:c", CreatedAt: "t",
	}
	if err := r.CreateEKSCluster(testAccount, good); err != nil {
		t.Errorf("SG in cluster VPC: %v", err)
	}
}

func TestEKSCluster_DeleteCASCADESChildren(t *testing.T) {
	r := setupRepo(t)
	clusterRole, nodeRole, subnets := setupEKSPrereqs(t, r)
	r.CreateEKSCluster(testAccount, &EKSCluster{
		Name: "demo", RoleARN: clusterRole, SubnetIDs: subnets,
		Region: testRegion, ARN: "arn:cluster", CreatedAt: "t",
	})
	r.CreateEKSNodeGroup(testAccount, &EKSNodeGroup{
		ClusterName: "demo", Name: "ng", NodeRoleARN: nodeRole, SubnetIDs: subnets,
		Region: testRegion, ARN: "arn:ng", CreatedAt: "t",
	})
	r.CreateEKSAddon(testAccount, &EKSAddon{
		ClusterName: "demo", Name: "vpc-cni", Version: "v1",
		Region: testRegion, ARN: "arn:addon", CreatedAt: "t",
	})

	if err := r.DeleteEKSCluster(testAccount, testRegion, "demo"); err != nil {
		t.Fatalf("DeleteEKSCluster: %v", err)
	}
	if _, err := r.GetEKSNodeGroup(testAccount, testRegion, "demo", "ng"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("CASCADE: nodegroup should be gone, got %v", err)
	}
	if _, err := r.GetEKSAddon(testAccount, testRegion, "demo", "vpc-cni"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("CASCADE: addon should be gone, got %v", err)
	}
}
