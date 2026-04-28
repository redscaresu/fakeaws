package repository

import (
	"errors"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

// setupVPCWith2Subnets is the bootstrap helper for RDS tests — almost
// every RDS scenario needs a DBSubnetGroup, which needs ≥2 subnets in
// the same VPC.
func setupVPCWith2Subnets(t *testing.T, r *Repository) (vpcID string, subnetIDs []string) {
	t.Helper()
	v := &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	if err := r.CreateVPC(testAccount, v); err != nil {
		t.Fatalf("seed VPC: %v", err)
	}
	for _, sub := range []*EC2Subnet{
		{ID: "subnet-a", VPCID: "vpc-1", CidrBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"},
		{ID: "subnet-b", VPCID: "vpc-1", CidrBlock: "10.0.2.0/24", AvailabilityZone: "us-east-1b", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"},
	} {
		if err := r.CreateSubnet(testAccount, sub); err != nil {
			t.Fatalf("seed subnet: %v", err)
		}
		subnetIDs = append(subnetIDs, sub.ID)
	}
	return v.ID, subnetIDs
}

func TestRDSSubnetGroup_SubnetsMustShareVPC(t *testing.T) {
	r := setupRepo(t)
	_, subnets := setupVPCWith2Subnets(t, r)

	// Add a second VPC + a subnet in it.
	v2 := &EC2VPC{ID: "vpc-2", CidrBlock: "10.1.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	r.CreateVPC(testAccount, v2)
	r.CreateSubnet(testAccount, &EC2Subnet{ID: "subnet-other", VPCID: "vpc-2", CidrBlock: "10.1.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"})

	// Mixing vpc-1 and vpc-2 subnets must reject.
	bad := &RDSSubnetGroup{
		Name: "mixed", SubnetIDs: []string{subnets[0], "subnet-other"},
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateDBSubnetGroup(testAccount, bad); !errors.Is(err, models.ErrConflict) {
		t.Errorf("mixed-VPC subnet group: want ErrConflict, got %v", err)
	}

	// Same-VPC subnets succeed.
	good := &RDSSubnetGroup{
		Name: "good", SubnetIDs: subnets, // both in vpc-1
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateDBSubnetGroup(testAccount, good); err != nil {
		t.Fatalf("same-VPC subnet group: %v", err)
	}
	got, _ := r.GetDBSubnetGroup(testAccount, testRegion, "good")
	if got.VPCID != "vpc-1" {
		t.Errorf("vpc_id: got %q want vpc-1", got.VPCID)
	}
}

func TestRDSSubnetGroup_MissingSubnet404(t *testing.T) {
	r := setupRepo(t)
	bad := &RDSSubnetGroup{
		Name: "x", SubnetIDs: []string{"subnet-missing"},
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateDBSubnetGroup(testAccount, bad); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("missing subnet: want ErrNotFound, got %v", err)
	}
}

func TestRDSInstance_FKChain(t *testing.T) {
	r := setupRepo(t)
	_, subnets := setupVPCWith2Subnets(t, r)

	r.CreateDBSubnetGroup(testAccount, &RDSSubnetGroup{
		Name: "default", SubnetIDs: subnets, Region: testRegion, ARN: "arn", CreatedAt: "t",
	})
	r.CreateDBParameterGroup(testAccount, &RDSParameterGroup{
		Name: "pg15", Family: "postgres15", Region: testRegion, ARN: "arn", CreatedAt: "t",
	})

	// Instance with missing subnet group → 404.
	bad := &RDSInstance{
		ID: "db-1", Engine: "postgres", InstanceClass: "db.t3.micro",
		SubnetGroupName: "missing-group", Region: testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateDBInstance(testAccount, bad); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("missing subnet group: want ErrNotFound, got %v", err)
	}

	// Instance with valid refs.
	good := &RDSInstance{
		ID: "db-1", Engine: "postgres", InstanceClass: "db.t3.micro",
		SubnetGroupName:    "default",
		ParameterGroupName: "pg15",
		Region:             testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateDBInstance(testAccount, good); err != nil {
		t.Fatalf("CreateDBInstance: %v", err)
	}
}

func TestRDSInstance_DeletionProtectionRefusesDelete(t *testing.T) {
	r := setupRepo(t)
	_, subnets := setupVPCWith2Subnets(t, r)
	r.CreateDBSubnetGroup(testAccount, &RDSSubnetGroup{Name: "default", SubnetIDs: subnets, Region: testRegion, ARN: "arn", CreatedAt: "t"})
	inst := &RDSInstance{
		ID: "db-1", Engine: "postgres", InstanceClass: "db.t3.micro",
		SubnetGroupName: "default", DeletionProtection: true,
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	}
	r.CreateDBInstance(testAccount, inst)
	if err := r.DeleteDBInstance(testAccount, testRegion, "db-1"); !errors.Is(err, models.ErrConflict) {
		t.Errorf("DeleteDBInstance with deletion_protection: want ErrConflict, got %v", err)
	}
}

func TestRDSInstance_SourceWithReplicasRESTRICT(t *testing.T) {
	r := setupRepo(t)
	_, subnets := setupVPCWith2Subnets(t, r)
	r.CreateDBSubnetGroup(testAccount, &RDSSubnetGroup{Name: "default", SubnetIDs: subnets, Region: testRegion, ARN: "arn", CreatedAt: "t"})

	src := &RDSInstance{ID: "src", Engine: "postgres", InstanceClass: "db.t3.micro", SubnetGroupName: "default", Region: testRegion, ARN: "arn", CreatedAt: "t"}
	r.CreateDBInstance(testAccount, src)
	repl := &RDSInstance{ID: "rep", Engine: "postgres", InstanceClass: "db.t3.micro", SubnetGroupName: "default", ReplicateSourceDB: "src", Region: testRegion, ARN: "arn", CreatedAt: "t"}
	if err := r.CreateDBInstance(testAccount, repl); err != nil {
		t.Fatalf("CreateDBInstance replica: %v", err)
	}

	// Source delete must be REJECTED while replicas exist.
	if err := r.DeleteDBInstance(testAccount, testRegion, "src"); !errors.Is(err, models.ErrConflict) {
		t.Errorf("source-with-replicas: want ErrConflict, got %v", err)
	}

	// After replica delete, source delete proceeds.
	r.DeleteDBInstance(testAccount, testRegion, "rep")
	if err := r.DeleteDBInstance(testAccount, testRegion, "src"); err != nil {
		t.Errorf("source delete after replica gone: %v", err)
	}
}

// TestRDS_RegionIsolation pins Codex pass 6 BLOCKING #3: same-named
// RDS resources in different regions must not collide. The PK of
// every RDS table includes region; this test creates a name collision
// across regions and asserts each region's view stays distinct.
func TestRDS_RegionIsolation(t *testing.T) {
	r := setupRepo(t)

	// Two parameter groups with the same name in different regions both succeed.
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		if err := r.CreateDBParameterGroup(testAccount, &RDSParameterGroup{
			Name: "shared", Family: "postgres15", Region: region,
			ARN: "arn:" + region, CreatedAt: "t",
		}); err != nil {
			t.Fatalf("CreateDBParameterGroup %s: %v", region, err)
		}
	}

	// Each region returns its own group — no bleed.
	us, _ := r.GetDBParameterGroup(testAccount, "us-east-1", "shared")
	eu, _ := r.GetDBParameterGroup(testAccount, "eu-west-1", "shared")
	if us.ARN == eu.ARN {
		t.Errorf("region isolation violated — ARN matches: %s", us.ARN)
	}

	// Delete in one region leaves the other intact.
	r.DeleteDBParameterGroup(testAccount, "us-east-1", "shared")
	if _, err := r.GetDBParameterGroup(testAccount, "eu-west-1", "shared"); err != nil {
		t.Errorf("eu-west-1 group should survive us-east-1 delete: %v", err)
	}
}

func TestRDSCluster_ParameterGroupAttachment(t *testing.T) {
	r := setupRepo(t)
	_, subnets := setupVPCWith2Subnets(t, r)
	r.CreateDBSubnetGroup(testAccount, &RDSSubnetGroup{Name: "default", SubnetIDs: subnets, Region: testRegion, ARN: "arn", CreatedAt: "t"})

	r.CreateDBClusterParameterGroup(testAccount, &RDSClusterParameterGroup{
		Name: "aurora-pg", Family: "aurora-postgresql15", Region: testRegion, ARN: "arn", CreatedAt: "t",
	})
	c := &RDSCluster{
		ID: "aurora-1", Engine: "aurora-postgresql", SubnetGroupName: "default",
		ClusterParameterGroupName: "aurora-pg",
		Region:                    testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateDBCluster(testAccount, c); err != nil {
		t.Fatalf("CreateDBCluster: %v", err)
	}
	got, _ := r.GetDBCluster(testAccount, testRegion, "aurora-1")
	if got.ClusterParameterGroupName != "aurora-pg" {
		t.Errorf("cluster param group: got %q", got.ClusterParameterGroupName)
	}
}
