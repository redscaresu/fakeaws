package repository

import (
	"errors"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

const testRegion = "us-east-1"

func TestVPCCRUD(t *testing.T) {
	r := setupRepo(t)
	v := &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}

	if err := r.CreateVPC(testAccount, v); err != nil {
		t.Fatalf("CreateVPC: %v", err)
	}
	got, err := r.GetVPC(testAccount, testRegion, "vpc-1")
	if err != nil {
		t.Fatalf("GetVPC: %v", err)
	}
	if got.CidrBlock != "10.0.0.0/16" {
		t.Errorf("cidr: got %q", got.CidrBlock)
	}
	vpcs, _ := r.ListVPCs(testAccount, testRegion)
	if len(vpcs) != 1 {
		t.Errorf("ListVPCs: got %d want 1", len(vpcs))
	}
	if err := r.DeleteVPC(testAccount, testRegion, "vpc-1"); err != nil {
		t.Fatalf("DeleteVPC: %v", err)
	}
	if _, err := r.GetVPC(testAccount, testRegion, "vpc-1"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("GetVPC after delete: %v", err)
	}
}

func TestSubnetFKToVPC(t *testing.T) {
	r := setupRepo(t)
	// Subnet without VPC → 404.
	s := &EC2Subnet{ID: "subnet-1", VPCID: "vpc-missing", CidrBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	if err := r.CreateSubnet(testAccount, s); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("CreateSubnet for missing VPC: want ErrNotFound, got %v", err)
	}

	// Now create the VPC + subnet.
	v := &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	if err := r.CreateVPC(testAccount, v); err != nil {
		t.Fatal(err)
	}
	s.VPCID = "vpc-1"
	if err := r.CreateSubnet(testAccount, s); err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}

	// Delete VPC → subnet CASCADE.
	if err := r.DeleteVPC(testAccount, testRegion, "vpc-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSubnet(testAccount, testRegion, "subnet-1"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("CASCADE: subnet should be gone after VPC delete, got %v", err)
	}
}

func TestInternetGatewayDetachOnVPCDelete(t *testing.T) {
	r := setupRepo(t)
	v := &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	if err := r.CreateVPC(testAccount, v); err != nil {
		t.Fatal(err)
	}
	igw := &EC2InternetGateway{ID: "igw-1", VPCID: "vpc-1", Region: testRegion, ARN: "arn", CreatedAt: "t"}
	if err := r.CreateInternetGateway(testAccount, igw); err != nil {
		t.Fatal(err)
	}

	// VPC delete should DETACH the IGW (ON DELETE SET NULL on vpc_id),
	// not cascade-delete it.
	if err := r.DeleteVPC(testAccount, testRegion, "vpc-1"); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetInternetGateway(testAccount, testRegion, "igw-1")
	if err != nil {
		t.Fatalf("IGW should still exist after VPC delete (detached, not cascaded): %v", err)
	}
	if got.VPCID != "" {
		t.Errorf("after VPC delete, IGW should be detached (vpc_id=''); got %q", got.VPCID)
	}
}

func TestRouteTableAssociationOnePerSubnet(t *testing.T) {
	r := setupRepo(t)
	v := &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	r.CreateVPC(testAccount, v)
	s := &EC2Subnet{ID: "subnet-1", VPCID: "vpc-1", CidrBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	r.CreateSubnet(testAccount, s)
	rt := &EC2RouteTable{ID: "rtb-1", VPCID: "vpc-1", Region: testRegion, ARN: "arn", CreatedAt: "t"}
	r.CreateRouteTable(testAccount, rt)
	rt2 := &EC2RouteTable{ID: "rtb-2", VPCID: "vpc-1", Region: testRegion, ARN: "arn", CreatedAt: "t"}
	r.CreateRouteTable(testAccount, rt2)

	// First association — fine.
	a := &EC2RouteTableAssociation{ID: "rtbassoc-1", RouteTableID: "rtb-1", SubnetID: "subnet-1"}
	if err := r.AssociateRouteTable(testAccount, testRegion, a); err != nil {
		t.Fatalf("first associate: %v", err)
	}
	// Second association on the same subnet — must fail (UNIQUE
	// constraint per the S44-T0 pitfall).
	a2 := &EC2RouteTableAssociation{ID: "rtbassoc-2", RouteTableID: "rtb-2", SubnetID: "subnet-1"}
	err := r.AssociateRouteTable(testAccount, testRegion, a2)
	if !errors.Is(err, models.ErrConflict) {
		t.Errorf("second associate on same subnet: want ErrConflict, got %v", err)
	}
}

func TestSecurityGroupCRUDPlusRules(t *testing.T) {
	r := setupRepo(t)
	v := &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	r.CreateVPC(testAccount, v)

	sg := &EC2SecurityGroup{
		ID: "sg-1", VPCID: "vpc-1", GroupName: "web", Description: "web tier",
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateSecurityGroup(testAccount, sg); err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}

	// Update ingress rules.
	rules := []byte(`[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]`)
	if err := r.UpdateSecurityGroupRules(testAccount, testRegion, "sg-1", "ingress", rules); err != nil {
		t.Fatalf("UpdateSecurityGroupRules: %v", err)
	}
	gotIng, _, err := r.GetSecurityGroupRules(testAccount, testRegion, "sg-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(gotIng) != string(rules) {
		t.Errorf("ingress rules: got %q want %q", gotIng, rules)
	}

	// SG with same group_name in same VPC — UNIQUE violation.
	sgDup := &EC2SecurityGroup{
		ID: "sg-2", VPCID: "vpc-1", GroupName: "web", Description: "x",
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateSecurityGroup(testAccount, sgDup); !errors.Is(err, models.ErrConflict) {
		t.Errorf("duplicate group_name: want ErrConflict, got %v", err)
	}
}

func TestEIPCreateGetDelete(t *testing.T) {
	r := setupRepo(t)
	eip := &EC2EIP{
		AllocationID: "eipalloc-1", Domain: "vpc", PublicIP: "203.0.113.7",
		Region: testRegion, CreatedAt: "t",
	}
	if err := r.CreateEIP(testAccount, eip); err != nil {
		t.Fatalf("CreateEIP: %v", err)
	}
	got, err := r.GetEIP(testAccount, testRegion, "eipalloc-1")
	if err != nil {
		t.Fatalf("GetEIP: %v", err)
	}
	if got.PublicIP != "203.0.113.7" {
		t.Errorf("public_ip: got %q", got.PublicIP)
	}
	if err := r.DeleteEIP(testAccount, testRegion, "eipalloc-1"); err != nil {
		t.Fatalf("DeleteEIP: %v", err)
	}
}

// TestEC2_CrossRegionFKRejected pins Codex pass 7 BLOCKING #1: a child
// resource (subnet, security group, route table) cannot reference a
// parent VPC that lives in a different region. The schema's PK is
// (account_id, id) and resource ids are globally unique within an
// account, so without an explicit region predicate the FK lookup would
// silently match a same-id parent in a different region. Each Get*
// the Create* path uses must filter by region.
func TestEC2_CrossRegionFKRejected(t *testing.T) {
	r := setupRepo(t)

	const (
		regionUS = "us-east-1"
		regionEU = "eu-west-1"
	)

	// Seed a VPC in us-east-1 only.
	usVPC := &EC2VPC{
		ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: regionUS,
		ARN: "arn:us", State: "available", CreatedAt: "t",
	}
	if err := r.CreateVPC(testAccount, usVPC); err != nil {
		t.Fatalf("seed us VPC: %v", err)
	}

	// Subnet in eu-west-1 referencing the us-east-1 VPC id MUST fail.
	euSubnet := &EC2Subnet{
		ID: "subnet-1", VPCID: "vpc-1", CidrBlock: "10.0.1.0/24",
		AvailabilityZone: "eu-west-1a", Region: regionEU,
		ARN: "arn:eu", State: "available", CreatedAt: "t",
	}
	if err := r.CreateSubnet(testAccount, euSubnet); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("cross-region subnet→VPC: want ErrNotFound, got %v", err)
	}

	// SG in eu-west-1 referencing the us-east-1 VPC id MUST fail.
	euSG := &EC2SecurityGroup{
		ID: "sg-1", VPCID: "vpc-1", GroupName: "web", Description: "web",
		Region: regionEU, ARN: "arn:eu", CreatedAt: "t",
	}
	if err := r.CreateSecurityGroup(testAccount, euSG); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("cross-region SG→VPC: want ErrNotFound, got %v", err)
	}

	// RouteTable in eu-west-1 referencing the us-east-1 VPC id MUST fail.
	euRT := &EC2RouteTable{
		ID: "rtb-1", VPCID: "vpc-1", Region: regionEU,
		ARN: "arn:eu", CreatedAt: "t",
	}
	if err := r.CreateRouteTable(testAccount, euRT); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("cross-region route table→VPC: want ErrNotFound, got %v", err)
	}

	// Now seed a VPC properly in eu-west-1 (different id, since PK is
	// (account, id) — using the same id across regions is a separate
	// gap not covered here). Same-region references succeed.
	euVPC := &EC2VPC{
		ID: "vpc-2", CidrBlock: "10.1.0.0/16", Region: regionEU,
		ARN: "arn:eu", State: "available", CreatedAt: "t",
	}
	if err := r.CreateVPC(testAccount, euVPC); err != nil {
		t.Fatalf("seed eu VPC: %v", err)
	}
	euSubnet.VPCID = "vpc-2"
	if err := r.CreateSubnet(testAccount, euSubnet); err != nil {
		t.Errorf("same-region subnet: %v", err)
	}
	euSG.VPCID = "vpc-2"
	if err := r.CreateSecurityGroup(testAccount, euSG); err != nil {
		t.Errorf("same-region SG: %v", err)
	}
	euRT.VPCID = "vpc-2"
	if err := r.CreateRouteTable(testAccount, euRT); err != nil {
		t.Errorf("same-region route table: %v", err)
	}

	// Get*-with-region must reject the cross-region lookup explicitly:
	// the us VPC must NOT be visible when scoped to eu-west-1.
	if _, err := r.GetVPC(testAccount, regionEU, "vpc-1"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("GetVPC(eu, vpc-1): want ErrNotFound, got %v", err)
	}
	// And empty-region keeps the account-wide lookup behavior so audit
	// helpers and list paths still see the row.
	if _, err := r.GetVPC(testAccount, "", "vpc-1"); err != nil {
		t.Errorf("GetVPC(\"\", vpc-1): empty region must still return the row, got %v", err)
	}
}
