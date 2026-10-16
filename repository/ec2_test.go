package repository

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/redscaresu/fakeaws/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRegion = "us-east-1"

// createVPC stores v with its default security group and main route
// table, as CreateVpc does.
func createVPC(r *Repository, v *EC2VPC) error {
	rt := "rtb-main-" + v.ID
	return r.CreateVPCWithDefaults(testAccount, v, &EC2SecurityGroup{
		ID: "sg-default-" + v.ID, VPCID: v.ID, GroupName: DefaultGroupName, Description: "default VPC security group",
		Region: v.Region, ARN: "arn", CreatedAt: "t",
	}, MainRouteTable{
		Table:       &EC2RouteTable{ID: rt, VPCID: v.ID, Region: v.Region, ARN: "arn", CreatedAt: "t"},
		Association: &EC2RouteTableAssociation{ID: "rtbassoc-main-" + v.ID, RouteTableID: rt, Main: true, State: "associated"},
		LocalRoute:  &EC2Route{RouteTableID: rt, DestinationCidrBlock: v.CidrBlock, GatewayID: "local", Origin: "CreateRouteTable", State: "active"},
	})
}

func TestVPCCRUD(t *testing.T) {
	r := setupRepo(t)
	v := &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}

	if err := createVPC(r, v); err != nil {
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
	if err := createVPC(r, v); err != nil {
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
	if err := createVPC(r, v); err != nil {
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
	createVPC(r, v)
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

// TestMainRouteTableAssociation: a main association has no subnet, its
// VPC holds one at most (the partial unique index), DisassociateRouteTable
// refuses it and keeps it, and DeleteSubnet leaves it.
func TestMainRouteTableAssociation(t *testing.T) {
	r := setupRepo(t)
	require.NoError(t, createVPC(r, &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	require.NoError(t, r.CreateSubnet(testAccount, &EC2Subnet{ID: "subnet-1", VPCID: "vpc-1", CidrBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	require.NoError(t, r.CreateRouteTable(testAccount, &EC2RouteTable{ID: "rtb-2", VPCID: "vpc-1", Region: testRegion, ARN: "arn", CreatedAt: "t"}))
	require.NoError(t, r.AssociateRouteTable(testAccount, testRegion, &EC2RouteTableAssociation{ID: "rtbassoc-1", RouteTableID: "rtb-2", SubnetID: "subnet-1", State: "associated"}))

	err := mapInsertError(insertAssociation(r.db, testAccount, "vpc-1", &EC2RouteTableAssociation{ID: "rtbassoc-main2", RouteTableID: "rtb-2", Main: true}))
	assert.ErrorIs(t, err, models.ErrConflict, "a second main association of one VPC")
	assert.ErrorIs(t, r.DisassociateRouteTable(testAccount, "rtbassoc-main-vpc-1"), ErrMainAssociation)
	require.NoError(t, r.DeleteSubnet(testAccount, testRegion, "subnet-1"))

	assocs, err := r.ListRouteTableAssociations(testAccount)
	require.NoError(t, err)
	assert.Equal(t, []*EC2RouteTableAssociation{{ID: "rtbassoc-main-vpc-1", RouteTableID: "rtb-main-vpc-1", Main: true, State: "associated"}}, assocs)
	assert.ErrorIs(t, r.DisassociateRouteTable(testAccount, "rtbassoc-1"), models.ErrNotFound, "DeleteSubnet dropped it")
}

func TestSecurityGroupCRUDPlusRules(t *testing.T) {
	r := setupRepo(t)
	v := &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	createVPC(r, v)

	sg := &EC2SecurityGroup{
		ID: "sg-1", VPCID: "vpc-1", GroupName: "web", Description: "web tier",
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateSecurityGroup(testAccount, sg); err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
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

// tcpRule is an ingress tcp rule of port from cidr.
func tcpRule(id string, port int, cidr string) EC2SecurityGroupRule {
	return EC2SecurityGroupRule{ID: id, GroupOwnerID: testAccount, IPProtocol: "tcp", FromPort: port, ToPort: port, CidrIPv4: cidr}
}

// ruleSlots names each rule by its id and (perm_ord, src_ord).
func ruleSlots(rules []EC2SecurityGroupRule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = fmt.Sprintf("%s %d/%d", r.ID, r.PermOrd, r.SrcOrd)
	}
	return out
}

// TestSecurityGroupRules: an authorized source joins the end of its
// permission (protocol and ports), or starts one after the direction's
// last; a held source adds nothing; a revoke keeps a permission's slot
// while it has a source. The list is ordered by direction, permission
// and source.
func TestSecurityGroupRules(t *testing.T) {
	r := setupRepo(t)
	require.NoError(t, createVPC(r, &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	require.NoError(t, r.CreateSecurityGroup(testAccount, &EC2SecurityGroup{ID: "sg-1", VPCID: "vpc-1", GroupName: "web", Description: "d", Region: testRegion, ARN: "arn", CreatedAt: "t"}))

	egress := tcpRule("sgr-e", 443, "0.0.0.0/0")
	egress.IsEgress = true
	added, err := r.AuthorizeSecurityGroupRules(testAccount, testRegion, "sg-1", []EC2SecurityGroupRule{
		egress,
		tcpRule("sgr-a", 22, "10.0.0.0/8"),
		tcpRule("sgr-b", 80, "10.1.0.0/16"),
		tcpRule("sgr-c", 22, "10.2.0.0/16"),
		tcpRule("sgr-dup", 22, "10.0.0.0/8"),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"sgr-e 0/0", "sgr-a 0/0", "sgr-b 1/0", "sgr-c 0/1"}, ruleSlots(added), "a held source is skipped")
	assert.Equal(t, "sg-1", added[0].GroupID)

	added, err = r.AuthorizeSecurityGroupRules(testAccount, testRegion, "sg-1", []EC2SecurityGroupRule{tcpRule("sgr-again", 80, "10.1.0.0/16")})
	require.NoError(t, err)
	assert.Empty(t, added, "re-authorizing adds nothing")

	require.NoError(t, r.RevokeSecurityGroupRules(testAccount, testRegion, "sg-1", []EC2SecurityGroupRule{
		tcpRule("", 22, "10.0.0.0/8"), tcpRule("", 22, "192.0.2.0/24"),
	}))
	rules, err := r.ListSecurityGroupRules(testAccount, testRegion, "sg-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"sgr-c 0/1", "sgr-b 1/0", "sgr-e 0/0"}, ruleSlots(rules), "the first permission keeps its slot")

	_, err = r.AuthorizeSecurityGroupRules(testAccount, testRegion, "sg-1", []EC2SecurityGroupRule{{ID: "sgr-two", IPProtocol: "-1", CidrIPv4: "10.0.0.0/8", CidrIPv6: "::/0"}})
	assert.Error(t, err, "a rule holds exactly one source")
	for _, c := range []struct{ region, group string }{{"eu-west-1", "sg-1"}, {testRegion, "sg-missing"}} {
		region, group := c.region, c.group
		_, err = r.AuthorizeSecurityGroupRules(testAccount, region, group, []EC2SecurityGroupRule{tcpRule("sgr-x", 1, "10.0.0.0/8")})
		assert.ErrorIs(t, err, models.ErrNotFound, "authorize %s in %s", group, region)
		assert.ErrorIs(t, r.RevokeSecurityGroupRules(testAccount, region, group, nil), models.ErrNotFound, "revoke %s in %s", group, region)
		_, err = r.ListSecurityGroupRules(testAccount, region, group)
		assert.ErrorIs(t, err, models.ErrNotFound, "list %s in %s", group, region)
	}
}

// TestRevokeSecurityGroupRulesByID: a rule with an ID revokes the rule
// of that id, group and direction; one the group lacks there is
// RuleNotFoundError and the whole revoke deletes nothing. Get and the
// region list answer rules by id and region.
func TestRevokeSecurityGroupRulesByID(t *testing.T) {
	r := setupRepo(t)
	require.NoError(t, createVPC(r, &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	for _, id := range []string{"sg-1", "sg-2"} {
		require.NoError(t, r.CreateSecurityGroup(testAccount, &EC2SecurityGroup{ID: id, VPCID: "vpc-1", GroupName: id, Description: "d", Region: testRegion, ARN: "arn", CreatedAt: "t"}))
	}
	egress := tcpRule("sgr-e", 443, "0.0.0.0/0")
	egress.IsEgress = true
	_, err := r.AuthorizeSecurityGroupRules(testAccount, testRegion, "sg-1", []EC2SecurityGroupRule{
		tcpRule("sgr-a", 22, "10.0.0.0/8"), tcpRule("sgr-b", 22, "10.1.0.0/16"), egress,
	})
	require.NoError(t, err)
	_, err = r.AuthorizeSecurityGroupRules(testAccount, testRegion, "sg-2", []EC2SecurityGroupRule{tcpRule("sgr-z", 80, "10.0.0.0/8")})
	require.NoError(t, err)

	got, err := r.GetSecurityGroupRule(testAccount, testRegion, "sgr-b")
	require.NoError(t, err)
	assert.Equal(t, "10.1.0.0/16", got.CidrIPv4)
	_, err = r.GetSecurityGroupRule(testAccount, "eu-west-1", "sgr-b")
	assert.ErrorIs(t, err, models.ErrNotFound, "another region's rule")
	_, err = r.GetSecurityGroupRule(testAccount, testRegion, "sgr-missing")
	assert.Equal(t, RuleNotFoundError{ID: "sgr-missing"}, err)
	all, err := r.ListRegionSecurityGroupRules(testAccount, testRegion)
	require.NoError(t, err)
	assert.Equal(t, []string{"sgr-a 0/0", "sgr-b 0/1", "sgr-e 0/0", "sgr-z 0/0"}, ruleSlots(all))
	none, err := r.ListRegionSecurityGroupRules(testAccount, "eu-west-1")
	require.NoError(t, err)
	assert.Empty(t, none)

	byID := func(id string, egress bool) EC2SecurityGroupRule {
		return EC2SecurityGroupRule{ID: id, IsEgress: egress}
	}
	for _, bad := range []EC2SecurityGroupRule{byID("sgr-missing", false), byID("sgr-e", false), byID("sgr-z", false)} {
		err = r.RevokeSecurityGroupRules(testAccount, testRegion, "sg-1", []EC2SecurityGroupRule{byID("sgr-a", false), tcpRule("", 22, "10.1.0.0/16"), bad})
		assert.Equal(t, RuleNotFoundError{ID: bad.ID}, err, "revoke %s", bad.ID)
	}
	rules, err := r.ListSecurityGroupRules(testAccount, testRegion, "sg-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"sgr-a 0/0", "sgr-b 0/1", "sgr-e 0/0"}, ruleSlots(rules), "a failed revoke deletes nothing")

	require.NoError(t, r.RevokeSecurityGroupRules(testAccount, testRegion, "sg-1", []EC2SecurityGroupRule{byID("sgr-a", false), byID("sgr-e", true)}))
	rules, err = r.ListSecurityGroupRules(testAccount, testRegion, "sg-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"sgr-b 0/1"}, ruleSlots(rules), "the permission keeps its other source")
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
	if err := createVPC(r, usVPC); err != nil {
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
	if err := createVPC(r, euVPC); err != nil {
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

func TestUpdateSubnet(t *testing.T) {
	r := setupRepo(t)
	require.NoError(t, createVPC(r, &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	require.NoError(t, r.CreateSubnet(testAccount, &EC2Subnet{ID: "subnet-1", VPCID: "vpc-1", CidrBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))

	require.NoError(t, r.UpdateSubnet(testAccount, testRegion, "subnet-1", func(s *EC2Subnet) { s.MapPublicIPOnLaunch = true }))
	got, err := r.GetSubnet(testAccount, testRegion, "subnet-1")
	require.NoError(t, err)
	assert.True(t, got.MapPublicIPOnLaunch)
	assert.Equal(t, "10.0.1.0/24", got.CidrBlock, "other fields survive")

	err = r.UpdateSubnet(testAccount, testRegion, "subnet-missing", func(*EC2Subnet) {})
	assert.ErrorIs(t, err, models.ErrNotFound)
}

// TestCreateEIPStepsPastAHeldIP: AWS never gives two allocations one
// IP, so CreateEIP takes the next free address in the /24, wrapping,
// and only within the account and region.
func TestCreateEIPStepsPastAHeldIP(t *testing.T) {
	r := setupRepo(t)
	create := func(id, region, ip string) string {
		t.Helper()
		eip := &EC2EIP{AllocationID: id, Domain: "vpc", PublicIP: ip, Region: region, CreatedAt: "t"}
		require.NoError(t, r.CreateEIP(testAccount, eip))
		got, err := r.GetEIP(testAccount, region, id)
		require.NoError(t, err)
		assert.Equal(t, eip.PublicIP, got.PublicIP, "%s: stored IP is the one set on eip", id)
		return got.PublicIP
	}
	assert.Equal(t, "203.0.113.7", create("eipalloc-1", testRegion, "203.0.113.7"))
	assert.Equal(t, "203.0.113.8", create("eipalloc-2", testRegion, "203.0.113.7"), "held: next one")
	assert.Equal(t, "203.0.113.255", create("eipalloc-3", testRegion, "203.0.113.255"))
	assert.Equal(t, "203.0.113.0", create("eipalloc-4", testRegion, "203.0.113.255"), "wraps within the /24")
	assert.Equal(t, "203.0.113.7", create("eipalloc-5", "eu-west-2", "203.0.113.7"), "another region's IP is not held")
}

func azRow(region, name, id string) AvailabilityZone {
	return AvailabilityZone{
		Region: region, ZoneName: name, ZoneID: id, State: "available", OptInStatus: "opt-in-not-required",
		ZoneType: "availability-zone", GroupName: region, NetworkBorderGroup: region,
	}
}

func zones(t *testing.T, r *Repository, region string) []AvailabilityZone {
	t.Helper()
	got, err := r.ListAvailabilityZones(testAccount, region)
	require.NoError(t, err)
	return got
}

// AZ rows are listed per account and region by zone name, survive
// snapshot/restore and a reopen, and reset empties the table.
func TestAvailabilityZonesLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	r, err := New(dbPath)
	require.NoError(t, err)
	b, a := azRow(testRegion, "us-east-1b", "use1-az1"), azRow(testRegion, "us-east-1a", "use1-az6")
	for _, z := range []AvailabilityZone{b, a, azRow("eu-west-2", "eu-west-2a", "euw2-az2")} {
		require.NoError(t, r.PutAvailabilityZone(testAccount, z))
	}
	require.NoError(t, r.PutAvailabilityZone("111111111111", azRow(testRegion, "us-east-1c", "use1-az2")))
	assert.Equal(t, []AvailabilityZone{a, b}, zones(t, r, testRegion))

	require.NoError(t, r.Snapshot())
	_, err = r.DB().Exec(`DELETE FROM availability_zones`)
	require.NoError(t, err)
	require.NoError(t, r.Restore(nil))
	assert.Equal(t, []AvailabilityZone{a, b}, zones(t, r, testRegion), "restore")

	require.NoError(t, r.Close())
	r, err = New(dbPath)
	require.NoError(t, err)
	defer r.Close()
	assert.Equal(t, []AvailabilityZone{a, b}, zones(t, r, testRegion), "reopen")

	require.NoError(t, r.Reset())
	assert.Empty(t, zones(t, r, testRegion), "reset")
	assert.Empty(t, zones(t, r, "eu-west-2"), "reset")
}

// An AZ row is account data: SetIdentity refuses an account change on
// a database whose only row is one.
func TestAvailabilityZoneRowIsNotEmpty(t *testing.T) {
	r := setupRepo(t)
	require.NoError(t, r.PutAvailabilityZone(testAccount, azRow(testRegion, "us-east-1a", "use1-az6")))
	err := r.SetIdentity(Identity{AccountID: "111111111111"}, testAccount, nil)
	assert.ErrorIs(t, err, models.ErrConflict)
}

// Concurrent creates of one CIDR in one VPC: the overlap check and the
// INSERT share a tx, so exactly one wins and the rest are refused.
func TestCreateSubnetOverlapIsAtomic(t *testing.T) {
	r := setupRepo(t)
	const goroutines, rounds = 8, 50
	for round := range rounds {
		vpcID := fmt.Sprintf("vpc-%d", round)
		require.NoError(t, createVPC(r, &EC2VPC{ID: vpcID, CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
		errs := make([]error, goroutines)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for g := range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[g] = r.CreateSubnet(testAccount, &EC2Subnet{ID: fmt.Sprintf("subnet-%d-%d", round, g), VPCID: vpcID,
					CidrBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"})
			}()
		}
		close(start)
		wg.Wait()
		won, refused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case errors.Is(err, ErrSubnetConflict):
				refused++
			default:
				t.Errorf("round %d: unexpected error %v", round, err)
			}
		}
		assert.Equal(t, 1, won, "round %d successes", round)
		assert.Equal(t, goroutines-1, refused, "round %d ErrSubnetConflict", round)
	}
}

// TestBackfillDefaultGroupsIsAtomic: the backfill lists the bare VPCs
// and inserts their groups in one transaction, so a failed insert adds
// no group at all; a loaded database gets none.
func TestBackfillDefaultGroupsIsAtomic(t *testing.T) {
	r := setupRepo(t)
	for _, id := range []string{"vpc-1", "vpc-2"} {
		require.NoError(t, createVPC(r, &EC2VPC{ID: id, CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	}
	_, err := r.DB().Exec(`DELETE FROM ec2_security_groups`)
	require.NoError(t, err)
	newGroup := func(account, region, vpcID string) *EC2SecurityGroup {
		return &EC2SecurityGroup{ID: "sg-" + vpcID, VPCID: vpcID, GroupName: DefaultGroupName, Region: region, ARN: "arn", CreatedAt: "t"}
	}
	groups := func() []string {
		t.Helper()
		sgs, err := r.ListSecurityGroups(testAccount, "")
		require.NoError(t, err)
		var ids []string
		for _, sg := range sgs {
			ids = append(ids, sg.ID)
		}
		return ids
	}

	_, err = r.DB().Exec(`CREATE TRIGGER refuse_vpc2 BEFORE INSERT ON ec2_security_groups WHEN NEW.vpc_id = 'vpc-2'
		BEGIN SELECT RAISE(ABORT, 'refused'); END`)
	require.NoError(t, err)
	assert.Error(t, r.BackfillDefaultGroups(newGroup))
	assert.Empty(t, groups(), "vpc-1's group rolled back with vpc-2's")

	_, err = r.DB().Exec(`DROP TRIGGER refuse_vpc2`)
	require.NoError(t, err)
	require.NoError(t, r.SetLoaded(true, testAccount))
	require.NoError(t, r.BackfillDefaultGroups(newGroup))
	assert.Empty(t, groups(), "loaded: none")

	require.NoError(t, r.SetLoaded(false, testAccount))
	require.NoError(t, r.BackfillDefaultGroups(newGroup))
	require.NoError(t, r.BackfillDefaultGroups(newGroup), "a second run finds nothing bare")
	assert.ElementsMatch(t, []string{"sg-vpc-1", "sg-vpc-2"}, groups())
}
