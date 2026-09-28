package repository

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/models"
)

// setupVPCSubnet is a small bootstrap helper for the compute tests —
// every Instance test needs at least one VPC + Subnet to attach to.
func setupVPCSubnet(t *testing.T, r *Repository) (vpcID, subnetID string) {
	t.Helper()
	v := &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	if err := r.CreateVPC(testAccount, v); err != nil {
		t.Fatalf("seed VPC: %v", err)
	}
	s := &EC2Subnet{ID: "subnet-1", VPCID: "vpc-1", CidrBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	if err := r.CreateSubnet(testAccount, s); err != nil {
		t.Fatalf("seed Subnet: %v", err)
	}
	// Seed AMI fixture for tests that create instances. Codex pass 9
	// BLOCKING #1: CreateInstance now requires the AMI to exist.
	if err := r.SeedAMI(testAccount, &EC2AMI{
		ID: "ami-1", Name: "test-ami", OwnerID: "amazon",
		VirtualizationType: "hvm", RootDeviceName: "/dev/xvda", Region: testRegion,
	}); err != nil {
		t.Fatalf("seed AMI: %v", err)
	}
	return v.ID, s.ID
}

func TestInstanceCRUDPlusFK(t *testing.T) {
	r := setupRepo(t)
	_, subnetID := setupVPCSubnet(t, r)

	// Instance without subnet → 404.
	bad := &EC2Instance{
		ID: "i-1", SubnetID: "subnet-missing", AMIID: "ami-1", InstanceType: "t3.micro",
		Region: testRegion, ARN: "arn", State: "running", CreatedAt: "t",
	}
	if err := r.CreateInstance(testAccount, bad, &EC2NetworkInterface{ID: "eni-1"}); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("CreateInstance with missing subnet: want ErrNotFound, got %v", err)
	}

	good := &EC2Instance{
		ID: "i-1", SubnetID: subnetID, AMIID: "ami-1", InstanceType: "t3.micro",
		Region: testRegion, ARN: "arn", State: "running", CreatedAt: "t",
	}
	if err := r.CreateInstance(testAccount, good, &EC2NetworkInterface{ID: "eni-1"}); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}

	got, err := r.GetInstance(testAccount, testRegion, "i-1")
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	if got.InstanceType != "t3.micro" {
		t.Errorf("instance_type: %q", got.InstanceType)
	}
}

func TestInstanceSubnetDeleteRESTRICT(t *testing.T) {
	r := setupRepo(t)
	_, subnetID := setupVPCSubnet(t, r)
	inst := &EC2Instance{
		ID: "i-1", SubnetID: subnetID, AMIID: "ami-1", InstanceType: "t3.micro",
		Region: testRegion, ARN: "arn", State: "running", CreatedAt: "t",
	}
	if err := r.CreateInstance(testAccount, inst, &EC2NetworkInterface{ID: "eni-1"}); err != nil {
		t.Fatal(err)
	}

	// Subnet delete must be REJECTED while instances exist (PLAN.md
	// S44 contract — RESTRICT, not CASCADE).
	err := r.DeleteSubnet(testAccount, testRegion, subnetID)
	if err == nil {
		t.Error("DeleteSubnet with attached instance: expected error, got nil")
	}

	// After instance termination + deletion, subnet delete proceeds.
	if err := r.DeleteInstance(testAccount, testRegion, "i-1"); err != nil {
		t.Fatalf("DeleteInstance: %v", err)
	}
	if err := r.DeleteSubnet(testAccount, testRegion, subnetID); err != nil {
		t.Errorf("DeleteSubnet after instance gone: %v", err)
	}
}

func TestInstanceTerminalStateRefusesTransition(t *testing.T) {
	r := setupRepo(t)
	_, subnetID := setupVPCSubnet(t, r)
	inst := &EC2Instance{
		ID: "i-1", SubnetID: subnetID, AMIID: "ami-1", InstanceType: "t3.micro",
		Region: testRegion, ARN: "arn", State: "running", CreatedAt: "t",
	}
	r.CreateInstance(testAccount, inst, &EC2NetworkInterface{ID: "eni-1"})

	if err := r.SetInstanceState(testAccount, testRegion, "i-1", "terminated"); err != nil {
		t.Fatalf("transition to terminated: %v", err)
	}
	// From terminated → anything is refused (concepts.md "Standing
	// patterns" item 9 — terminal-state refusal).
	if err := r.SetInstanceState(testAccount, testRegion, "i-1", "running"); !errors.Is(err, models.ErrConflict) {
		t.Errorf("transition out of terminated: want ErrConflict, got %v", err)
	}
}

// TestPrivateIP pins the subnet allocator: AWS keeps the first four
// addresses and the last one, so a /28 holds 11 ENIs, and a requested
// address must be one of those and free.
func TestPrivateIP(t *testing.T) {
	used := map[string]bool{}
	for i := 4; i <= 14; i++ {
		ip, err := privateIP("10.0.1.0/28", "", used)
		require.NoError(t, err, "address %d", i)
		assert.Equal(t, fmt.Sprintf("10.0.1.%d", i), ip)
		used[ip] = true
	}
	_, err := privateIP("10.0.1.0/28", "", used)
	assert.ErrorIs(t, err, models.ErrConflict, "a full /28")

	ip, err := privateIP("10.0.1.7/24", "", nil)
	require.NoError(t, err)
	assert.Equal(t, "10.0.1.4", ip, "host bits in the cidr are masked off")

	ip, err = privateIP("10.0.1.0/24", "10.0.1.50", map[string]bool{"10.0.1.4": true})
	require.NoError(t, err)
	assert.Equal(t, "10.0.1.50", ip, "a requested free address")
	for _, want := range []string{"10.0.1.4", "10.0.1.1", "10.0.1.255", "10.0.2.5"} {
		_, err = privateIP("10.0.1.0/24", want, map[string]bool{"10.0.1.4": true})
		assert.ErrorIs(t, err, models.ErrConflict, "requested %s (in use, reserved or outside)", want)
	}

	_, err = privateIP("2001:db8::/64", "", nil)
	assert.ErrorIs(t, err, models.ErrConflict, "IPv6 subnet cidr")
}

// TestCreateInstanceFullSubnetIsAtomic: when the subnet has no free
// address the ENI insert fails and the instance row rolls back with it.
func TestCreateInstanceFullSubnetIsAtomic(t *testing.T) {
	r := setupRepo(t)
	setupVPCSubnet(t, r)
	small := &EC2Subnet{ID: "subnet-28", VPCID: "vpc-1", CidrBlock: "10.0.2.0/28", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}
	require.NoError(t, r.CreateSubnet(testAccount, small))
	create := func(n int) error {
		inst := &EC2Instance{
			ID: fmt.Sprintf("i-%d", n), SubnetID: small.ID, AMIID: "ami-1", InstanceType: "t3.micro",
			Region: testRegion, ARN: "arn", State: "running", CreatedAt: "t",
		}
		return r.CreateInstance(testAccount, inst, &EC2NetworkInterface{ID: fmt.Sprintf("eni-%d", n)})
	}
	for n := 1; n <= 11; n++ {
		require.NoError(t, create(n), "instance %d", n)
	}
	assert.ErrorIs(t, create(12), models.ErrConflict, "12th instance in a /28")
	_, err := r.GetInstance(testAccount, testRegion, "i-12")
	assert.ErrorIs(t, err, models.ErrNotFound, "failed launch left an instance row")
	enis, err := r.ListNetworkInterfaces(testAccount, "")
	require.NoError(t, err)
	assert.Len(t, enis, 11)
}

func TestKeyPairCRUD(t *testing.T) {
	r := setupRepo(t)
	kp := &EC2KeyPair{Name: "deploy", PublicKey: "ssh-rsa AAA", Fingerprint: "ab:cd", Region: testRegion, CreatedAt: "t"}
	if err := r.CreateKeyPair(testAccount, kp); err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	got, err := r.GetKeyPair(testAccount, testRegion, "deploy")
	if err != nil {
		t.Fatalf("GetKeyPair: %v", err)
	}
	if got.PublicKey != "ssh-rsa AAA" {
		t.Errorf("public_key: %q", got.PublicKey)
	}
	if err := r.DeleteKeyPair(testAccount, testRegion, "deploy"); err != nil {
		t.Fatalf("DeleteKeyPair: %v", err)
	}
	if _, err := r.GetKeyPair(testAccount, testRegion, "deploy"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

func TestAMISeedAndList(t *testing.T) {
	r := setupRepo(t)
	a := &EC2AMI{
		ID: "ami-0abcd1234", Name: "amazon-linux-2", OwnerID: "amazon",
		VirtualizationType: "hvm", RootDeviceName: "/dev/xvda", Region: testRegion,
	}
	if err := r.SeedAMI(testAccount, a); err != nil {
		t.Fatalf("SeedAMI: %v", err)
	}
	// Idempotent (INSERT OR IGNORE).
	if err := r.SeedAMI(testAccount, a); err != nil {
		t.Fatalf("SeedAMI re-seed: %v", err)
	}
	list, err := r.ListAMIs(testAccount, testRegion)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "ami-0abcd1234" {
		t.Errorf("ListAMIs: %#v", list)
	}
}
