package repository

import (
	"errors"
	"fmt"
	"testing"
	"time"

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

	if _, err := r.SetInstanceState(testAccount, testRegion, "terminated", "i-1"); err != nil {
		t.Fatalf("transition to terminated: %v", err)
	}
	// From terminated → anything but terminated is refused (concepts.md
	// "Standing patterns" item 9 — terminal-state refusal).
	if _, err := r.SetInstanceState(testAccount, testRegion, "running", "i-1"); !errors.Is(err, models.ErrConflict) {
		t.Errorf("transition out of terminated: want ErrConflict, got %v", err)
	}
}

// TestSetInstanceStateTerminateTwice: a second terminate of the same
// instance, in a later call or later in the same one, finds it
// terminated in the transaction and leaves it so; an id with no row
// is refused, terminating none of the others.
func TestSetInstanceStateTerminateTwice(t *testing.T) {
	r := setupRepo(t)
	createInstances(t, r, 3)
	previous, err := r.SetInstanceState(testAccount, testRegion, "terminated", "i-0")
	require.NoError(t, err)
	assert.Equal(t, []string{"running"}, previous, "first terminate")
	previous, err = r.SetInstanceState(testAccount, testRegion, "terminated", "i-0", "i-1", "i-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"terminated", "running", "terminated"}, previous, "back-to-back, and a repeated id")

	_, err = r.SetInstanceState(testAccount, testRegion, "terminated", "i-2", "i-missing")
	var refused *InstanceError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, "i-missing", refused.InstanceID)
	assert.ErrorIs(t, err, models.ErrNotFound)
	got, err := r.GetInstance(testAccount, testRegion, "i-2")
	require.NoError(t, err)
	assert.Equal(t, "running", got.State, "named with an unknown id, i-2 is not terminated")
}

// createInstances creates running instances i-0 … i-<n-1> in one subnet.
func createInstances(t *testing.T, r *Repository, n int) {
	t.Helper()
	_, subnetID := setupVPCSubnet(t, r)
	for i := range n {
		require.NoError(t, r.CreateInstance(testAccount, &EC2Instance{
			ID: fmt.Sprintf("i-%d", i), SubnetID: subnetID, AMIID: "ami-1", InstanceType: "t3.micro",
			Region: testRegion, ARN: "arn", State: "running", CreatedAt: "t",
		}, &EC2NetworkInterface{ID: fmt.Sprintf("eni-%d", i)}))
	}
}

// receive waits for one error from ch, failing the test after 10s.
func receive(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("%s never finished", what)
		return nil
	}
}

// TestUpdateInstanceAttributesKeepsAConcurrentState: a state change
// that arrives while an attribute update is between its read and its
// write waits for it, rather than landing there and being overwritten
// by the stale state the update read into data.
func TestUpdateInstanceAttributesKeepsAConcurrentState(t *testing.T) {
	r := setupRepo(t)
	createInstances(t, r, 1)

	stopped := make(chan error, 1)
	require.NoError(t, r.UpdateInstanceAttributes(testAccount, testRegion, "i-0", EC2InstanceAttributeChange{Set: func(a *EC2InstanceAttributes) {
		go func() {
			_, err := r.SetInstanceState(testAccount, testRegion, "stopped", "i-0")
			stopped <- err
		}()
		select { // without the update's transaction the state change finishes here
		case err := <-stopped:
			stopped <- err
		case <-time.After(200 * time.Millisecond):
		}
		a.DisableAPIStop = true
	}}))
	require.NoError(t, receive(t, stopped, "the state change"))
	got, err := r.GetInstance(testAccount, testRegion, "i-0")
	require.NoError(t, err)
	assert.Equal(t, "stopped", got.State, "the state change is not undone")
	assert.True(t, got.DisableAPIStop, "the update is kept")
}

// TestSetInstanceStateKeepsAConcurrentAttributeUpdate: a state change
// and an attribute update queued on the one connection both survive,
// whichever runs first. The pool hands the connection to a random
// waiter, so each round runs the state change first about half the
// time; a state change that read outside its transaction would then
// lose the update committed between its read and its write.
func TestSetInstanceStateKeepsAConcurrentAttributeUpdate(t *testing.T) {
	const rounds = 20
	r := setupRepo(t)
	createInstances(t, r, rounds)
	for i := range rounds {
		id := fmt.Sprintf("i-%d", i)
		hold, err := r.db.Begin() // takes the only connection
		require.NoError(t, err)
		waits := r.db.Stats().WaitCount
		stateErr, attrErr := make(chan error, 1), make(chan error, 1)
		go func() {
			_, err := r.SetInstanceState(testAccount, testRegion, "stopped", id)
			stateErr <- err
		}()
		go func() {
			attrErr <- r.UpdateInstanceAttributes(testAccount, testRegion, id, EC2InstanceAttributeChange{
				Set: func(a *EC2InstanceAttributes) { a.DisableAPITermination = true },
			})
		}()
		require.Eventually(t, func() bool { return r.db.Stats().WaitCount >= waits+2 }, 10*time.Second, time.Millisecond, "both queued")
		require.NoError(t, hold.Rollback())
		require.NoError(t, receive(t, stateErr, "the state change"))
		require.NoError(t, receive(t, attrErr, "the attribute update"))

		got, err := r.GetInstance(testAccount, testRegion, id)
		require.NoError(t, err)
		assert.Equal(t, "stopped", got.State, "round %d", i)
		assert.True(t, got.DisableAPITermination, "round %d: the update is kept", i)
	}
}

// TestUpdateInstanceAttributesIsAtomic: the attribute write and the
// ENI's sourceDestCheck write commit together or not at all, and a
// terminated instance is refused before either.
func TestUpdateInstanceAttributesIsAtomic(t *testing.T) {
	r := setupRepo(t)
	createInstances(t, r, 2)
	off := false
	change := EC2InstanceAttributeChange{Set: func(a *EC2InstanceAttributes) { a.DisableAPIStop = true }, SourceDestCheck: &off}

	_, err := r.db.Exec(`DELETE FROM ec2_network_interfaces WHERE instance_id = 'i-0'`)
	require.NoError(t, err)
	assert.ErrorIs(t, r.UpdateInstanceAttributes(testAccount, testRegion, "i-0", change), models.ErrConflict, "no ENI for sourceDestCheck")
	got, err := r.GetInstance(testAccount, testRegion, "i-0")
	require.NoError(t, err)
	assert.False(t, got.DisableAPIStop, "the attribute write rolled back with the ENI write")

	_, err = r.SetInstanceState(testAccount, testRegion, "terminated", "i-1")
	require.NoError(t, err)
	assert.ErrorIs(t, r.UpdateInstanceAttributes(testAccount, testRegion, "i-1", change), models.ErrTerminalState, "terminated")
	got, err = r.GetInstance(testAccount, testRegion, "i-1")
	require.NoError(t, err)
	assert.False(t, got.DisableAPIStop, "nothing written to a terminated instance")
	assert.ErrorIs(t, r.UpdateInstanceAttributes(testAccount, testRegion, "i-missing", change), models.ErrNotFound)
}

// TestSetInstanceStateTerminationProtected: terminating several
// instances, one with DisableAPITermination set, terminates none.
func TestSetInstanceStateTerminationProtected(t *testing.T) {
	r := setupRepo(t)
	createInstances(t, r, 2)
	require.NoError(t, r.UpdateInstanceAttributes(testAccount, testRegion, "i-1", EC2InstanceAttributeChange{
		Set: func(a *EC2InstanceAttributes) { a.DisableAPITermination = true },
	}))

	_, err := r.SetInstanceState(testAccount, testRegion, "terminated", "i-0", "i-1")
	var refused *InstanceError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, "i-1", refused.InstanceID)
	assert.ErrorIs(t, err, ErrTerminationProtected)
	for _, id := range []string{"i-0", "i-1"} {
		got, err := r.GetInstance(testAccount, testRegion, id)
		require.NoError(t, err)
		assert.Equal(t, "running", got.State, id)
	}
	enis, err := r.ListNetworkInterfaces(testAccount, testRegion)
	require.NoError(t, err)
	assert.Len(t, enis, 2, "no ENI deleted")
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

// TestAssociateEIPGuardIsInTheWrite: the already-associated refusal
// lives in AssociateEIP's UPDATE, not in a read before it, so a second
// associate (as two racing AssociateAddress calls would send) fails
// ErrConflict and leaves the first association in place.
func TestAssociateEIPGuardIsInTheWrite(t *testing.T) {
	r := setupRepo(t)
	_, subnetID := setupVPCSubnet(t, r)
	inst := &EC2Instance{
		ID: "i-1", SubnetID: subnetID, AMIID: "ami-1", InstanceType: "t3.micro",
		Region: testRegion, ARN: "arn", State: "running", CreatedAt: "t",
	}
	eni := &EC2NetworkInterface{ID: "eni-1"}
	require.NoError(t, r.CreateInstance(testAccount, inst, eni))
	other := &EC2Instance{
		ID: "i-2", SubnetID: subnetID, AMIID: "ami-1", InstanceType: "t3.micro",
		Region: testRegion, ARN: "arn", State: "running", CreatedAt: "t",
	}
	otherENI := &EC2NetworkInterface{ID: "eni-2"}
	require.NoError(t, r.CreateInstance(testAccount, other, otherENI))
	for _, id := range []string{"eipalloc-1", "eipalloc-2"} {
		require.NoError(t, r.CreateEIP(testAccount, &EC2EIP{AllocationID: id, Domain: "vpc", PublicIP: "203.0.113.7", Region: testRegion, CreatedAt: "t"}))
	}
	associate := func(allocID, assocID string, to *EC2NetworkInterface) error {
		return r.AssociateEIP(testAccount, &EC2EIP{
			AllocationID: allocID, Domain: "vpc", PublicIP: "203.0.113.7", Region: testRegion, CreatedAt: "t",
			AssociationID: assocID, InstanceID: to.InstanceID, NetworkInterfaceID: to.ID,
		}, to)
	}

	require.NoError(t, associate("eipalloc-1", "eipassoc-a", eni))
	assert.ErrorIs(t, associate("eipalloc-1", "eipassoc-b", otherENI), models.ErrConflict, "associated address to another ENI")
	assert.ErrorIs(t, associate("eipalloc-2", "eipassoc-c", eni), models.ErrConflict, "second address on the ENI")
	assert.ErrorIs(t, associate("eipalloc-missing", "eipassoc-d", otherENI), models.ErrNotFound, "missing address")

	got, err := r.GetEIP(testAccount, testRegion, "eipalloc-1")
	require.NoError(t, err)
	assert.Equal(t, "eipassoc-a", got.AssociationID, "first association kept")
	got, err = r.GetEIP(testAccount, testRegion, "eipalloc-2")
	require.NoError(t, err)
	assert.Empty(t, got.AssociationID, "second address left unassociated")
}

// TestClaimPublicIPStepsPastAHeldIP: two launches can derive one
// auto-assigned public IP, so CreateInstance takes the next one no other
// ENI in the region holds, and DisassociateEIP does the same when it
// gives an ENI an auto-assigned IP back.
func TestClaimPublicIPStepsPastAHeldIP(t *testing.T) {
	r := setupRepo(t)
	_, subnetID := setupVPCSubnet(t, r)
	launch := func(id string) *EC2NetworkInterface {
		t.Helper()
		eni := &EC2NetworkInterface{ID: "eni-" + id, PublicIP: "192.0.2.7", AutoPublicIP: true}
		require.NoError(t, r.CreateInstance(testAccount, &EC2Instance{
			ID: "i-" + id, SubnetID: subnetID, AMIID: "ami-1", InstanceType: "t3.micro",
			Region: testRegion, ARN: "arn", State: "running", CreatedAt: "t",
		}, eni))
		got, err := r.GetNetworkInterface(testAccount, testRegion, eni.ID)
		require.NoError(t, err)
		assert.Equal(t, eni.PublicIP, got.PublicIP, "%s: stored IP is the one set on eni", id)
		return got
	}
	a := launch("a")
	assert.Equal(t, "192.0.2.7", a.PublicIP)
	assert.Equal(t, "192.0.2.8", launch("b").PublicIP, "held: next one")

	eip := &EC2EIP{AllocationID: "eipalloc-1", Domain: "vpc", PublicIP: "203.0.113.7", Region: testRegion, CreatedAt: "t"}
	require.NoError(t, r.CreateEIP(testAccount, eip))
	eip.AssociationID, eip.InstanceID, eip.NetworkInterfaceID = "eipassoc-1", a.InstanceID, a.ID
	a.PublicIP = eip.PublicIP
	require.NoError(t, r.AssociateEIP(testAccount, eip, a))
	assert.Equal(t, "192.0.2.7", launch("c").PublicIP, "freed when a took the address")

	eip.AssociationID, eip.InstanceID, eip.NetworkInterfaceID = "", "", ""
	a.PublicIP = "192.0.2.7"
	require.NoError(t, r.DisassociateEIP(testAccount, eip, a))
	got, err := r.GetNetworkInterface(testAccount, testRegion, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.9", got.PublicIP, ".7 and .8 are held")
}
