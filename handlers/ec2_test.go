package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EC2 handler tests — networking surface that landed in S44-T4.
//
// Wire format: Query-RPC POST /ec2/region/<region> with form body
// Action=<op>&Version=2016-11-15&<params>; XML response. Per concepts.md
// "Coverage requirements" rule 1: each in-scope endpoint has a
// success-path test plus a 404 / FK-violation test where applicable.

const ec2Version = "2016-11-15"

func ec2Call(t *testing.T, srv *httptest.Server, region, action string, params url.Values) (*http.Response, []byte) {
	t.Helper()
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", ec2Version)
	path := "/ec2/region/" + region
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(params.Encode()))
	require.NoError(t, err, "new request")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "POST %s %s", path, action)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// extractEC2Tag returns the contents of the first <tag>...</tag> in body
// — sufficient for asserting server-stamped ids in handler tests
// without pulling a full XML decoder for the per-shape result types.
func extractEC2Tag(body []byte, tag string) string {
	start := "<" + tag + ">"
	end := "</" + tag + ">"
	s := strings.Index(string(body), start)
	if s < 0 {
		return ""
	}
	s += len(start)
	e := strings.Index(string(body)[s:], end)
	if e < 0 {
		return ""
	}
	return string(body)[s : s+e]
}

func TestEC2_CreateDescribeDeleteVPC(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// CreateVpc.
	resp, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateVpc body=%s", body)
	vpcID := extractEC2Tag(body, "vpcId")
	require.True(t, strings.HasPrefix(vpcID, "vpc-"), "CreateVpc body missing vpcId or wrong prefix: %s", body)
	assert.Contains(t, string(body), "<cidrBlock>10.0.0.0/16</cidrBlock>", "CreateVpc body missing cidrBlock: %s", body)

	// DescribeVpcs returns the new VPC.
	resp, body = ec2Call(t, srv, region, "DescribeVpcs", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeVpcs body=%s", body)
	assert.Contains(t, string(body), vpcID, "DescribeVpcs missing %s: %s", vpcID, body)

	// DeleteVpc.
	resp, body = ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {vpcID}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteVpc body=%s", body)

	// DeleteVpc on missing VPC → 404.
	resp, body = ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {"vpc-missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteVpc on missing vpc body=%s", body)
}

func TestEC2_CreateVPC_MissingCidr(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := ec2Call(t, srv, "us-east-1", "CreateVpc", nil)
	// Missing required CidrBlock surfaces as ErrConflict → 409.
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateVpc with no CidrBlock")
}

func TestEC2_SubnetCRUDAndFK(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Subnet without VPC → 404 (FK enforcement at the handler layer).
	resp, _ := ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId":     {"vpc-missing"},
		"CidrBlock": {"10.0.1.0/24"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "CreateSubnet missing vpc")

	// Create the VPC then the subnet.
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	require.NotEmpty(t, vpcID, "setup CreateVpc failed: %s", body)

	resp, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId":     {vpcID},
		"CidrBlock": {"10.0.1.0/24"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateSubnet body=%s", body)
	subnetID := extractEC2Tag(body, "subnetId")
	require.True(t, strings.HasPrefix(subnetID, "subnet-"), "CreateSubnet missing subnetId: %s", body)
	// AvailabilityZone defaults to <region>+"a" when unspecified.
	assert.Contains(t, string(body), "<availabilityZone>us-east-1a</availabilityZone>", "CreateSubnet should default AZ to <region>a: %s", body)

	// DescribeSubnets unfiltered.
	resp, body = ec2Call(t, srv, region, "DescribeSubnets", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), subnetID, "DescribeSubnets missing %s: %s", subnetID, body)

	// DescribeSubnets with vpc-id filter.
	params := url.Values{}
	params.Set("Filter.1.Name", "vpc-id")
	params.Set("Filter.1.Value.1", vpcID)
	resp, body = ec2Call(t, srv, region, "DescribeSubnets", params)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), subnetID, "DescribeSubnets filtered: %s", body)

	// DescribeSubnets with non-matching vpc-id → no subnets in list.
	params.Set("Filter.1.Value.1", "vpc-other")
	_, body = ec2Call(t, srv, region, "DescribeSubnets", params)
	assert.NotContains(t, string(body), subnetID, "DescribeSubnets vpc-other should not return %s: %s", subnetID, body)

	// DeleteVpc cascades to subnet (repository CASCADE).
	r, b := ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {vpcID}})
	require.Equal(t, http.StatusOK, r.StatusCode, "DeleteVpc body=%s", b)
	_, body = ec2Call(t, srv, region, "DescribeSubnets", nil)
	assert.NotContains(t, string(body), subnetID, "subnet should be cascade-deleted with vpc: %s", body)
}

func TestEC2_UnknownAction(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := ec2Call(t, srv, "us-east-1", "CreateNatGateway", nil)
	// Unimplemented EC2 actions surface as ErrNotFound → 404 with a
	// log-line marker; per concepts.md "Anti-patterns explicitly
	// forbidden", silent 200 is unacceptable.
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Unknown EC2 action body=%s", body)
}

func TestEC2_InternetGatewayLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Need a VPC to attach to.
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	require.NotEmpty(t, vpcID, "setup CreateVpc failed: %s", body)

	// Create — comes back unattached.
	resp, body := ec2Call(t, srv, region, "CreateInternetGateway", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateInternetGateway: %s", body)
	igwID := extractEC2Tag(body, "internetGatewayId")
	require.True(t, strings.HasPrefix(igwID, "igw-"), "CreateInternetGateway missing igw id: %s", body)

	// Attach.
	resp, body = ec2Call(t, srv, region, "AttachInternetGateway", url.Values{
		"InternetGatewayId": {igwID}, "VpcId": {vpcID},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "AttachInternetGateway: %s", body)

	// Describe shows the attachment.
	_, body = ec2Call(t, srv, region, "DescribeInternetGateways", nil)
	assert.Contains(t, string(body), "<vpcId>"+vpcID+"</vpcId>", "DescribeInternetGateways missing attachment to %s: %s", vpcID, body)

	// Attach to a missing VPC → 404.
	resp, _ = ec2Call(t, srv, region, "AttachInternetGateway", url.Values{
		"InternetGatewayId": {igwID}, "VpcId": {"vpc-missing"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "AttachInternetGateway missing vpc")

	// VPC delete detaches, doesn't cascade IGW (PLAN.md S44 contract).
	r, b := ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {vpcID}})
	require.Equal(t, http.StatusOK, r.StatusCode, "DeleteVpc: %s", b)
	_, body = ec2Call(t, srv, region, "DescribeInternetGateways", nil)
	assert.Contains(t, string(body), igwID, "IGW should survive VPC delete (detach, not cascade): %s", body)
	assert.NotContains(t, string(body), "<vpcId>"+vpcID+"</vpcId>", "IGW should be detached after VPC delete: %s", body)

	// Delete IGW.
	r, b = ec2Call(t, srv, region, "DeleteInternetGateway", url.Values{"InternetGatewayId": {igwID}})
	require.Equal(t, http.StatusOK, r.StatusCode, "DeleteInternetGateway: %s", b)
}

func TestEC2_RouteTableAndAssociation(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"},
	})
	subnetID := extractEC2Tag(body, "subnetId")

	// CreateRouteTable.
	resp, body := ec2Call(t, srv, region, "CreateRouteTable", url.Values{"VpcId": {vpcID}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateRouteTable: %s", body)
	rtbID := extractEC2Tag(body, "routeTableId")
	require.True(t, strings.HasPrefix(rtbID, "rtb-"), "CreateRouteTable missing rtb id: %s", body)

	// CreateRouteTable on missing VPC → 404.
	resp, _ = ec2Call(t, srv, region, "CreateRouteTable", url.Values{"VpcId": {"vpc-missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "CreateRouteTable missing vpc")

	// Associate.
	resp, body = ec2Call(t, srv, region, "AssociateRouteTable", url.Values{
		"RouteTableId": {rtbID}, "SubnetId": {subnetID},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "AssociateRouteTable: %s", body)
	assocID := extractEC2Tag(body, "associationId")
	require.True(t, strings.HasPrefix(assocID, "rtbassoc-"), "AssociateRouteTable missing associationId: %s", body)

	// Second route table associated to same subnet → ErrConflict (UNIQUE).
	_, body = ec2Call(t, srv, region, "CreateRouteTable", url.Values{"VpcId": {vpcID}})
	rtb2 := extractEC2Tag(body, "routeTableId")
	resp, _ = ec2Call(t, srv, region, "AssociateRouteTable", url.Values{
		"RouteTableId": {rtb2}, "SubnetId": {subnetID},
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "AssociateRouteTable second-on-subnet")

	// CreateRoute on the associated table.
	resp, _ = ec2Call(t, srv, region, "CreateRoute", url.Values{
		"RouteTableId":         {rtbID},
		"DestinationCidrBlock": {"0.0.0.0/0"},
		"GatewayId":            {"igw-stub"},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "CreateRoute")

	// Disassociate.
	resp, _ = ec2Call(t, srv, region, "DisassociateRouteTable", url.Values{"AssociationId": {assocID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DisassociateRouteTable")
}

func TestEC2_SecurityGroupCRUDPlusRules(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")

	// CreateSecurityGroup.
	resp, body := ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName":        {"web"},
		"GroupDescription": {"web tier"},
		"VpcId":            {vpcID},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateSecurityGroup: %s", body)
	sgID := extractEC2Tag(body, "groupId")
	require.True(t, strings.HasPrefix(sgID, "sg-"), "CreateSecurityGroup missing groupId: %s", body)

	// Duplicate group_name in same VPC → 409.
	resp, _ = ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"web"}, "GroupDescription": {"x"}, "VpcId": {vpcID},
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "duplicate SG name in same VPC")

	// AuthorizeSecurityGroupIngress: tcp 443 from 0.0.0.0/0.
	resp, _ = ec2Call(t, srv, region, "AuthorizeSecurityGroupIngress", url.Values{
		"GroupId":                           {sgID},
		"IpPermissions.1.IpProtocol":        {"tcp"},
		"IpPermissions.1.FromPort":          {"443"},
		"IpPermissions.1.ToPort":            {"443"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "AuthorizeSecurityGroupIngress")

	// DescribeSecurityGroups echoes the rule back.
	params := url.Values{}
	params.Set("GroupId.1", sgID)
	resp, body = ec2Call(t, srv, region, "DescribeSecurityGroups", params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeSecurityGroups: %s", body)
	assert.Contains(t, string(body), "<cidrIp>0.0.0.0/0</cidrIp>", "DescribeSecurityGroups missing cidrIp: %s", body)
	assert.Contains(t, string(body), "<fromPort>443</fromPort>", "DescribeSecurityGroups missing fromPort: %s", body)

	// Authorize same rule twice → idempotent (dedup by key).
	for i := 0; i < 2; i++ {
		ec2Call(t, srv, region, "AuthorizeSecurityGroupIngress", url.Values{
			"GroupId":                           {sgID},
			"IpPermissions.1.IpProtocol":        {"tcp"},
			"IpPermissions.1.FromPort":          {"443"},
			"IpPermissions.1.ToPort":            {"443"},
			"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
		})
	}
	_, body = ec2Call(t, srv, region, "DescribeSecurityGroups", params)
	assert.Equal(t, 1, strings.Count(string(body), "<cidrIp>0.0.0.0/0</cidrIp>"), "Authorize must be idempotent on identical rule; body=%s", body)

	// Revoke removes it.
	resp, _ = ec2Call(t, srv, region, "RevokeSecurityGroupIngress", url.Values{
		"GroupId":                           {sgID},
		"IpPermissions.1.IpProtocol":        {"tcp"},
		"IpPermissions.1.FromPort":          {"443"},
		"IpPermissions.1.ToPort":            {"443"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "RevokeSecurityGroupIngress")
	_, body = ec2Call(t, srv, region, "DescribeSecurityGroups", params)
	assert.NotContains(t, string(body), "<cidrIp>0.0.0.0/0</cidrIp>", "Revoke should remove rule; body=%s", body)

	// AuthorizeSecurityGroupEgress.
	resp, _ = ec2Call(t, srv, region, "AuthorizeSecurityGroupEgress", url.Values{
		"GroupId":                           {sgID},
		"IpPermissions.1.IpProtocol":        {"-1"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "AuthorizeSecurityGroupEgress")
	_, body = ec2Call(t, srv, region, "DescribeSecurityGroups", params)
	assert.Contains(t, string(body), "<ipPermissionsEgress>", "egress rule not echoed: %s", body)

	// SG on missing VPC → 404.
	resp, _ = ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"x"}, "GroupDescription": {"x"}, "VpcId": {"vpc-missing"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "SG with missing VPC")

	// DeleteSecurityGroup.
	resp, _ = ec2Call(t, srv, region, "DeleteSecurityGroup", url.Values{"GroupId": {sgID}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteSecurityGroup")
}

func TestEC2_RunInstancesAndTerminate(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"},
	})
	subnetID := extractEC2Tag(body, "subnetId")
	_, body = ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"app"}, "GroupDescription": {"app sg"}, "VpcId": {vpcID},
	})
	sgID := extractEC2Tag(body, "groupId")

	// RunInstances.
	resp, body := ec2Call(t, srv, region, "RunInstances", url.Values{
		"SubnetId":          {subnetID},
		"ImageId":           {"ami-0abcd1234"},
		"InstanceType":      {"t3.micro"},
		"SecurityGroupId.1": {sgID},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "RunInstances: %s", body)
	instID := extractEC2Tag(body, "instanceId")
	require.True(t, strings.HasPrefix(instID, "i-"), "RunInstances missing instanceId: %s", body)

	// DescribeInstances by id.
	params := url.Values{}
	params.Set("InstanceId.1", instID)
	resp, body = ec2Call(t, srv, region, "DescribeInstances", params)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "<name>running</name>", "DescribeInstances: %s", body)

	// TerminateInstances. The wire format wraps state-transitions in
	// <currentState> + <previousState>; assert each marker is present
	// (indented XML defeats single-line substring checks).
	resp, body = ec2Call(t, srv, region, "TerminateInstances", url.Values{
		"InstanceId.1": {instID},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "TerminateInstances: %s", body)
	for _, want := range []string{"<previousState>", "<currentState>", "<code>16</code>", "<name>running</name>", "<code>48</code>", "<name>terminated</name>"} {
		assert.Contains(t, string(body), want, "TerminateInstances missing %q in body: %s", want, body)
	}

	// Already-terminated → echoes terminated/terminated, no error.
	resp, body = ec2Call(t, srv, region, "TerminateInstances", url.Values{"InstanceId.1": {instID}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "TerminateInstances on terminated: %s", body)
}

func TestEC2_RunInstances_SubnetVPCPairing(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Two VPCs: SG in vpc-A, subnet in vpc-B → mismatched pair → 404.
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcA := extractEC2Tag(body, "vpcId")
	_, body = ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.1.0.0/16"}})
	vpcB := extractEC2Tag(body, "vpcId")

	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {vpcB}, "CidrBlock": {"10.1.1.0/24"},
	})
	subnetB := extractEC2Tag(body, "subnetId")

	_, body = ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"x"}, "GroupDescription": {"x"}, "VpcId": {vpcA},
	})
	sgA := extractEC2Tag(body, "groupId")

	resp, body := ec2Call(t, srv, region, "RunInstances", url.Values{
		"SubnetId":          {subnetB},
		"ImageId":           {"ami-0abcd1234"},
		"InstanceType":      {"t3.micro"},
		"SecurityGroupId.1": {sgA},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "subnet/SG VPC mismatch body=%s", body)
}

func TestEC2_KeyPairImportDescribeDelete(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	resp, body := ec2Call(t, srv, region, "ImportKeyPair", url.Values{
		"KeyName":           {"deploy"},
		"PublicKeyMaterial": {"ssh-rsa AAAAB3NzaC1yc2E"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "ImportKeyPair: %s", body)
	assert.Contains(t, string(body), "<keyName>deploy</keyName>", "ImportKeyPair: %s", body)

	resp, body = ec2Call(t, srv, region, "DescribeKeyPairs", url.Values{"KeyName.1": {"deploy"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "<keyName>deploy</keyName>", "DescribeKeyPairs: %s", body)

	resp, _ = ec2Call(t, srv, region, "DeleteKeyPair", url.Values{"KeyName": {"deploy"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteKeyPair")
}

func TestEC2_DescribeImagesFixtures(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Without a filter, the canonical fixture set is returned.
	resp, body := ec2Call(t, srv, region, "DescribeImages", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
	for _, ami := range []string{"ami-0abcd1234", "ami-0ubuntu2004", "ami-0ubuntu2204"} {
		assert.Contains(t, string(body), ami, "DescribeImages missing fixture %s: %s", ami, body)
	}

	// With ImageId.1 filter → just that one.
	params := url.Values{}
	params.Set("ImageId.1", "ami-0abcd1234")
	resp, body = ec2Call(t, srv, region, "DescribeImages", params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages filtered: %s", body)
	assert.Contains(t, string(body), "ami-0abcd1234", "DescribeImages filtered missing target: %s", body)
	assert.NotContains(t, string(body), "ami-0ubuntu2004", "DescribeImages filtered should NOT include other AMIs: %s", body)

	// Unknown AMI → 404.
	params.Set("ImageId.1", "ami-nope")
	resp, _ = ec2Call(t, srv, region, "DescribeImages", params)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeImages unknown AMI")
}

func TestEC2_EIPLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	resp, body := ec2Call(t, srv, region, "AllocateAddress", url.Values{"Domain": {"vpc"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "AllocateAddress: %s", body)
	allocID := extractEC2Tag(body, "allocationId")
	require.True(t, strings.HasPrefix(allocID, "eipalloc-"), "AllocateAddress missing allocationId: %s", body)
	publicIP := extractEC2Tag(body, "publicIp")
	assert.True(t, strings.HasPrefix(publicIP, "203.0.113."), "public IP must be in TEST-NET-3 range; got %q", publicIP)

	// Domain=standard rejected (v1 supports vpc only).
	resp, _ = ec2Call(t, srv, region, "AllocateAddress", url.Values{"Domain": {"standard"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "AllocateAddress Domain=standard")

	// DescribeAddresses with allocationId filter.
	params := url.Values{}
	params.Set("AllocationId.1", allocID)
	resp, body = ec2Call(t, srv, region, "DescribeAddresses", params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeAddresses: %s", body)
	assert.Contains(t, string(body), allocID, "DescribeAddresses missing %s: %s", allocID, body)

	// ReleaseAddress.
	resp, _ = ec2Call(t, srv, region, "ReleaseAddress", url.Values{"AllocationId": {allocID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ReleaseAddress")
	resp, _ = ec2Call(t, srv, region, "ReleaseAddress", url.Values{"AllocationId": {allocID}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "ReleaseAddress on already-released")
}
