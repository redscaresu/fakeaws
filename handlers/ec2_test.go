package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s %s: %v", path, action, err)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateVpc: got %d body=%s", resp.StatusCode, body)
	}
	vpcID := extractEC2Tag(body, "vpcId")
	if !strings.HasPrefix(vpcID, "vpc-") {
		t.Fatalf("CreateVpc body missing vpcId or wrong prefix: %s", body)
	}
	if !strings.Contains(string(body), "<cidrBlock>10.0.0.0/16</cidrBlock>") {
		t.Errorf("CreateVpc body missing cidrBlock: %s", body)
	}

	// DescribeVpcs returns the new VPC.
	resp, body = ec2Call(t, srv, region, "DescribeVpcs", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DescribeVpcs: got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), vpcID) {
		t.Errorf("DescribeVpcs missing %s: %s", vpcID, body)
	}

	// DeleteVpc.
	resp, body = ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {vpcID}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteVpc: got %d body=%s", resp.StatusCode, body)
	}

	// DeleteVpc on missing VPC → 404.
	resp, body = ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {"vpc-missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DeleteVpc on missing vpc: got %d body=%s, want 404", resp.StatusCode, body)
	}
}

func TestEC2_CreateVPC_MissingCidr(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := ec2Call(t, srv, "us-east-1", "CreateVpc", nil)
	// Missing required CidrBlock surfaces as ErrConflict → 409.
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateVpc with no CidrBlock: got %d, want 409", resp.StatusCode)
	}
}

func TestEC2_SubnetCRUDAndFK(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Subnet without VPC → 404 (FK enforcement at the handler layer).
	resp, _ := ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId":     {"vpc-missing"},
		"CidrBlock": {"10.0.1.0/24"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("CreateSubnet missing vpc: got %d, want 404", resp.StatusCode)
	}

	// Create the VPC then the subnet.
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	if vpcID == "" {
		t.Fatalf("setup CreateVpc failed: %s", body)
	}

	resp, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId":     {vpcID},
		"CidrBlock": {"10.0.1.0/24"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateSubnet: got %d body=%s", resp.StatusCode, body)
	}
	subnetID := extractEC2Tag(body, "subnetId")
	if !strings.HasPrefix(subnetID, "subnet-") {
		t.Fatalf("CreateSubnet missing subnetId: %s", body)
	}
	// AvailabilityZone defaults to <region>+"a" when unspecified.
	if !strings.Contains(string(body), "<availabilityZone>us-east-1a</availabilityZone>") {
		t.Errorf("CreateSubnet should default AZ to <region>a: %s", body)
	}

	// DescribeSubnets unfiltered.
	resp, body = ec2Call(t, srv, region, "DescribeSubnets", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), subnetID) {
		t.Errorf("DescribeSubnets missing %s: %d %s", subnetID, resp.StatusCode, body)
	}

	// DescribeSubnets with vpc-id filter.
	params := url.Values{}
	params.Set("Filter.1.Name", "vpc-id")
	params.Set("Filter.1.Value.1", vpcID)
	resp, body = ec2Call(t, srv, region, "DescribeSubnets", params)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), subnetID) {
		t.Errorf("DescribeSubnets filtered: %d %s", resp.StatusCode, body)
	}

	// DescribeSubnets with non-matching vpc-id → no subnets in list.
	params.Set("Filter.1.Value.1", "vpc-other")
	_, body = ec2Call(t, srv, region, "DescribeSubnets", params)
	if strings.Contains(string(body), subnetID) {
		t.Errorf("DescribeSubnets vpc-other should not return %s: %s", subnetID, body)
	}

	// DeleteVpc cascades to subnet (repository CASCADE).
	if resp, body := ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {vpcID}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteVpc: %d %s", resp.StatusCode, body)
	}
	_, body = ec2Call(t, srv, region, "DescribeSubnets", nil)
	if strings.Contains(string(body), subnetID) {
		t.Errorf("subnet should be cascade-deleted with vpc: %s", body)
	}
}

func TestEC2_UnknownAction(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := ec2Call(t, srv, "us-east-1", "CreateNatGateway", nil)
	// Unimplemented EC2 actions surface as ErrNotFound → 404 with a
	// log-line marker; per concepts.md "Anti-patterns explicitly
	// forbidden", silent 200 is unacceptable.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Unknown EC2 action: got %d, want 404; body=%s", resp.StatusCode, body)
	}
}

func TestEC2_InternetGatewayLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Need a VPC to attach to.
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	if vpcID == "" {
		t.Fatalf("setup CreateVpc failed: %s", body)
	}

	// Create — comes back unattached.
	resp, body := ec2Call(t, srv, region, "CreateInternetGateway", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateInternetGateway: %d %s", resp.StatusCode, body)
	}
	igwID := extractEC2Tag(body, "internetGatewayId")
	if !strings.HasPrefix(igwID, "igw-") {
		t.Fatalf("CreateInternetGateway missing igw id: %s", body)
	}

	// Attach.
	resp, body = ec2Call(t, srv, region, "AttachInternetGateway", url.Values{
		"InternetGatewayId": {igwID}, "VpcId": {vpcID},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("AttachInternetGateway: %d %s", resp.StatusCode, body)
	}

	// Describe shows the attachment.
	_, body = ec2Call(t, srv, region, "DescribeInternetGateways", nil)
	if !strings.Contains(string(body), "<vpcId>"+vpcID+"</vpcId>") {
		t.Errorf("DescribeInternetGateways missing attachment to %s: %s", vpcID, body)
	}

	// Attach to a missing VPC → 404.
	resp, _ = ec2Call(t, srv, region, "AttachInternetGateway", url.Values{
		"InternetGatewayId": {igwID}, "VpcId": {"vpc-missing"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("AttachInternetGateway missing vpc: got %d, want 404", resp.StatusCode)
	}

	// VPC delete detaches, doesn't cascade IGW (PLAN.md S44 contract).
	if resp, body := ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {vpcID}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteVpc: %d %s", resp.StatusCode, body)
	}
	_, body = ec2Call(t, srv, region, "DescribeInternetGateways", nil)
	if !strings.Contains(string(body), igwID) {
		t.Errorf("IGW should survive VPC delete (detach, not cascade): %s", body)
	}
	if strings.Contains(string(body), "<vpcId>"+vpcID+"</vpcId>") {
		t.Errorf("IGW should be detached after VPC delete: %s", body)
	}

	// Delete IGW.
	if resp, body := ec2Call(t, srv, region, "DeleteInternetGateway", url.Values{"InternetGatewayId": {igwID}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteInternetGateway: %d %s", resp.StatusCode, body)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRouteTable: %d %s", resp.StatusCode, body)
	}
	rtbID := extractEC2Tag(body, "routeTableId")
	if !strings.HasPrefix(rtbID, "rtb-") {
		t.Fatalf("CreateRouteTable missing rtb id: %s", body)
	}

	// CreateRouteTable on missing VPC → 404.
	resp, _ = ec2Call(t, srv, region, "CreateRouteTable", url.Values{"VpcId": {"vpc-missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("CreateRouteTable missing vpc: got %d, want 404", resp.StatusCode)
	}

	// Associate.
	resp, body = ec2Call(t, srv, region, "AssociateRouteTable", url.Values{
		"RouteTableId": {rtbID}, "SubnetId": {subnetID},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("AssociateRouteTable: %d %s", resp.StatusCode, body)
	}
	assocID := extractEC2Tag(body, "associationId")
	if !strings.HasPrefix(assocID, "rtbassoc-") {
		t.Fatalf("AssociateRouteTable missing associationId: %s", body)
	}

	// Second route table associated to same subnet → ErrConflict (UNIQUE).
	_, body = ec2Call(t, srv, region, "CreateRouteTable", url.Values{"VpcId": {vpcID}})
	rtb2 := extractEC2Tag(body, "routeTableId")
	resp, _ = ec2Call(t, srv, region, "AssociateRouteTable", url.Values{
		"RouteTableId": {rtb2}, "SubnetId": {subnetID},
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("AssociateRouteTable second-on-subnet: got %d, want 409", resp.StatusCode)
	}

	// CreateRoute on the associated table.
	resp, _ = ec2Call(t, srv, region, "CreateRoute", url.Values{
		"RouteTableId":         {rtbID},
		"DestinationCidrBlock": {"0.0.0.0/0"},
		"GatewayId":            {"igw-stub"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("CreateRoute: got %d", resp.StatusCode)
	}

	// Disassociate.
	resp, _ = ec2Call(t, srv, region, "DisassociateRouteTable", url.Values{"AssociationId": {assocID}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DisassociateRouteTable: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateSecurityGroup: %d %s", resp.StatusCode, body)
	}
	sgID := extractEC2Tag(body, "groupId")
	if !strings.HasPrefix(sgID, "sg-") {
		t.Fatalf("CreateSecurityGroup missing groupId: %s", body)
	}

	// Duplicate group_name in same VPC → 409.
	resp, _ = ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"web"}, "GroupDescription": {"x"}, "VpcId": {vpcID},
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate SG name in same VPC: got %d, want 409", resp.StatusCode)
	}

	// AuthorizeSecurityGroupIngress: tcp 443 from 0.0.0.0/0.
	resp, _ = ec2Call(t, srv, region, "AuthorizeSecurityGroupIngress", url.Values{
		"GroupId":                          {sgID},
		"IpPermissions.1.IpProtocol":       {"tcp"},
		"IpPermissions.1.FromPort":         {"443"},
		"IpPermissions.1.ToPort":           {"443"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("AuthorizeSecurityGroupIngress: %d", resp.StatusCode)
	}

	// DescribeSecurityGroups echoes the rule back.
	params := url.Values{}
	params.Set("GroupId.1", sgID)
	resp, body = ec2Call(t, srv, region, "DescribeSecurityGroups", params)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DescribeSecurityGroups: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "<cidrIp>0.0.0.0/0</cidrIp>") {
		t.Errorf("DescribeSecurityGroups missing cidrIp: %s", body)
	}
	if !strings.Contains(string(body), "<fromPort>443</fromPort>") {
		t.Errorf("DescribeSecurityGroups missing fromPort: %s", body)
	}

	// Authorize same rule twice → idempotent (dedup by key).
	for i := 0; i < 2; i++ {
		ec2Call(t, srv, region, "AuthorizeSecurityGroupIngress", url.Values{
			"GroupId":                          {sgID},
			"IpPermissions.1.IpProtocol":       {"tcp"},
			"IpPermissions.1.FromPort":         {"443"},
			"IpPermissions.1.ToPort":           {"443"},
			"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
		})
	}
	_, body = ec2Call(t, srv, region, "DescribeSecurityGroups", params)
	if strings.Count(string(body), "<cidrIp>0.0.0.0/0</cidrIp>") != 1 {
		t.Errorf("Authorize must be idempotent on identical rule; body=%s", body)
	}

	// Revoke removes it.
	resp, _ = ec2Call(t, srv, region, "RevokeSecurityGroupIngress", url.Values{
		"GroupId":                          {sgID},
		"IpPermissions.1.IpProtocol":       {"tcp"},
		"IpPermissions.1.FromPort":         {"443"},
		"IpPermissions.1.ToPort":           {"443"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("RevokeSecurityGroupIngress: %d", resp.StatusCode)
	}
	_, body = ec2Call(t, srv, region, "DescribeSecurityGroups", params)
	if strings.Contains(string(body), "<cidrIp>0.0.0.0/0</cidrIp>") {
		t.Errorf("Revoke should remove rule; body=%s", body)
	}

	// AuthorizeSecurityGroupEgress.
	resp, _ = ec2Call(t, srv, region, "AuthorizeSecurityGroupEgress", url.Values{
		"GroupId":                           {sgID},
		"IpPermissions.1.IpProtocol":        {"-1"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("AuthorizeSecurityGroupEgress: %d", resp.StatusCode)
	}
	_, body = ec2Call(t, srv, region, "DescribeSecurityGroups", params)
	if !strings.Contains(string(body), "<ipPermissionsEgress>") {
		t.Errorf("egress rule not echoed: %s", body)
	}

	// SG on missing VPC → 404.
	resp, _ = ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"x"}, "GroupDescription": {"x"}, "VpcId": {"vpc-missing"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("SG with missing VPC: got %d, want 404", resp.StatusCode)
	}

	// DeleteSecurityGroup.
	resp, _ = ec2Call(t, srv, region, "DeleteSecurityGroup", url.Values{"GroupId": {sgID}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteSecurityGroup: %d", resp.StatusCode)
	}
}

func TestEC2_EIPLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	resp, body := ec2Call(t, srv, region, "AllocateAddress", url.Values{"Domain": {"vpc"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("AllocateAddress: %d %s", resp.StatusCode, body)
	}
	allocID := extractEC2Tag(body, "allocationId")
	if !strings.HasPrefix(allocID, "eipalloc-") {
		t.Fatalf("AllocateAddress missing allocationId: %s", body)
	}
	publicIP := extractEC2Tag(body, "publicIp")
	if !strings.HasPrefix(publicIP, "203.0.113.") {
		t.Errorf("public IP must be in TEST-NET-3 range; got %q", publicIP)
	}

	// Domain=standard rejected (v1 supports vpc only).
	resp, _ = ec2Call(t, srv, region, "AllocateAddress", url.Values{"Domain": {"standard"}})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("AllocateAddress Domain=standard: got %d, want 409", resp.StatusCode)
	}

	// DescribeAddresses with allocationId filter.
	params := url.Values{}
	params.Set("AllocationId.1", allocID)
	resp, body = ec2Call(t, srv, region, "DescribeAddresses", params)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DescribeAddresses: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), allocID) {
		t.Errorf("DescribeAddresses missing %s: %s", allocID, body)
	}

	// ReleaseAddress.
	resp, _ = ec2Call(t, srv, region, "ReleaseAddress", url.Values{"AllocationId": {allocID}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ReleaseAddress: %d", resp.StatusCode)
	}
	resp, _ = ec2Call(t, srv, region, "ReleaseAddress", url.Values{"AllocationId": {allocID}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("ReleaseAddress on already-released: got %d, want 404", resp.StatusCode)
	}
}
