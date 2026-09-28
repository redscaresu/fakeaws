package handlers_test

import (
	"encoding/json"
	"encoding/xml"
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

// sgRuleSourceXML decodes any DescribeSecurityGroups rule source item;
// only the fields of that source's kind are set.
type sgRuleSourceXML struct {
	CidrIp       string `xml:"cidrIp"`
	CidrIpv6     string `xml:"cidrIpv6"`
	GroupId      string `xml:"groupId"`
	UserId       string `xml:"userId"`
	PrefixListId string `xml:"prefixListId"`
	Description  string `xml:"description"`
}

type sgPermXML struct {
	IpProtocol    string            `xml:"ipProtocol"`
	FromPort      int               `xml:"fromPort"`
	ToPort        int               `xml:"toPort"`
	IpRanges      []sgRuleSourceXML `xml:"ipRanges>item"`
	Ipv6Ranges    []sgRuleSourceXML `xml:"ipv6Ranges>item"`
	Groups        []sgRuleSourceXML `xml:"groups>item"`
	PrefixListIds []sgRuleSourceXML `xml:"prefixListIds>item"`
}

// newSGPair creates a VPC with two security groups and returns the
// server, the group under test and a peer group to reference.
func newSGPair(t *testing.T, region string) (srv *httptest.Server, sgID, peerID string) {
	t.Helper()
	srv = newTestServer(t, ":memory:")
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	ids := make([]string, 2)
	for i, name := range []string{"web", "lb"} {
		resp, body := ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
			"GroupName": {name}, "GroupDescription": {name}, "VpcId": {vpcID},
		})
		require.Equal(t, http.StatusOK, resp.StatusCode, "CreateSecurityGroup %s: %s", name, body)
		ids[i] = extractEC2Tag(body, "groupId")
	}
	return srv, ids[0], ids[1]
}

func sgAuthorize(t *testing.T, srv *httptest.Server, region, action, sgID string, params url.Values) {
	t.Helper()
	params.Set("GroupId", sgID)
	resp, body := ec2Call(t, srv, region, action, params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", action, body)
}

// describeSGRules returns sgID's ingress and egress permissions as
// DescribeSecurityGroups renders them.
func describeSGRules(t *testing.T, srv *httptest.Server, region, sgID string) (ingress, egress []sgPermXML) {
	t.Helper()
	resp, body := ec2Call(t, srv, region, "DescribeSecurityGroups", url.Values{"GroupId.1": {sgID}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeSecurityGroups: %s", body)
	var out struct {
		Groups []struct {
			Ingress []sgPermXML `xml:"ipPermissions>item"`
			Egress  []sgPermXML `xml:"ipPermissionsEgress>item"`
		} `xml:"securityGroupInfo>item"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "decode DescribeSecurityGroups: %s", body)
	require.Len(t, out.Groups, 1, "DescribeSecurityGroups: %s", body)
	return out.Groups[0].Ingress, out.Groups[0].Egress
}

// sgPermByPort returns the permission with the given from_port, or the
// zero value.
func sgPermByPort(perms []sgPermXML, port int) sgPermXML {
	for _, p := range perms {
		if p.FromPort == port {
			return p
		}
	}
	return sgPermXML{}
}

// sgStateRules returns sgID's ip_permissions and ip_permissions_egress
// from /mock/state as raw JSON.
func sgStateRules(t *testing.T, srv *httptest.Server, sgID string) (ingress, egress string) {
	t.Helper()
	resp, body := doGet(t, srv, "/mock/state/ec2")
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state/ec2: %s", body)
	var state struct {
		EC2 struct {
			SecurityGroups []struct {
				ID      string          `json:"id"`
				Ingress json.RawMessage `json:"ip_permissions"`
				Egress  json.RawMessage `json:"ip_permissions_egress"`
			} `json:"security_groups"`
		} `json:"ec2"`
	}
	require.NoError(t, json.Unmarshal(body, &state), "decode /mock/state: %s", body)
	for _, sg := range state.EC2.SecurityGroups {
		if sg.ID == sgID {
			return string(sg.Ingress), string(sg.Egress)
		}
	}
	require.FailNow(t, "security group missing from /mock/state", "%s in %s", sgID, body)
	return "", ""
}

func TestEC2_SecurityGroupFullIpPermissionsShape(t *testing.T) {
	const region = "us-east-1"
	const prefixList = "pl-0123456789abcdef0"
	srv, sgID, peerID := newSGPair(t, region)

	// tcp 22 from 0.0.0.0/0 and ::/0 in one permission, the way an
	// inline ingress block with cidr_blocks + ipv6_cidr_blocks sends it.
	sgAuthorize(t, srv, region, "AuthorizeSecurityGroupIngress", sgID, url.Values{
		"IpPermissions.1.IpProtocol":                   {"tcp"},
		"IpPermissions.1.FromPort":                     {"22"},
		"IpPermissions.1.ToPort":                       {"22"},
		"IpPermissions.1.IpRanges.1.CidrIp":            {"0.0.0.0/0"},
		"IpPermissions.1.Ipv6Ranges.1.CidrIpv6":        {"::/0"},
		"IpPermissions.2.IpProtocol":                   {"tcp"},
		"IpPermissions.2.FromPort":                     {"443"},
		"IpPermissions.2.ToPort":                       {"443"},
		"IpPermissions.2.Groups.1.GroupId":             {peerID},
		"IpPermissions.3.IpProtocol":                   {"tcp"},
		"IpPermissions.3.FromPort":                     {"5432"},
		"IpPermissions.3.ToPort":                       {"5432"},
		"IpPermissions.3.PrefixListIds.1.PrefixListId": {prefixList},
	})
	sgAuthorize(t, srv, region, "AuthorizeSecurityGroupEgress", sgID, url.Values{
		"IpPermissions.1.IpProtocol":        {"-1"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
	})

	ingress, _ := describeSGRules(t, srv, region, sgID)
	assert.Equal(t, []sgRuleSourceXML{{CidrIpv6: "::/0"}}, sgPermByPort(ingress, 22).Ipv6Ranges, "tcp 22 ::/0 in ipv6Ranges")
	assert.Equal(t, []sgRuleSourceXML{{GroupId: peerID}}, sgPermByPort(ingress, 443).Groups, "SG-to-SG rule as a UserIdGroupPair")
	assert.Equal(t, []sgRuleSourceXML{{PrefixListId: prefixList}}, sgPermByPort(ingress, 5432).PrefixListIds, "prefix list rule")

	stateIngress, stateEgress := sgStateRules(t, srv, sgID)
	assert.Contains(t, stateIngress, `"ipv6_ranges":[{"cidr_ipv6":"::/0","description":""}]`, "tcp 22 ::/0 in /mock/state")
	assert.JSONEq(t, `[{"ip_protocol":"-1","from_port":0,"to_port":0,
		"ip_ranges":[{"cidr_ip":"0.0.0.0/0","description":""}],
		"ipv6_ranges":[],"user_id_group_pairs":[],"prefix_list_ids":[]}]`, stateEgress, "allow-all egress in ip_permissions_egress")

	// Revoking ::/0 removes only that source; the IPv4 source on the
	// same permission stays.
	sgAuthorize(t, srv, region, "RevokeSecurityGroupIngress", sgID, url.Values{
		"IpPermissions.1.IpProtocol":            {"tcp"},
		"IpPermissions.1.FromPort":              {"22"},
		"IpPermissions.1.ToPort":                {"22"},
		"IpPermissions.1.Ipv6Ranges.1.CidrIpv6": {"::/0"},
	})
	stateIngress, _ = sgStateRules(t, srv, sgID)
	assert.Contains(t, stateIngress, `"ip_ranges":[{"cidr_ip":"0.0.0.0/0","description":""}],"ipv6_ranges":[]`, "revoke ::/0 keeps the IPv4 source in /mock/state")
}

// authorizeEverySourceKind puts one ingress permission carrying every
// source kind, each with its own description, and one egress rule.
func authorizeEverySourceKind(t *testing.T, srv *httptest.Server, region, sgID, peerID string) {
	t.Helper()
	sgAuthorize(t, srv, region, "AuthorizeSecurityGroupIngress", sgID, url.Values{
		"IpPermissions.1.IpProtocol":                   {"tcp"},
		"IpPermissions.1.FromPort":                     {"22"},
		"IpPermissions.1.ToPort":                       {"22"},
		"IpPermissions.1.IpRanges.1.CidrIp":            {"10.0.0.0/8"},
		"IpPermissions.1.IpRanges.1.Description":       {"office"},
		"IpPermissions.1.Ipv6Ranges.1.CidrIpv6":        {"::/0"},
		"IpPermissions.1.Ipv6Ranges.1.Description":     {"anywhere v6"},
		"IpPermissions.1.Groups.1.GroupId":             {peerID},
		"IpPermissions.1.Groups.1.UserId":              {"111122223333"},
		"IpPermissions.1.Groups.1.Description":         {"from lb"},
		"IpPermissions.1.PrefixListIds.1.PrefixListId": {"pl-0123456789abcdef0"},
		"IpPermissions.1.PrefixListIds.1.Description":  {"s3"},
	})
	sgAuthorize(t, srv, region, "AuthorizeSecurityGroupEgress", sgID, url.Values{
		"IpPermissions.1.IpProtocol":             {"-1"},
		"IpPermissions.1.IpRanges.1.CidrIp":      {"0.0.0.0/0"},
		"IpPermissions.1.IpRanges.1.Description": {"all out"},
	})
}

// TestEC2_SecurityGroupStateRulesGolden pins the exact /mock/state
// permission keys that state policies (open-ingress deny_state) read.
func TestEC2_SecurityGroupStateRulesGolden(t *testing.T) {
	const region = "us-east-1"
	srv, sgID, peerID := newSGPair(t, region)
	authorizeEverySourceKind(t, srv, region, sgID, peerID)

	ingress, egress := sgStateRules(t, srv, sgID)
	assert.JSONEq(t, strings.ReplaceAll(`[{
		"ip_protocol": "tcp", "from_port": 22, "to_port": 22,
		"ip_ranges": [{"cidr_ip": "10.0.0.0/8", "description": "office"}],
		"ipv6_ranges": [{"cidr_ipv6": "::/0", "description": "anywhere v6"}],
		"user_id_group_pairs": [{"group_id": "PEER", "user_id": "111122223333", "description": "from lb"}],
		"prefix_list_ids": [{"prefix_list_id": "pl-0123456789abcdef0", "description": "s3"}]
	}]`, "PEER", peerID), ingress)
	assert.JSONEq(t, `[{
		"ip_protocol": "-1", "from_port": 0, "to_port": 0,
		"ip_ranges": [{"cidr_ip": "0.0.0.0/0", "description": "all out"}],
		"ipv6_ranges": [], "user_id_group_pairs": [], "prefix_list_ids": []
	}]`, egress)
}

// TestContract_ec2_sg_rule_source_descriptions_round_trip pins
// CRITICAL[ec2-sg-rule-source-descriptions-round-trip] in ec2.go.
func TestContract_ec2_sg_rule_source_descriptions_round_trip(t *testing.T) {
	const region = "us-east-1"
	srv, sgID, peerID := newSGPair(t, region)
	authorizeEverySourceKind(t, srv, region, sgID, peerID)

	ingress, egress := describeSGRules(t, srv, region, sgID)
	assert.Equal(t, []sgPermXML{{
		IpProtocol:    "tcp",
		FromPort:      22,
		ToPort:        22,
		IpRanges:      []sgRuleSourceXML{{CidrIp: "10.0.0.0/8", Description: "office"}},
		Ipv6Ranges:    []sgRuleSourceXML{{CidrIpv6: "::/0", Description: "anywhere v6"}},
		Groups:        []sgRuleSourceXML{{GroupId: peerID, UserId: "111122223333", Description: "from lb"}},
		PrefixListIds: []sgRuleSourceXML{{PrefixListId: "pl-0123456789abcdef0", Description: "s3"}},
	}}, ingress)
	assert.Equal(t, []sgPermXML{{
		IpProtocol: "-1",
		IpRanges:   []sgRuleSourceXML{{CidrIp: "0.0.0.0/0", Description: "all out"}},
	}}, egress)
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
