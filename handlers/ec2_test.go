package handlers_test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
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

// ec2Error decodes an EC2 Query error body's first Code and Message.
func ec2Error(t *testing.T, body []byte) (code, message string) {
	t.Helper()
	var out struct {
		Code    string `xml:"Errors>Error>Code"`
		Message string `xml:"Errors>Error>Message"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "decode EC2 error: %s", body)
	return out.Code, out.Message
}

// sgPerm is one IpPermissions.1.* permission with an optional IPv4 source.
func sgPerm(proto, from, to, cidr string) url.Values {
	p := url.Values{"IpPermissions.1.IpProtocol": {proto}}
	if from != "" {
		p.Set("IpPermissions.1.FromPort", from)
		p.Set("IpPermissions.1.ToPort", to)
	}
	if cidr != "" {
		p.Set("IpPermissions.1.IpRanges.1.CidrIp", cidr)
	}
	return p
}

// TestEC2_SecurityGroupRuleValidation pins the InvalidParameterValue
// refusals. Messages are real EC2's where one has been seen:
//   - CIDR: "CIDR block ::/0 is malformed" (aws-cli#2846,
//     hashicorp/terraform#14382)
//   - port range: "TCP/UDP (from) port (-1) out of range" (aws-cli#1066)
//   - protocol: "Invalid value 'all' for IP protocol. Unknown protocol."
//     (terraform-provider-aws#1793); 'esp' likewise (hashicorp/terraform#9092)
//   - ICMP: "ICMP code (65535) out of range"
//     (terraform-aws-modules/terraform-aws-security-group#7)
//
// Neither AWS nor moto documents a message for FromPort > ToPort, or
// for ICMP type -1 with a specific code (the AuthorizeSecurityGroupIngress
// reference documents the rule), so those two are fakeaws's own.
func TestEC2_SecurityGroupRuleValidation(t *testing.T) {
	const region = "us-east-1"
	srv, sgID, _ := newSGPair(t, region)

	cases := []struct {
		name, action string
		params       url.Values
		fragment     string
	}{
		{"ipv4 /33", "AuthorizeSecurityGroupIngress", sgPerm("tcp", "22", "22", "10.0.0.0/33"), "CIDR block 10.0.0.0/33 is malformed"},
		{"bogus cidr", "AuthorizeSecurityGroupIngress", sgPerm("tcp", "22", "22", "bogus"), "CIDR block bogus is malformed"},
		{"bad ipv6 cidr", "AuthorizeSecurityGroupIngress", url.Values{
			"IpPermissions.1.IpProtocol":            {"tcp"},
			"IpPermissions.1.FromPort":              {"22"},
			"IpPermissions.1.ToPort":                {"22"},
			"IpPermissions.1.Ipv6Ranges.1.CidrIpv6": {"2001:db8::/129"},
		}, "CIDR block 2001:db8::/129 is malformed"},
		{"tcp 80->70", "AuthorizeSecurityGroupIngress", sgPerm("tcp", "80", "70", "10.0.0.0/8"), "Invalid port range 80-70 for protocol 'tcp'"},
		{"tcp 70000", "AuthorizeSecurityGroupIngress", sgPerm("tcp", "80", "70000", "10.0.0.0/8"), "TCP/UDP (to) port (70000) out of range"},
		{"protocol bogus", "AuthorizeSecurityGroupIngress", sgPerm("bogus", "80", "80", "10.0.0.0/8"), "Invalid value 'bogus' for IP protocol"},
		{"protocol all", "AuthorizeSecurityGroupIngress", sgPerm("all", "", "", "10.0.0.0/8"), "Invalid value 'all' for IP protocol"},
		{"protocol 256", "AuthorizeSecurityGroupIngress", sgPerm("256", "", "", "10.0.0.0/8"), "Invalid value '256' for IP protocol"},
		{"protocol 6 80->70", "AuthorizeSecurityGroupIngress", sgPerm("6", "80", "70", "10.0.0.0/8"), "Invalid port range 80-70 for protocol '6'"},
		{"icmp type 256", "AuthorizeSecurityGroupIngress", sgPerm("icmp", "256", "0", "10.0.0.0/8"), "ICMP type (256) out of range"},
		{"icmp all types, code 0", "AuthorizeSecurityGroupIngress", sgPerm("icmp", "-1", "0", "10.0.0.0/8"), "ICMP code (0) must be -1 when the ICMP type is -1"},
		{"egress icmpv6 code 300", "AuthorizeSecurityGroupEgress", url.Values{
			"IpPermissions.1.IpProtocol":            {"icmpv6"},
			"IpPermissions.1.FromPort":              {"128"},
			"IpPermissions.1.ToPort":                {"300"},
			"IpPermissions.1.Ipv6Ranges.1.CidrIpv6": {"::/0"},
		}, "ICMP code (300) out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.params.Set("GroupId", sgID)
			resp, body := ec2Call(t, srv, region, tc.action, tc.params)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s", body)
			code, msg := ec2Error(t, body)
			assert.Equal(t, "InvalidParameterValue", code)
			assert.Contains(t, msg, tc.fragment)
		})
	}

	ingress, egress := describeSGRules(t, srv, region, sgID)
	assert.Empty(t, ingress, "refused ingress rules must not be stored")
	assert.Empty(t, egress, "refused egress rules must not be stored")
}

// TestEC2_SecurityGroupRulePositiveControls pins the edge rules EC2
// accepts, so the validation above does not over-refuse.
func TestEC2_SecurityGroupRulePositiveControls(t *testing.T) {
	const region = "us-east-1"
	srv, sgID, _ := newSGPair(t, region)

	for name, params := range map[string]url.Values{
		"all protocols":  sgPerm("-1", "", "", "0.0.0.0/0"),
		"tcp 0-65535":    sgPerm("tcp", "0", "65535", "10.0.0.0/8"),
		"icmp -1/-1":     sgPerm("icmp", "-1", "-1", "10.0.0.0/8"),
		"protocol 6 80":  sgPerm("6", "80", "80", "10.0.0.0/8"),
		"ipv6 ::/0 icmp": {"IpPermissions.1.IpProtocol": {"icmpv6"}, "IpPermissions.1.FromPort": {"-1"}, "IpPermissions.1.ToPort": {"-1"}, "IpPermissions.1.Ipv6Ranges.1.CidrIpv6": {"::/0"}},
	} {
		t.Run(name, func(t *testing.T) {
			sgAuthorize(t, srv, region, "AuthorizeSecurityGroupIngress", sgID, params)
		})
	}
}

// TestEC2_SecurityGroupRuleSourceGroupMustExist: a same-account
// Groups.N.GroupId must name a group (moto's InvalidGroup.NotFound
// message); another account's reference is admitted unchecked.
func TestEC2_SecurityGroupRuleSourceGroupMustExist(t *testing.T) {
	const region = "us-east-1"
	srv, sgID, peerID := newSGPair(t, region)
	const missing = "sg-0000000000000dead"

	resp, body := ec2Call(t, srv, region, "AuthorizeSecurityGroupIngress", url.Values{
		"GroupId":                          {sgID},
		"IpPermissions.1.IpProtocol":       {"tcp"},
		"IpPermissions.1.FromPort":         {"443"},
		"IpPermissions.1.ToPort":           {"443"},
		"IpPermissions.1.Groups.1.GroupId": {missing},
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s", body)
	code, msg := ec2Error(t, body)
	assert.Equal(t, "InvalidGroup.NotFound", code)
	assert.Equal(t, "The security group '"+missing+"' does not exist", msg)

	sgAuthorize(t, srv, region, "AuthorizeSecurityGroupIngress", sgID, url.Values{
		"IpPermissions.1.IpProtocol":       {"tcp"},
		"IpPermissions.1.FromPort":         {"443"},
		"IpPermissions.1.ToPort":           {"443"},
		"IpPermissions.1.Groups.1.GroupId": {peerID},
	})
	sgAuthorize(t, srv, region, "AuthorizeSecurityGroupIngress", sgID, url.Values{
		"IpPermissions.1.IpProtocol":       {"tcp"},
		"IpPermissions.1.FromPort":         {"8443"},
		"IpPermissions.1.ToPort":           {"8443"},
		"IpPermissions.1.Groups.1.GroupId": {missing},
		"IpPermissions.1.Groups.1.UserId":  {"111122223333"},
	})
	ingress, _ := describeSGRules(t, srv, region, sgID)
	assert.Equal(t, []sgRuleSourceXML{{GroupId: peerID}}, sgPermByPort(ingress, 443).Groups, "existing group applies")
	assert.Equal(t, []sgRuleSourceXML{{GroupId: missing, UserId: "111122223333"}}, sgPermByPort(ingress, 8443).Groups, "other account admitted")
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

// instanceNet is a VPC with one subnet and two security groups.
type instanceNet struct {
	subnet string
	sgs    []string
}

func newInstanceNet(t *testing.T, srv *httptest.Server, region, vpcCidr, subnetCidr string) instanceNet {
	t.Helper()
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {vpcCidr}})
	vpcID := extractEC2Tag(body, "vpcId")
	resp, body := ec2Call(t, srv, region, "CreateSubnet", url.Values{"VpcId": {vpcID}, "CidrBlock": {subnetCidr}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateSubnet: %s", body)
	n := instanceNet{subnet: extractEC2Tag(body, "subnetId")}
	for _, name := range []string{"web", "ssh"} {
		resp, body := ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
			"GroupName": {name}, "GroupDescription": {name}, "VpcId": {vpcID},
		})
		require.Equal(t, http.StatusOK, resp.StatusCode, "CreateSecurityGroup: %s", body)
		n.sgs = append(n.sgs, extractEC2Tag(body, "groupId"))
	}
	return n
}

// nicParams is the NetworkInterface.1.* launch the provider sends when
// associate_public_ip_address is set.
func nicParams(subnet string, sgs []string, public bool) url.Values {
	p := url.Values{
		"ImageId":                                     {"ami-0abcd1234"},
		"InstanceType":                                {"t3.micro"},
		"NetworkInterface.1.DeviceIndex":              {"0"},
		"NetworkInterface.1.SubnetId":                 {subnet},
		"NetworkInterface.1.AssociatePublicIpAddress": {strconv.FormatBool(public)},
	}
	for i, sg := range sgs {
		p.Set(fmt.Sprintf("NetworkInterface.1.SecurityGroupId.%d", i+1), sg)
	}
	return p
}

func topLevelParams(subnet string, sgs []string) url.Values {
	p := url.Values{"ImageId": {"ami-0abcd1234"}, "InstanceType": {"t3.micro"}, "SubnetId": {subnet}}
	for i, sg := range sgs {
		p.Set(fmt.Sprintf("SecurityGroupId.%d", i+1), sg)
	}
	return p
}

func runInstance(t *testing.T, srv *httptest.Server, region string, params url.Values) string {
	t.Helper()
	resp, body := ec2Call(t, srv, region, "RunInstances", params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "RunInstances: %s", body)
	return extractEC2Tag(body, "instanceId")
}

type instanceNetXML struct {
	PrivateIpAddress string   `xml:"privateIpAddress"`
	IpAddress        string   `xml:"ipAddress"`
	SourceDestCheck  bool     `xml:"sourceDestCheck"`
	Groups           []string `xml:"groupSet>item>groupId"`
	ENIs             []struct {
		ID              string `xml:"networkInterfaceId"`
		PublicIp        string `xml:"association>publicIp"`
		SourceDestCheck bool   `xml:"sourceDestCheck"`
	} `xml:"networkInterfaceSet>item"`
}

// describeInstance returns id's network fields from DescribeInstances,
// and the raw body.
func describeInstance(t *testing.T, srv *httptest.Server, region, id string) (instanceNetXML, string) {
	t.Helper()
	resp, body := ec2Call(t, srv, region, "DescribeInstances", url.Values{"InstanceId.1": {id}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeInstances: %s", body)
	var out struct {
		Instances []instanceNetXML `xml:"reservationSet>item>instancesSet>item"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "decode DescribeInstances: %s", body)
	require.Len(t, out.Instances, 1, "DescribeInstances: %s", body)
	return out.Instances[0], string(body)
}

func describeENIIDs(t *testing.T, srv *httptest.Server, region string, params url.Values) []string {
	t.Helper()
	resp, body := ec2Call(t, srv, region, "DescribeNetworkInterfaces", params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeNetworkInterfaces: %s", body)
	var out struct {
		IDs []string `xml:"networkInterfaceSet>item>networkInterfaceId"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "decode DescribeNetworkInterfaces: %s", body)
	return out.IDs
}

type instanceStateXML struct {
	Instances []struct {
		ID        string `json:"id"`
		PublicIP  string `json:"public_ip"`
		PrivateIP string `json:"private_ip"`
	} `json:"instances"`
	ENIs []struct {
		ID         string `json:"id"`
		InstanceID string `json:"instance_id"`
	} `json:"network_interfaces"`
}

func instanceState(t *testing.T, srv *httptest.Server) instanceStateXML {
	t.Helper()
	resp, body := doGet(t, srv, "/mock/state/ec2")
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state/ec2: %s", body)
	var state struct {
		EC2 instanceStateXML `json:"ec2"`
	}
	require.NoError(t, json.Unmarshal(body, &state), "decode /mock/state: %s", body)
	require.NotNil(t, state.EC2.ENIs, "network_interfaces is a list, never null: %s", body)
	return state.EC2
}

// TestContract_ec2_instance_public_ip_from_primary_eni pins
// CRITICAL[ec2-instance-public-ip-from-primary-eni] in ec2.go.
func TestContract_ec2_instance_public_ip_from_primary_eni(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	n := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")

	id := runInstance(t, srv, region, nicParams(n.subnet, n.sgs, true))

	inst, body := describeInstance(t, srv, region, id)
	require.Len(t, inst.ENIs, 1, "networkInterfaceSet: %s", body)
	assert.NotEmpty(t, inst.IpAddress, "ipAddress: %s", body)
	assert.Equal(t, inst.ENIs[0].PublicIp, inst.IpAddress, "ipAddress is the primary ENI's association.publicIp")
	ip, err := netip.ParseAddr(inst.PrivateIpAddress)
	require.NoError(t, err, "privateIpAddress: %s", body)
	assert.True(t, netip.MustParsePrefix("10.0.1.0/24").Contains(ip), "privateIpAddress %s outside the subnet", ip)
	assert.Equal(t, n.sgs, inst.Groups, "instance groupSet is the two SGs")
}

// TestEC2_RunInstances_PublicIPOnlyWhenAsked: without
// AssociatePublicIpAddress=true there is no ipAddress and no
// association, in either launch form. Both land in one subnet, so
// their private IPs must differ.
func TestEC2_RunInstances_PublicIPOnlyWhenAsked(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	n := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")

	var privateIPs []string
	for name, params := range map[string]url.Values{
		"AssociatePublicIpAddress=false": nicParams(n.subnet, n.sgs, false),
		"top-level SubnetId":             topLevelParams(n.subnet, n.sgs),
	} {
		inst, body := describeInstance(t, srv, region, runInstance(t, srv, region, params))
		assert.NotContains(t, body, "<ipAddress>", name)
		assert.NotContains(t, body, "<association>", name)
		assert.Equal(t, n.sgs, inst.Groups, name)
		assert.NotEmpty(t, inst.PrivateIpAddress, name)
		privateIPs = append(privateIPs, inst.PrivateIpAddress)
	}
	assert.NotEqual(t, privateIPs[0], privateIPs[1], "two instances in one subnet share a private IP")
}

// TestEC2_RunInstances_NICFailsLikeTopLevel: both launch forms go
// through one subnet and SG-VPC check, so they fail with the same body.
func TestEC2_RunInstances_NICFailsLikeTopLevel(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	a := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")
	b := newInstanceNet(t, srv, region, "10.1.0.0/16", "10.1.1.0/24")

	for name, c := range map[string]instanceNet{
		"SG from another VPC": {subnet: a.subnet, sgs: b.sgs[:1]},
		"unknown subnet":      {subnet: "subnet-missing"},
	} {
		topResp, topBody := ec2Call(t, srv, region, "RunInstances", topLevelParams(c.subnet, c.sgs))
		nicResp, nicBody := ec2Call(t, srv, region, "RunInstances", nicParams(c.subnet, c.sgs, true))
		assert.Equal(t, http.StatusNotFound, topResp.StatusCode, "%s top-level: %s", name, topBody)
		assert.Equal(t, topResp.StatusCode, nicResp.StatusCode, name)
		assert.Equal(t, string(topBody), string(nicBody), name)
	}

	for param, value := range map[string]string{
		"SubnetId": a.subnet, "SecurityGroupId.1": a.sgs[0], "PrivateIpAddress": "10.0.1.50",
	} {
		both := nicParams(a.subnet, a.sgs, true)
		both.Set(param, value)
		resp, body := ec2Call(t, srv, region, "RunInstances", both)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s + NetworkInterface.1.*: %s", param, body)
		assert.Equal(t, "InvalidParameterCombination", extractEC2Tag(body, "Code"), param)
	}
}

// TestEC2_RunInstances_RequestedPrivateIP: a configured private_ip
// arrives as NetworkInterface.1.PrivateIpAddress or PrivateIpAddress
// and must be the address the instance gets.
func TestEC2_RunInstances_RequestedPrivateIP(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	n := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")

	nic := nicParams(n.subnet, n.sgs, true)
	nic.Set("NetworkInterface.1.PrivateIpAddress", "10.0.1.50")
	inst, _ := describeInstance(t, srv, region, runInstance(t, srv, region, nic))
	assert.Equal(t, "10.0.1.50", inst.PrivateIpAddress, "NetworkInterface.1.PrivateIpAddress")

	top := topLevelParams(n.subnet, n.sgs)
	top.Set("PrivateIpAddress", "10.0.1.51")
	inst, _ = describeInstance(t, srv, region, runInstance(t, srv, region, top))
	assert.Equal(t, "10.0.1.51", inst.PrivateIpAddress, "top-level PrivateIpAddress")

	resp, body := ec2Call(t, srv, region, "RunInstances", nic)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "private IP already in use: %s", body)
}

// TestEC2_ModifyInstanceAttributeSourceDestCheck: the provider sends
// source_dest_check = false through ModifyInstanceAttribute and reads
// it back from the instance and its primary ENI.
func TestEC2_ModifyInstanceAttributeSourceDestCheck(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	n := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")
	id := runInstance(t, srv, region, topLevelParams(n.subnet, n.sgs))
	inst, raw := describeInstance(t, srv, region, id)
	require.Len(t, inst.ENIs, 1, "networkInterfaceSet: %s", raw)
	assert.True(t, inst.SourceDestCheck, "sourceDestCheck defaults to true")

	resp, body := ec2Call(t, srv, region, "ModifyInstanceAttribute", url.Values{
		"InstanceId": {id}, "SourceDestCheck.Value": {"false"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "ModifyInstanceAttribute: %s", body)
	inst, raw = describeInstance(t, srv, region, id)
	require.Len(t, inst.ENIs, 1, "networkInterfaceSet: %s", raw)
	assert.False(t, inst.SourceDestCheck, "instance sourceDestCheck: %s", raw)
	assert.False(t, inst.ENIs[0].SourceDestCheck, "ENI sourceDestCheck: %s", raw)
}

func TestEC2_ModifyNetworkInterfaceAttributeGroups(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	a := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")
	b := newInstanceNet(t, srv, region, "10.1.0.0/16", "10.1.1.0/24")
	id := runInstance(t, srv, region, nicParams(a.subnet, a.sgs[:1], true))
	inst, raw := describeInstance(t, srv, region, id)
	require.Len(t, inst.ENIs, 1, "networkInterfaceSet: %s", raw)
	eniID := inst.ENIs[0].ID

	modify := func(sgID string) (*http.Response, []byte) {
		return ec2Call(t, srv, region, "ModifyNetworkInterfaceAttribute", url.Values{
			"NetworkInterfaceId": {eniID}, "SecurityGroupId.1": {sgID},
		})
	}
	resp, body := modify(a.sgs[1])
	require.Equal(t, http.StatusOK, resp.StatusCode, "ModifyNetworkInterfaceAttribute: %s", body)
	inst, _ = describeInstance(t, srv, region, id)
	assert.Equal(t, []string{a.sgs[1]}, inst.Groups, "instance groupSet follows the ENI")

	resp, body = modify(b.sgs[0])
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "SG from another VPC: %s", body)
	inst, _ = describeInstance(t, srv, region, id)
	assert.Equal(t, []string{a.sgs[1]}, inst.Groups, "refused change leaves groupSet alone")

	eniID = "eni-missing"
	resp, body = modify(a.sgs[0])
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "InvalidNetworkInterfaceID.NotFound", extractEC2Tag(body, "Code"))
}

func TestEC2_TerminateInstancesDeletesENI(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	n := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")
	id := runInstance(t, srv, region, nicParams(n.subnet, n.sgs, true))
	inst, raw := describeInstance(t, srv, region, id)
	require.Len(t, inst.ENIs, 1, "networkInterfaceSet: %s", raw)
	eniID := inst.ENIs[0].ID

	for name, params := range map[string]url.Values{
		"attachment.instance-id": {"Filter.1.Name": {"attachment.instance-id"}, "Filter.1.Value.1": {id}},
		"network-interface-id":   {"Filter.1.Name": {"network-interface-id"}, "Filter.1.Value.1": {eniID}},
		"subnet-id":              {"Filter.1.Name": {"subnet-id"}, "Filter.1.Value.1": {n.subnet}},
		"group-id":               {"Filter.1.Name": {"group-id"}, "Filter.1.Value.1": {n.sgs[1]}},
		"NetworkInterfaceId.1":   {"NetworkInterfaceId.1": {eniID}},
	} {
		assert.Equal(t, []string{eniID}, describeENIIDs(t, srv, region, params), name)
	}
	assert.Empty(t, describeENIIDs(t, srv, region, url.Values{
		"Filter.1.Name": {"attachment.instance-id"}, "Filter.1.Value.1": {"i-other"},
	}), "non-matching filter")
	resp, _ := ec2Call(t, srv, region, "DescribeNetworkInterfaces", url.Values{
		"Filter.1.Name": {"description"}, "Filter.1.Value.1": {"x"},
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "unsupported filter is refused, not ignored")

	state := instanceState(t, srv)
	require.Len(t, state.Instances, 1)
	assert.Equal(t, inst.IpAddress, state.Instances[0].PublicIP, "state public_ip")
	assert.Equal(t, inst.PrivateIpAddress, state.Instances[0].PrivateIP, "state private_ip")
	assert.Len(t, state.ENIs, 1, "state network_interfaces")

	resp, body := ec2Call(t, srv, region, "TerminateInstances", url.Values{"InstanceId.1": {id}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "TerminateInstances: %s", body)

	assert.Empty(t, describeENIIDs(t, srv, region, nil), "unfiltered DescribeNetworkInterfaces after terminate")
	resp, body = ec2Call(t, srv, region, "DescribeNetworkInterfaces", url.Values{"NetworkInterfaceId.1": {eniID}})
	assert.Equal(t, "InvalidNetworkInterfaceID.NotFound", extractEC2Tag(body, "Code"), "deleted ENI by id: %s", body)
	inst, _ = describeInstance(t, srv, region, id)
	state = instanceState(t, srv)
	assert.Empty(t, state.ENIs, "state network_interfaces after terminate")
	require.Len(t, state.Instances, 1)
	assert.Equal(t, inst.IpAddress, state.Instances[0].PublicIP, "state public_ip after terminate")
	assert.Equal(t, inst.PrivateIpAddress, state.Instances[0].PrivateIP, "state private_ip after terminate")
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

func setMapPublicIPOnLaunch(t *testing.T, srv *httptest.Server, region, subnet string, v bool) {
	t.Helper()
	resp, body := ec2Call(t, srv, region, "ModifySubnetAttribute", url.Values{
		"SubnetId": {subnet}, "MapPublicIpOnLaunch.Value": {strconv.FormatBool(v)},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "ModifySubnetAttribute: %s", body)
}

// TestEC2_ModifySubnetAttribute_MapPublicIpOnLaunch: the provider
// waits for DescribeSubnets to echo the value it set, so a no-op
// taints the subnet.
func TestEC2_ModifySubnetAttribute_MapPublicIpOnLaunch(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	n := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")

	describe := func() string {
		resp, body := ec2Call(t, srv, region, "DescribeSubnets", url.Values{"SubnetId.1": {n.subnet}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeSubnets: %s", body)
		return extractEC2Tag(body, "mapPublicIpOnLaunch")
	}
	assert.Equal(t, "false", describe(), "default")
	setMapPublicIPOnLaunch(t, srv, region, n.subnet, true)
	assert.Equal(t, "true", describe(), "after true")
	setMapPublicIPOnLaunch(t, srv, region, n.subnet, false)
	assert.Equal(t, "false", describe(), "after false")

	// Another attribute leaves the flag alone.
	setMapPublicIPOnLaunch(t, srv, region, n.subnet, true)
	resp, body := ec2Call(t, srv, region, "ModifySubnetAttribute", url.Values{
		"SubnetId": {n.subnet}, "EnableDns64.Value": {"false"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "ModifySubnetAttribute EnableDns64: %s", body)
	assert.Equal(t, "true", describe(), "after EnableDns64")

	resp, body = ec2Call(t, srv, region, "ModifySubnetAttribute", url.Values{
		"SubnetId": {"subnet-missing"}, "MapPublicIpOnLaunch.Value": {"true"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "unknown subnet: %s", body)
}

// TestEC2_RunInstances_MapPublicIpOnLaunch: a launch that does not
// set AssociatePublicIpAddress gets a public IP only in a flagged
// subnet; an explicit false still wins there.
func TestEC2_RunInstances_MapPublicIpOnLaunch(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	flagged := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")
	unflagged := newInstanceNet(t, srv, region, "10.1.0.0/16", "10.1.1.0/24")
	setMapPublicIPOnLaunch(t, srv, region, flagged.subnet, true)

	inst, body := describeInstance(t, srv, region, runInstance(t, srv, region, topLevelParams(flagged.subnet, flagged.sgs)))
	require.Len(t, inst.ENIs, 1, "networkInterfaceSet: %s", body)
	assert.NotEmpty(t, inst.IpAddress, "flagged subnet: %s", body)
	assert.Equal(t, inst.ENIs[0].PublicIp, inst.IpAddress, "flagged subnet")

	for name, params := range map[string]url.Values{
		"unflagged subnet":               topLevelParams(unflagged.subnet, unflagged.sgs),
		"flagged subnet, explicit false": nicParams(flagged.subnet, flagged.sgs, false),
	} {
		_, body := describeInstance(t, srv, region, runInstance(t, srv, region, params))
		assert.NotContains(t, body, "<ipAddress>", name)
		assert.NotContains(t, body, "<association>", name)
	}
}

// TestEC2_DescribeInstanceAttribute_UserData: RunInstances' base64
// UserData reads back unchanged, and an instance without any answers
// an empty <userData/>.
func TestEC2_DescribeInstanceAttribute_UserData(t *testing.T) {
	const region = "us-east-1"
	srv := newTestServer(t, ":memory:")
	n := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")
	userData := base64.StdEncoding.EncodeToString([]byte("#!/bin/bash\necho hello\n"))

	withData := topLevelParams(n.subnet, n.sgs)
	withData.Set("UserData", userData)
	for name, c := range map[string]struct {
		params url.Values
		want   string
	}{
		"with UserData":    {withData, userData},
		"without UserData": {topLevelParams(n.subnet, n.sgs), ""},
	} {
		id := runInstance(t, srv, region, c.params)
		resp, body := ec2Call(t, srv, region, "DescribeInstanceAttribute", url.Values{
			"InstanceId": {id}, "Attribute": {"userData"},
		})
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", name, body)
		var out struct {
			UserData *struct {
				Value *string `xml:"value"`
			} `xml:"userData"`
		}
		require.NoError(t, xml.Unmarshal(body, &out), "%s: %s", name, body)
		require.NotNil(t, out.UserData, "%s: <userData> missing: %s", name, body)
		if c.want == "" {
			assert.Nil(t, out.UserData.Value, "%s: <value> reads back as sha1(\"\"): %s", name, body)
			continue
		}
		require.NotNil(t, out.UserData.Value, "%s: %s", name, body)
		assert.Equal(t, c.want, *out.UserData.Value, name)
	}

	resp, body := ec2Call(t, srv, region, "DescribeInstanceAttribute", url.Values{
		"InstanceId": {"i-missing"}, "Attribute": {"userData"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "unknown instance: %s", body)
	assert.Equal(t, "InvalidInstanceID.NotFound", extractEC2Tag(body, "Code"))
}

// ----- Tags -----

// tagSetIn merges every <tagSet> in a Describe* body into key → value.
func tagSetIn(t *testing.T, body []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out
		}
		require.NoError(t, err, "decode %s", body)
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "tagSet" {
			var set struct {
				Items []struct {
					Key   string `xml:"key"`
					Value string `xml:"value"`
				} `xml:"item"`
			}
			require.NoError(t, dec.DecodeElement(&set, &se))
			for _, it := range set.Items {
				out[it.Key] = it.Value
			}
		}
	}
}

// tagParams flattens alternating key, value pairs under prefix.
func tagParams(p url.Values, prefix string, kv ...string) url.Values {
	for i := 0; i < len(kv); i += 2 {
		n := strconv.Itoa(i/2 + 1)
		p.Set(prefix+n+".Key", kv[i])
		p.Set(prefix+n+".Value", kv[i+1])
	}
	return p
}

func withTagSpec(p url.Values, n int, resourceType string, kv ...string) url.Values {
	prefix := fmt.Sprintf("TagSpecification.%d.", n)
	p.Set(prefix+"ResourceType", resourceType)
	return tagParams(p, prefix+"Tag.", kv...)
}

type describeTag struct {
	ResourceId   string `xml:"resourceId"`
	ResourceType string `xml:"resourceType"`
	Key          string `xml:"key"`
	Value        string `xml:"value"`
}

func describeTags(t *testing.T, srv *httptest.Server, region string, params url.Values) []describeTag {
	t.Helper()
	resp, body := ec2Call(t, srv, region, "DescribeTags", params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeTags: %s", body)
	var out struct {
		Tags []describeTag `xml:"tagSet>item"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "DescribeTags: %s", body)
	return out.Tags
}

// taggedKind creates one resource of a type with the given
// TagSpecification tags and describes it by id.
type taggedKind struct {
	resourceType string
	create       func(t *testing.T, srv *httptest.Server, tags ...string) string
	describe     func(id string) (string, url.Values)
}

const tagRegion = "us-east-1"

func createOK(t *testing.T, srv *httptest.Server, action, idTag string, params url.Values) string {
	t.Helper()
	resp, body := ec2Call(t, srv, tagRegion, action, params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", action, body)
	id := extractEC2Tag(body, idTag)
	require.NotEmpty(t, id, "%s: %s", action, body)
	return id
}

func tagVPC(t *testing.T, srv *httptest.Server) string {
	return createOK(t, srv, "CreateVpc", "vpcId", url.Values{"CidrBlock": {"10.0.0.0/16"}})
}

var taggedKinds = []taggedKind{
	{"vpc", func(t *testing.T, srv *httptest.Server, tags ...string) string {
		return createOK(t, srv, "CreateVpc", "vpcId", withTagSpec(url.Values{"CidrBlock": {"10.0.0.0/16"}}, 1, "vpc", tags...))
	}, func(string) (string, url.Values) { return "DescribeVpcs", nil }},
	{"subnet", func(t *testing.T, srv *httptest.Server, tags ...string) string {
		return createOK(t, srv, "CreateSubnet", "subnetId",
			withTagSpec(url.Values{"VpcId": {tagVPC(t, srv)}, "CidrBlock": {"10.0.1.0/24"}}, 1, "subnet", tags...))
	}, func(id string) (string, url.Values) { return "DescribeSubnets", url.Values{"SubnetId.1": {id}} }},
	{"internet-gateway", func(t *testing.T, srv *httptest.Server, tags ...string) string {
		return createOK(t, srv, "CreateInternetGateway", "internetGatewayId", withTagSpec(url.Values{}, 1, "internet-gateway", tags...))
	}, func(string) (string, url.Values) { return "DescribeInternetGateways", nil }},
	{"route-table", func(t *testing.T, srv *httptest.Server, tags ...string) string {
		return createOK(t, srv, "CreateRouteTable", "routeTableId", withTagSpec(url.Values{"VpcId": {tagVPC(t, srv)}}, 1, "route-table", tags...))
	}, func(id string) (string, url.Values) { return "DescribeRouteTables", url.Values{"RouteTableId.1": {id}} }},
	{"security-group", func(t *testing.T, srv *httptest.Server, tags ...string) string {
		return createOK(t, srv, "CreateSecurityGroup", "groupId", withTagSpec(url.Values{
			"GroupName": {"app"}, "GroupDescription": {"app"}, "VpcId": {tagVPC(t, srv)},
		}, 1, "security-group", tags...))
	}, func(id string) (string, url.Values) { return "DescribeSecurityGroups", url.Values{"GroupId.1": {id}} }},
	{"instance", func(t *testing.T, srv *httptest.Server, tags ...string) string {
		n := newInstanceNet(t, srv, tagRegion, "10.0.0.0/16", "10.0.1.0/24")
		p := withTagSpec(nicParams(n.subnet, n.sgs[:1], false), 1, "instance", tags...)
		return runInstance(t, srv, tagRegion, withTagSpec(p, 2, "volume", "Owner", "platform"))
	}, func(id string) (string, url.Values) { return "DescribeInstances", url.Values{"InstanceId.1": {id}} }},
}

func describedTags(t *testing.T, srv *httptest.Server, k taggedKind, id string) map[string]string {
	t.Helper()
	action, params := k.describe(id)
	resp, body := ec2Call(t, srv, tagRegion, action, params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", action, body)
	require.Contains(t, string(body), id, "%s", action)
	return tagSetIn(t, body)
}

// keyPairKind is outside taggedKinds: DescribeKeyPairs carries no
// ownerId. Its tag calls name it by KeyPairId, not by name.
var keyPairKind = taggedKind{"key-pair", func(t *testing.T, srv *httptest.Server, tags ...string) string {
	return createOK(t, srv, "ImportKeyPair", "keyPairId", withTagSpec(url.Values{
		"KeyName": {"tagged"}, "PublicKeyMaterial": {"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterial"},
	}, 1, "key-pair", tags...))
}, func(string) (string, url.Values) { return "DescribeKeyPairs", url.Values{"KeyName.1": {"tagged"}} }}

func TestEC2_TagsRoundTripPerResourceType(t *testing.T) {
	for _, k := range append(slices.Clone(taggedKinds), keyPairKind) {
		t.Run(k.resourceType, func(t *testing.T) {
			srv := newTestServer(t, ":memory:")
			id := k.create(t, srv, "Name", "v1", "env", "dev", "team", "x")
			assert.Equal(t, map[string]string{"Name": "v1", "env": "dev", "team": "x"},
				describedTags(t, srv, k, id), "TagSpecification in tagSet")

			resp, body := ec2Call(t, srv, tagRegion, "CreateTags",
				tagParams(url.Values{"ResourceId.1": {id}}, "Tag.", "Name", "v2", "extra", ""))
			require.Equal(t, http.StatusOK, resp.StatusCode, "CreateTags: %s", body)
			assert.Equal(t, map[string]string{"Name": "v2", "env": "dev", "team": "x", "extra": ""},
				describedTags(t, srv, k, id), "CreateTags adds and overwrites")

			resp, body = ec2Call(t, srv, tagRegion, "DeleteTags", url.Values{
				"ResourceId.1": {id}, "Tag.1.Key": {"env"}, "Tag.2.Key": {"team"}, "Tag.2.Value": {"wrong"},
			})
			require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteTags: %s", body)
			assert.Equal(t, map[string]string{"Name": "v2", "team": "x", "extra": ""},
				describedTags(t, srv, k, id), "key-only removes; a mismatched value keeps the tag")

			resp, body = ec2Call(t, srv, tagRegion, "DeleteTags", tagParams(url.Values{"ResourceId.1": {id}}, "Tag.", "team", "x"))
			require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteTags: %s", body)
			assert.Equal(t, map[string]string{"Name": "v2", "extra": ""},
				describedTags(t, srv, k, id), "key+value removes")

			got := describeTags(t, srv, tagRegion, url.Values{
				"Filter.1.Name": {"resource-id"}, "Filter.1.Value.1": {id},
				"Filter.2.Name": {"key"}, "Filter.2.Value.1": {"Name"},
			})
			assert.Equal(t, []describeTag{{ResourceId: id, ResourceType: k.resourceType, Key: "Name", Value: "v2"}}, got, "DescribeTags")
		})
	}
}

// TestEC2_DescribeCarriesOwnerID: the provider builds the internet
// gateway, route table and security group ARNs from the described
// ownerId and stores it as owner_id, so an empty one leaves both
// without the account.
func TestEC2_DescribeCarriesOwnerID(t *testing.T) {
	for _, k := range taggedKinds {
		t.Run(k.resourceType, func(t *testing.T) {
			srv := newTestServer(t, ":memory:")
			id := k.create(t, srv)
			action, params := k.describe(id)
			resp, body := ec2Call(t, srv, tagRegion, action, params)
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", action, body)
			assert.Equal(t, awsproto.FakeAccountID, extractEC2Tag(body, "ownerId"), "%s: %s", action, body)
		})
	}
}

func TestEC2_TagsNetworkInterfaceSpecAndFilters(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	n := newInstanceNet(t, srv, tagRegion, "10.0.0.0/16", "10.0.1.0/24")
	id := runInstance(t, srv, tagRegion, withTagSpec(withTagSpec(nicParams(n.subnet, n.sgs[:1], false),
		1, "instance", "Name", "web"), 2, "network-interface", "Name", "web-eni"))
	inst, raw := describeInstance(t, srv, tagRegion, id)
	require.Len(t, inst.ENIs, 1, "networkInterfaceSet: %s", raw)
	eniID := inst.ENIs[0].ID

	got := describeTags(t, srv, tagRegion, url.Values{"Filter.1.Name": {"resource-type"}, "Filter.1.Value.1": {"network-interface"}})
	assert.Equal(t, []describeTag{{ResourceId: eniID, ResourceType: "network-interface", Key: "Name", Value: "web-eni"}}, got)
	assert.Len(t, describeTags(t, srv, tagRegion, nil), 2, "unfiltered")
	assert.Empty(t, describeTags(t, srv, "eu-west-1", nil), "other region")

	resp, _ := ec2Call(t, srv, tagRegion, "DescribeTags", url.Values{"Filter.1.Name": {"tag:Name"}, "Filter.1.Value.1": {"web"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "unsupported filter is refused, not ignored")

	resp, body := ec2Call(t, srv, tagRegion, "TerminateInstances", url.Values{"InstanceId.1": {id}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "TerminateInstances: %s", body)
	got = describeTags(t, srv, tagRegion, nil)
	assert.Equal(t, []describeTag{{ResourceId: id, ResourceType: "instance", Key: "Name", Value: "web"}}, got,
		"the deleted ENI's tags go; the terminated instance keeps its own")
}

func TestEC2_TagsUnknownResource(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	for id, code := range map[string]string{
		"vpc-doesnotexist":    "InvalidVpcID.NotFound",
		"subnet-doesnotexist": "InvalidSubnetID.NotFound",
		"igw-doesnotexist":    "InvalidInternetGatewayID.NotFound",
		"rtb-doesnotexist":    "InvalidRouteTableID.NotFound",
		"sg-doesnotexist":     "InvalidGroup.NotFound",
		"i-doesnotexist":      "InvalidInstanceID.NotFound",
		"eni-doesnotexist":    "InvalidNetworkInterfaceID.NotFound",
		"vol-0123":            "InvalidID",
	} {
		for _, action := range []string{"CreateTags", "DeleteTags"} {
			resp, body := ec2Call(t, srv, tagRegion, action, tagParams(url.Values{"ResourceId.1": {id}}, "Tag.", "k", "v"))
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s %s: %s", action, id, body)
			assert.Equal(t, code, extractEC2Tag(body, "Code"), "%s %s: %s", action, id, body)
		}
	}

	// A known VPC alongside an unknown one tags neither.
	vpc := tagVPC(t, srv)
	resp, _ := ec2Call(t, srv, tagRegion, "CreateTags",
		tagParams(url.Values{"ResourceId.1": {vpc}, "ResourceId.2": {"vpc-doesnotexist"}}, "Tag.", "k", "v"))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, describeTags(t, srv, tagRegion, nil))
}

func TestEC2_TagSpecificationWrongResourceType(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := ec2Call(t, srv, tagRegion, "CreateVpc",
		withTagSpec(url.Values{"CidrBlock": {"10.0.0.0/16"}}, 1, "subnet", "Name", "x"))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "CreateVpc: %s", body)
	assert.Equal(t, "InvalidParameterValue", extractEC2Tag(body, "Code"), "%s", body)
	_, body = ec2Call(t, srv, tagRegion, "DescribeVpcs", nil)
	assert.NotContains(t, string(body), "vpc-", "refused create leaves no VPC")
}

func TestEC2_TagsGoWithResourceAndReset(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	vpc := taggedKinds[0].create(t, srv, "Name", "a")
	subnet := createOK(t, srv, "CreateSubnet", "subnetId",
		withTagSpec(url.Values{"VpcId": {vpc}, "CidrBlock": {"10.0.1.0/24"}}, 1, "subnet", "Name", "b"))
	require.Len(t, describeTags(t, srv, tagRegion, nil), 2)

	resp, body := ec2Call(t, srv, tagRegion, "DeleteSubnet", url.Values{"SubnetId": {subnet}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteSubnet: %s", body)
	resp, body = ec2Call(t, srv, tagRegion, "DeleteVpc", url.Values{"VpcId": {vpc}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteVpc: %s", body)
	assert.Empty(t, describeTags(t, srv, tagRegion, nil), "deleting a resource deletes its tags")

	taggedKinds[0].create(t, srv, "Name", "c")
	require.Len(t, describeTags(t, srv, tagRegion, nil), 1)
	resp, _ = doPost(t, srv, "/mock/reset")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, describeTags(t, srv, tagRegion, nil), "/mock/reset clears tags")
}

func TestContract_ec2_tags_round_trip_in_tagset(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	k := taggedKinds[0]
	id := k.create(t, srv, "Name", "v1", "gone", "soon")
	resp, _ := ec2Call(t, srv, tagRegion, "DeleteTags", url.Values{"ResourceId.1": {id}, "Tag.1.Key": {"gone"}, "Tag.1.Value": {"soon"}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp, _ = ec2Call(t, srv, tagRegion, "CreateTags", tagParams(url.Values{"ResourceId.1": {id}}, "Tag.", "Name", "v2"))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, map[string]string{"Name": "v2"}, describedTags(t, srv, k, id))
}
