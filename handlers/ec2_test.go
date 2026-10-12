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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/repository"
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
	// No CidrBlock is refused as unmodelled: AWS also takes Ipv4IpamPoolId.
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "CreateVpc with no CidrBlock")
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
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "unsupported filter is refused, not ignored")

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

// The AWS scope reap deletes a key pair by the KeyPairId the sweep lists.
func TestEC2_DeleteKeyPairByID(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	resp, body := ec2Call(t, srv, region, "ImportKeyPair", url.Values{
		"KeyName":           {"deploy"},
		"PublicKeyMaterial": {"ssh-rsa AAAAB3NzaC1yc2E"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "ImportKeyPair: %s", body)
	id := extractEC2Tag(body, "keyPairId")
	require.NotEmpty(t, id, "ImportKeyPair: %s", body)

	resp, body = ec2Call(t, srv, region, "DeleteKeyPair", url.Values{"KeyPairId": {id}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteKeyPair by id: %s", body)

	resp, body = ec2Call(t, srv, region, "DescribeKeyPairs", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotContains(t, string(body), id, "DescribeKeyPairs after the delete: %s", body)

	resp, _ = ec2Call(t, srv, region, "DeleteKeyPair", url.Values{"KeyPairId": {id}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteKeyPair of a missing id")
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
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "AllocateAddress Domain=standard")

	// DescribeAddresses with allocationId filter.
	params := url.Values{}
	params.Set("AllocationId.1", allocID)
	resp, body = ec2Call(t, srv, region, "DescribeAddresses", params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeAddresses: %s", body)
	assert.Contains(t, string(body), allocID, "DescribeAddresses missing %s: %s", allocID, body)

	// aws_eip reads its domain-name attribute after every describe;
	// fakeaws sets no ptrRecord.
	resp, body = ec2Call(t, srv, region, "DescribeAddressesAttribute", url.Values{"AllocationId.1": {allocID}, "Attribute": {"domain-name"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeAddressesAttribute: %s", body)
	assert.Equal(t, allocID, extractEC2Tag(body, "allocationId"), "DescribeAddressesAttribute: %s", body)
	assert.NotContains(t, string(body), "ptrRecord", "DescribeAddressesAttribute: %s", body)

	// ReleaseAddress.
	resp, _ = ec2Call(t, srv, region, "ReleaseAddress", url.Values{"AllocationId": {allocID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ReleaseAddress")
	for _, action := range []string{"DescribeAddresses", "DescribeAddressesAttribute"} {
		resp, body = ec2Call(t, srv, region, action, params)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s after release", action)
		assert.Contains(t, string(body), "<Code>InvalidAllocationID.NotFound</Code>", "%s: %s", action, body)
	}
	resp, body = ec2Call(t, srv, region, "ReleaseAddress", url.Values{"AllocationId": {allocID}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "ReleaseAddress on already-released")
	assert.Contains(t, string(body), "<Code>InvalidAllocationID.NotFound</Code>", "ReleaseAddress on already-released: %s", body)
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
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "unknown instance: %s", body)
	assert.Equal(t, "InvalidInstanceID.NotFound", extractEC2Tag(body, "Code"))
}

func TestContract_ec2_instance_attributes_from_rows(t *testing.T) {
	const region = "us-east-1"
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	n := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")
	attribute := func(id, name string) (*http.Response, []byte) {
		return ec2Call(t, srv, region, "DescribeInstanceAttribute", url.Values{"InstanceId": {id}, "Attribute": {name}})
	}
	values := func(id string) map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, name := range []string{"sourceDestCheck", "disableApiTermination", "disableApiStop", "instanceInitiatedShutdownBehavior", "ebsOptimized"} {
			resp, body := attribute(id, name)
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", name, body)
			out[name] = extractEC2Tag(body, "value")
		}
		return out
	}

	// The provider sends EbsOptimized=false and DisableApiTermination=false on every launch.
	launch := topLevelParams(n.subnet, n.sgs)
	launch.Set("EbsOptimized", "false")
	launch.Set("DisableApiTermination", "false")
	id := runInstance(t, srv, region, launch)
	assert.Equal(t, map[string]string{
		"sourceDestCheck": "true", "disableApiTermination": "false", "disableApiStop": "false",
		"instanceInitiatedShutdownBehavior": "stop", "ebsOptimized": "false",
	}, values(id), "AWS's defaults when nothing is set")
	_, raw := describeInstance(t, srv, region, id)
	assert.NotContains(t, raw, "ebsOptimized", "DescribeInstances is unchanged when nothing is set")

	modified := map[string]string{
		"sourceDestCheck": "false", "disableApiTermination": "true", "disableApiStop": "true",
		"instanceInitiatedShutdownBehavior": "terminate", "ebsOptimized": "false",
	}
	for _, param := range []string{"SourceDestCheck", "DisableApiTermination", "DisableApiStop", "InstanceInitiatedShutdownBehavior"} {
		attr := strings.ToLower(param[:1]) + param[1:]
		resp, body := ec2Call(t, srv, region, "ModifyInstanceAttribute", url.Values{"InstanceId": {id}, param + ".Value": {modified[attr]}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "ModifyInstanceAttribute %s: %s", param, body)
		assert.Equal(t, modified[attr], values(id)[attr], "%s after ModifyInstanceAttribute", attr)
	}
	assert.Equal(t, modified, values(id), "one ModifyInstanceAttribute leaves the others")

	launch = topLevelParams(n.subnet, n.sgs)
	for param, v := range map[string]string{"DisableApiTermination": "true", "DisableApiStop": "true", "EbsOptimized": "true", "InstanceInitiatedShutdownBehavior": "terminate"} {
		launch.Set(param, v)
	}
	launched := runInstance(t, srv, region, launch)
	assert.Equal(t, map[string]string{
		"sourceDestCheck": "true", "disableApiTermination": "true", "disableApiStop": "true",
		"instanceInitiatedShutdownBehavior": "terminate", "ebsOptimized": "true",
	}, values(launched), "what RunInstances set")
	_, raw = describeInstance(t, srv, region, launched)
	assert.Contains(t, raw, "<ebsOptimized>true</ebsOptimized>", "DescribeInstances")

	resp, body := ec2Call(t, srv, region, "ModifyInstanceAttribute", url.Values{"InstanceId": {launched}, "DisableApiTermination.Value": {"false"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "ModifyInstanceAttribute: %s", body)
	resp, body = ec2Call(t, srv, region, "TerminateInstances", url.Values{"InstanceId.1": {launched}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "TerminateInstances: %s", body)
	resp, body = attribute(launched, "sourceDestCheck")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "terminated: %s", body)
	assert.NotContains(t, string(body), "sourceDestCheck", "a terminated instance has no ENI")

	for _, name := range []string{"userData", "disableApiTermination", "sourceDestCheck", "instanceType"} {
		resp, body := attribute("i-missing", name)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "unknown instance %s: %s", name, body)
		assert.Equal(t, "InvalidInstanceID.NotFound", extractEC2Tag(body, "Code"), name)
		assert.Equal(t, "answered-from-rows", lastClass(t, srv), name)
	}
	resp, body = ec2Call(t, srv, region, "DescribeInstances", url.Values{"InstanceId.1": {"i-missing"}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "DescribeInstances unknown instance: %s", body)
	assert.Equal(t, "InvalidInstanceID.NotFound", extractEC2Tag(body, "Code"), "DescribeInstances")

	for _, name := range []string{"instanceType", "groupSet", "kernel"} {
		resp, body := attribute(id, name)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%q: %s", name, body)
		assert.Equal(t, "DescribeInstanceAttribute: not modelled by fakeaws: Attribute="+name, extractEC2Tag(body, "Message"), name)
		assert.Equal(t, "filter-refused", lastClass(t, srv), name)
	}
	resp, body = ec2Call(t, srv, region, "DescribeInstanceAttribute", url.Values{"InstanceId": {id}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "no Attribute: %s", body)
	assert.Equal(t, "MissingParameter", extractEC2Tag(body, "Code"), "no Attribute")
	assert.Equal(t, "answered-from-rows", lastClass(t, srv), "no Attribute")

	// disableApiStop guards nothing: StopInstances is not modelled. A
	// StopInstances handler must refuse an instance whose disableApiStop
	// is set before this assertion changes.
	resp, body = ec2Call(t, srv, region, "StopInstances", url.Values{"InstanceId.1": {id}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "StopInstances: %s", body)
	assert.Equal(t, "not-modelled-404", lastClass(t, srv), "StopInstances")
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

// eipKind is outside taggedKinds too: DescribeAddresses carries no
// ownerId. Its tag calls name it by allocation id.
var eipKind = taggedKind{"elastic-ip", func(t *testing.T, srv *httptest.Server, tags ...string) string {
	return createOK(t, srv, "AllocateAddress", "allocationId", withTagSpec(url.Values{"Domain": {"vpc"}}, 1, "elastic-ip", tags...))
}, func(id string) (string, url.Values) { return "DescribeAddresses", url.Values{"AllocationId.1": {id}} }}

func TestEC2_TagsRoundTripPerResourceType(t *testing.T) {
	for _, k := range append(slices.Clone(taggedKinds), keyPairKind, eipKind) {
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
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "unsupported filter is refused, not ignored")

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
	} {
		for _, action := range []string{"CreateTags", "DeleteTags"} {
			resp, body := ec2Call(t, srv, tagRegion, action, tagParams(url.Values{"ResourceId.1": {id}}, "Tag.", "k", "v"))
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s %s: %s", action, id, body)
			assert.Equal(t, code, extractEC2Tag(body, "Code"), "%s %s: %s", action, id, body)
		}
	}
	for _, action := range []string{"CreateTags", "DeleteTags"} {
		resp, body := ec2Call(t, srv, tagRegion, action, tagParams(url.Values{"ResourceId.1": {"vol-0123"}}, "Tag.", "k", "v"))
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s on a type fakeaws does not tag: %s", action, body)
		assert.Equal(t, action+": not modelled by fakeaws: tags on vol-0123", extractEC2Tag(body, "Message"), action)
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

	eip := eipKind.create(t, srv, "Name", "e")
	resp, body = ec2Call(t, srv, tagRegion, "ReleaseAddress", url.Values{"AllocationId": {eip}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "ReleaseAddress: %s", body)
	assert.Empty(t, describeTags(t, srv, tagRegion, nil), "releasing an EIP deletes its tags")

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

// ----- The AWS scope sweep's Describes, through aws-sdk-go-v2 -----

const sweepRegion = "us-east-1"

// sweepClient is an aws-sdk-go-v2 EC2 client on srv in sweepRegion.
func sweepClient(srv *httptest.Server) *ec2.Client {
	return ec2.New(ec2.Options{
		Region:           sweepRegion,
		BaseEndpoint:     aws.String(srv.URL + "/ec2/region/" + sweepRegion),
		Credentials:      aws.AnonymousCredentials{},
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
	})
}

// sweepFilter is a tag Filter.N no sweep resource matches: a Describe
// that models tags answers it empty, the rest refuse it.
var sweepFilter = []ec2types.Filter{{Name: aws.String("tag:Owner"), Values: []string{"sweep"}}}

// assertRefused asserts err is fakeaws's 501 for an unmodelled param.
func assertRefused(t *testing.T, err error, msg string) {
	t.Helper()
	var re *awshttp.ResponseError
	if assert.ErrorAs(t, err, &re, msg) {
		assert.Equal(t, http.StatusNotImplemented, re.HTTPStatusCode(), msg)
	}
}

func TestRegressionSweepDescribeAddressesListsEveryAddress(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	c, ctx := sweepClient(srv), t.Context()
	alloc, err := c.AllocateAddress(ctx, &ec2.AllocateAddressInput{Domain: ec2types.DomainTypeVpc})
	require.NoError(t, err)
	resp, body := ec2Call(t, srv, "eu-west-2", "AllocateAddress", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "AllocateAddress eu-west-2: %s", body)

	out, err := c.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	require.NoError(t, err)
	require.Len(t, out.Addresses, 1, "the region's address, not eu-west-2's")
	assert.Equal(t, aws.ToString(alloc.AllocationId), aws.ToString(out.Addresses[0].AllocationId))

	out, err = c.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{Filters: sweepFilter})
	require.NoError(t, err)
	assert.Empty(t, out.Addresses, "no address is tagged Owner=sweep")
	out, err = c.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{PublicIps: []string{aws.ToString(alloc.PublicIp)}})
	require.NoError(t, err)
	require.Len(t, out.Addresses, 1)
	assert.Equal(t, aws.ToString(alloc.AllocationId), aws.ToString(out.Addresses[0].AllocationId))
	// UNVERIFIED(aws-code): InvalidAddress.NotFound from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
	_, err = c.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{PublicIps: []string{"198.51.100.1"}})
	var re *awshttp.ResponseError
	require.ErrorAs(t, err, &re)
	assert.Equal(t, http.StatusBadRequest, re.HTTPStatusCode())
	assert.ErrorContains(t, err, "InvalidAddress.NotFound")
}

func TestRegressionSweepDescribeSecurityGroupsListsEveryGroup(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	c, ctx := sweepClient(srv), t.Context()
	vpc, err := c.CreateVpc(ctx, &ec2.CreateVpcInput{CidrBlock: aws.String("10.0.0.0/16")})
	require.NoError(t, err)
	sg, err := c.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName: aws.String("web"), Description: aws.String("web"), VpcId: vpc.Vpc.VpcId,
	})
	require.NoError(t, err)

	out, err := c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{MaxResults: aws.Int32(1000)})
	require.NoError(t, err)
	require.Len(t, out.SecurityGroups, 1)
	assert.Equal(t, aws.ToString(sg.GroupId), aws.ToString(out.SecurityGroups[0].GroupId))
	assert.Equal(t, "web", aws.ToString(out.SecurityGroups[0].GroupName))

	out, err = c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{Filters: sweepFilter})
	require.NoError(t, err)
	assert.Empty(t, out.SecurityGroups, "no group is tagged Owner=sweep")
	_, err = c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupNames: []string{"web"}})
	var re *awshttp.ResponseError
	require.ErrorAs(t, err, &re)
	assert.Equal(t, http.StatusBadRequest, re.HTTPStatusCode())
	assert.ErrorContains(t, err, "VPCIdNotSpecified", "fakeaws has no default VPC to resolve GroupName.N in")
}

func TestRegressionSweepDescribeImagesOwnerSelf(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	c, ctx := sweepClient(srv), t.Context()
	imageIDs := func(in *ec2.DescribeImagesInput) []string {
		t.Helper()
		out, err := c.DescribeImages(ctx, in)
		require.NoError(t, err)
		var ids []string
		for _, img := range out.Images {
			ids = append(ids, aws.ToString(img.ImageId))
		}
		return ids
	}

	assert.Empty(t, imageIDs(&ec2.DescribeImagesInput{Owners: []string{"self"}, IncludeDisabled: aws.Bool(true)}),
		"none of the fixtures is the caller's")
	assert.Equal(t, []string{handlers.AL2023AMIID}, imageIDs(&ec2.DescribeImagesInput{ImageIds: []string{handlers.AL2023AMIID}}))
	assert.ElementsMatch(t, []string{"ami-0ubuntu2004", "ami-0ubuntu2204"},
		imageIDs(&ec2.DescribeImagesInput{Owners: []string{"099720109477"}}), "Owner.N keeps that owner's images")
}

func TestRegressionSweepDescribesNeverCreated(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	c, ctx := sweepClient(srv), t.Context()
	describes := map[string]func([]ec2types.Filter) (any, error){
		"DescribeVolumes": func(f []ec2types.Filter) (any, error) {
			out, err := c.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{Filters: f, MaxResults: aws.Int32(500)})
			if err != nil {
				return nil, err
			}
			return out.Volumes, nil
		},
		"DescribeNatGateways": func(f []ec2types.Filter) (any, error) {
			out, err := c.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{Filter: f, MaxResults: aws.Int32(1000)})
			if err != nil {
				return nil, err
			}
			return out.NatGateways, nil
		},
		"DescribeSnapshots": func(f []ec2types.Filter) (any, error) {
			out, err := c.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{Filters: f, OwnerIds: []string{"self"}, MaxResults: aws.Int32(1000)})
			if err != nil {
				return nil, err
			}
			return out.Snapshots, nil
		},
		"DescribeLaunchTemplates": func(f []ec2types.Filter) (any, error) {
			out, err := c.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{Filters: f, MaxResults: aws.Int32(200)})
			if err != nil {
				return nil, err
			}
			return out.LaunchTemplates, nil
		},
	}
	for action, describe := range describes {
		t.Run(action, func(t *testing.T) {
			list, err := describe(nil)
			require.NoError(t, err)
			assert.NotNil(t, list, "the result set element is present")
			assert.Empty(t, list)
			_, err = describe(sweepFilter)
			assertRefused(t, err, "Filter.N")
		})
	}
}

func TestRegressionSweepTerminatedInstanceENIGone(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	c, ctx := sweepClient(srv), t.Context()
	vpc, err := c.CreateVpc(ctx, &ec2.CreateVpcInput{CidrBlock: aws.String("10.0.0.0/16")})
	require.NoError(t, err)
	subnet, err := c.CreateSubnet(ctx, &ec2.CreateSubnetInput{VpcId: vpc.Vpc.VpcId, CidrBlock: aws.String("10.0.1.0/24")})
	require.NoError(t, err)
	run, err := c.RunInstances(ctx, &ec2.RunInstancesInput{
		ImageId: aws.String(handlers.AL2023AMIID), InstanceType: ec2types.InstanceTypeT3Micro,
		SubnetId: subnet.Subnet.SubnetId, MinCount: aws.Int32(1), MaxCount: aws.Int32(1),
	})
	require.NoError(t, err)
	require.Len(t, run.Instances, 1)
	id := aws.ToString(run.Instances[0].InstanceId)

	enis, err := c.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{})
	require.NoError(t, err)
	require.Len(t, enis.NetworkInterfaces, 1, "the running instance's ENI")
	require.NotNil(t, enis.NetworkInterfaces[0].Attachment)
	assert.Equal(t, id, aws.ToString(enis.NetworkInterfaces[0].Attachment.InstanceId))

	_, err = c.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{id}})
	require.NoError(t, err)
	enis, err = c.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{})
	require.NoError(t, err)
	assert.Empty(t, enis.NetworkInterfaces, "a terminated instance's ENI is gone")
	insts, err := c.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{id}})
	require.NoError(t, err)
	require.Len(t, insts.Reservations, 1)
	require.Len(t, insts.Reservations[0].Instances, 1)
	require.NotNil(t, insts.Reservations[0].Instances[0].State)
	assert.Equal(t, ec2types.InstanceStateNameTerminated, insts.Reservations[0].Instances[0].State.Name)
}

// TestEC2_DescribeVpcsAndIGWsByID: the provider looks a VPC or internet
// gateway up by VpcId.N / InternetGatewayId.N and wants exactly that
// one back, so answering every one in the region broke it once a
// second existed.
func TestEC2_DescribeVpcsAndIGWsByID(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	vpc := tagVPC(t, srv)
	tagVPC(t, srv)
	igw := createOK(t, srv, "CreateInternetGateway", "internetGatewayId", nil)
	createOK(t, srv, "CreateInternetGateway", "internetGatewayId", nil)

	for _, tc := range []struct{ action, param, id, idTag, missing, code string }{
		{"DescribeVpcs", "VpcId.1", vpc, "vpcId", "vpc-doesnotexist", "InvalidVpcID.NotFound"},
		{"DescribeInternetGateways", "InternetGatewayId.1", igw, "internetGatewayId", "igw-doesnotexist", "InvalidInternetGatewayID.NotFound"},
	} {
		_, body := ec2Call(t, srv, tagRegion, tc.action, nil)
		assert.Equal(t, 2, strings.Count(string(body), "<"+tc.idTag+">"), "%s with no ids lists all: %s", tc.action, body)

		resp, body := ec2Call(t, srv, tagRegion, tc.action, url.Values{tc.param: {tc.id}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", tc.action, body)
		assert.Equal(t, 1, strings.Count(string(body), "<"+tc.idTag+">"), "%s by id: %s", tc.action, body)
		assert.Equal(t, tc.id, extractEC2Tag(body, tc.idTag))

		resp, body = ec2Call(t, srv, tagRegion, tc.action, url.Values{tc.param: {tc.missing}})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s missing: %s", tc.action, body)
		assert.Equal(t, tc.code, extractEC2Tag(body, "Code"))
	}
}

// TestEC2_DescribeRouteTablesFilters: the provider finds a route table
// association by Filter association.route-table-association-id and a
// VPC's main route table by vpc-id + association.main, and wants one
// result, so ignoring the filters broke both once a second VPC existed.
func TestEC2_DescribeRouteTablesFilters(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	var vpcs, rts []string
	for range 2 {
		vpc := tagVPC(t, srv)
		vpcs = append(vpcs, vpc)
		rts = append(rts, createOK(t, srv, "CreateRouteTable", "routeTableId", url.Values{"VpcId": {vpc}}))
	}
	subnet := createOK(t, srv, "CreateSubnet", "subnetId", url.Values{"VpcId": {vpcs[0]}, "CidrBlock": {"10.0.1.0/24"}})
	assoc := createOK(t, srv, "AssociateRouteTable", "associationId", url.Values{"RouteTableId": {rts[0]}, "SubnetId": {subnet}})

	for name, tc := range map[string]struct {
		params url.Values
		want   []string
	}{
		"no filter":      {nil, rts},
		"by association": {ec2FilterParams("association.route-table-association-id", assoc), rts[:1]},
		"by vpc":         {ec2FilterParams("vpc-id", vpcs[1]), rts[1:]},
		"main of a vpc":  {ec2FilterParams("association.main", "true", "vpc-id", vpcs[0]), nil},
	} {
		resp, body := ec2Call(t, srv, tagRegion, "DescribeRouteTables", tc.params)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", name, body)
		for _, rt := range rts {
			assert.Equal(t, slices.Contains(tc.want, rt), strings.Contains(string(body), "<routeTableId>"+rt+"</routeTableId>"), "%s: %s in %s", name, rt, body)
		}
	}

	resp, _ := ec2Call(t, srv, tagRegion, "DescribeRouteTables", ec2FilterParams("route.gateway-id", "igw-1"))
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "an unmodelled filter is refused, not ignored")
}

// ec2DescribeArms are the Describe names in handleEC2's case arms at
// fakeaws 1993583, ec2DescribeExempt the three among them that take no
// Filter in the AWS API.
var (
	ec2DescribeArms = []string{
		"DescribeVpcs", "DescribeVpcAttribute", "DescribeSubnets", "DescribeNetworkInterfaces",
		"DescribeInternetGateways", "DescribeRouteTables", "DescribeAddresses", "DescribeAddressesAttribute",
		"DescribeInstances", "DescribeKeyPairs", "DescribeImages", "DescribeVolumes", "DescribeNatGateways",
		"DescribeSnapshots", "DescribeLaunchTemplates", "DescribeInstanceTypes", "DescribeTags",
		"DescribeInstanceAttribute", "DescribeSecurityGroups",
	}
	ec2DescribeExempt = []string{"DescribeVpcAttribute", "DescribeInstanceAttribute", "DescribeAddressesAttribute"}
)

// handleEC2DescribeNames scans every case arm of handleEC2 in ec2.go
// and returns every Describe name on each case line.
func handleEC2DescribeNames(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("ec2.go")
	require.NoError(t, err)
	_, body, found := strings.Cut(string(src), "func (app *Application) handleEC2(")
	require.True(t, found, "no handleEC2 in ec2.go")
	body, _, _ = strings.Cut(body, "\n}\n")
	var names []string
	for _, line := range regexp.MustCompile(`(?m)^\s*case\s+(.+):`).FindAllStringSubmatch(body, -1) {
		for _, m := range regexp.MustCompile(`"(Describe\w*)"`).FindAllStringSubmatch(line[1], -1) {
			names = append(names, m[1])
		}
	}
	return names
}

func TestContract_ec2_describe_filter_never_ignored(t *testing.T) {
	scanned := handleEC2DescribeNames(t)
	require.ElementsMatch(t, ec2DescribeArms, scanned, "handleEC2's Describe arms")
	for _, name := range ec2DescribeExempt {
		require.Contains(t, scanned, name, "exemption %s is no longer an arm", name)
	}

	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	probes := []struct {
		name   string
		params url.Values
	}{
		{"fakeaws-no-such-filter", url.Values{"Filter.1.Name": {"fakeaws-no-such-filter"}, "Filter.1.Value.1": {"x"}}},
		{"FakeawsNoSuchParam.N", url.Values{"FakeawsNoSuchParam.1": {"x"}}},
	}
	for _, action := range ec2DescribeArms {
		if slices.Contains(ec2DescribeExempt, action) {
			continue
		}
		for _, probe := range probes {
			resp, body := ec2Call(t, srv, tagRegion, action, probe.params)
			assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s %s: %s", action, probe.name, body)
			assert.Equal(t, "NotImplemented", extractEC2Tag(body, "Code"), "%s %s", action, probe.name)
			assert.Equal(t, action+": not modelled by fakeaws: "+probe.name, extractEC2Tag(body, "Message"), "%s %s", action, probe.name)
			assert.Equal(t, "filter-refused", lastClass(t, srv), "%s %s", action, probe.name)
		}
	}
}

func TestContract_ec2_filter_and_across_or_within(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	a, b := tagVPC(t, srv), tagVPC(t, srv)
	rtA := createOK(t, srv, "CreateRouteTable", "routeTableId", url.Values{"VpcId": {a}})
	rtB := createOK(t, srv, "CreateRouteTable", "routeTableId", url.Values{"VpcId": {b}})
	subnet := createOK(t, srv, "CreateSubnet", "subnetId", url.Values{"VpcId": {b}, "CidrBlock": {"10.0.1.0/24"}})

	routeTables := func(params url.Values) []string {
		resp, body := ec2Call(t, srv, tagRegion, "DescribeRouteTables", params)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%v: %s", params, body)
		var out struct {
			IDs []string `xml:"routeTableSet>item>routeTableId"`
		}
		require.NoError(t, xml.Unmarshal(body, &out), "%s", body)
		return out.IDs
	}
	assert.Empty(t, routeTables(url.Values{
		"Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {a},
		"Filter.2.Name": {"vpc-id"}, "Filter.2.Value.1": {b},
	}), "vpc-id A in Filter.1 and B in Filter.2: no table is in both")
	assert.ElementsMatch(t, []string{rtA, rtB}, routeTables(url.Values{
		"Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {a}, "Filter.1.Value.2": {b},
	}), "Value.1 A and Value.2 B in one Filter.N: either")

	resp, body := ec2Call(t, srv, tagRegion, "DescribeSubnets", url.Values{
		"Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {"vpc-matches-nothing"}, "Filter.1.Value.2": {b},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeSubnets: %s", body)
	var subnets struct {
		IDs []string `xml:"subnetSet>item>subnetId"`
	}
	require.NoError(t, xml.Unmarshal(body, &subnets), "%s", body)
	assert.Equal(t, []string{subnet}, subnets.IDs, "a Value.2 that matches is read")
}

func TestContract_ec2_filter_wildcard_crosses_slash(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const name = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04"
	resp, body := ec2Call(t, srv, tagRegion, "CreateTags", tagParams(url.Values{"ResourceId.1": {tagVPC(t, srv)}}, "Tag.", "Name", name))
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateTags: %s", body)

	for pattern, want := range map[string]bool{
		"ubuntu/images/*":      true,
		"ubuntu/*-22.0?":       true,
		"*/hvm-ssd/*":          true,
		"ubuntu/other/*":       false,
		"ubuntu/images/hvm-ss": false,
	} {
		tags := describeTags(t, srv, tagRegion, url.Values{"Filter.1.Name": {"value"}, "Filter.1.Value.1": {pattern}})
		assert.Equal(t, want, len(tags) == 1 && tags[0].Value == name, "%s: %v", pattern, tags)
	}
}

// TestEC2_DescribeRefusesUnreadParams: a Describe param fakeaws does
// not read is refused by name, never ignored.
func TestEC2_DescribeRefusesUnreadParams(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	for _, c := range []struct {
		action, param, name string
	}{
		{"DescribeImages", "ExecutableBy.1", "ExecutableBy.N"},
		{"DescribeKeyPairs", "IncludePublicKey", "IncludePublicKey"},
		{"DescribeAddresses", "PublicIp.x", "PublicIp.x"},
		{"DescribeSubnets", "SubnetId.x", "SubnetId.x"},
	} {
		resp, body := ec2Call(t, srv, tagRegion, c.action, url.Values{c.param: {"all"}})
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s %s: %s", c.action, c.param, body)
		assert.Equal(t, c.action+": not modelled by fakeaws: "+c.name, extractEC2Tag(body, "Message"), c.action)
	}
}

// TestEC2_DescribeImagesReadsIncludeDeprecated: data.aws_ami always
// sends IncludeDeprecated; no image is deprecated, so it is read, not
// refused.
func TestEC2_DescribeImagesReadsIncludeDeprecated(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := ec2Call(t, srv, tagRegion, "DescribeImages", url.Values{"Owner.1": {"099720109477"}, "IncludeDeprecated": {"false"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	var out struct {
		IDs []string `xml:"imagesSet>item>imageId"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "%s", body)
	assert.ElementsMatch(t, []string{"ami-0ubuntu2004", "ami-0ubuntu2204"}, out.IDs)
}

// describeImageIDs answers DescribeImages with params, which must
// succeed, as its image ids.
func describeImageIDs(t *testing.T, srv *httptest.Server, params url.Values) []string {
	t.Helper()
	resp, body := ec2Call(t, srv, tagRegion, "DescribeImages", params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%v: %s", params, body)
	var out struct {
		IDs []string `xml:"imagesSet>item>imageId"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "%s", body)
	return out.IDs
}

// TestEC2_DescribeImagesFilters: each imageFilters name selects the
// fixtures whose row answers it; Owner.1=self with a name filter keeps
// none, and a filter on a field AMI rows do not store, or
// ExecutableBy.N, is refused by name.
func TestEC2_DescribeImagesFilters(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	filter := func(name, value string) url.Values {
		return url.Values{"Filter.1.Name": {name}, "Filter.1.Value.1": {value}}
	}
	amazon := []string{"ami-0abcd1234", handlers.AL2023AMIID}
	ubuntu := []string{"ami-0ubuntu2004", "ami-0ubuntu2204"}
	for _, c := range []struct {
		name, value string
		want        []string
	}{
		{"image-id", "ami-0ubuntu2204", ubuntu[1:]},
		{"owner-id", "099720109477", ubuntu},
		{"owner-alias", "amazon", amazon},
		{"virtualization-type", "hvm", append(amazon, ubuntu...)},
		{"root-device-name", "/dev/sda1", ubuntu},
		{"state", "available", append(amazon, ubuntu...)},
		{"image-type", "machine", append(amazon, ubuntu...)},
		{"image-type", "kernel", nil},
		{"tag:Name", "*", nil},
	} {
		assert.ElementsMatch(t, c.want, describeImageIDs(t, srv, filter(c.name, c.value)), "%s=%s", c.name, c.value)
	}

	self := filter("name", "*")
	self.Set("Owner.1", "self")
	assert.Empty(t, describeImageIDs(t, srv, self), "none of the fixtures is the caller's")

	for _, c := range []struct {
		params url.Values
		name   string
	}{
		{filter("architecture", "x86_64"), "architecture"},
		{url.Values{"ExecutableBy.1": {"all"}}, "ExecutableBy.N"},
	} {
		resp, body := ec2Call(t, srv, tagRegion, "DescribeImages", c.params)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s: %s", c.name, body)
		assert.Equal(t, "DescribeImages: not modelled by fakeaws: "+c.name, extractEC2Tag(body, "Message"), c.name)
		assert.Equal(t, "filter-refused", lastClass(t, srv), c.name)
	}
}

// TestEC2_DescribeIdListReadsEveryIndex: VpcId.1 and VpcId.3 with no
// VpcId.2 look up both.
func TestEC2_DescribeIdListReadsEveryIndex(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	a, b := tagVPC(t, srv), tagVPC(t, srv)
	resp, body := ec2Call(t, srv, tagRegion, "DescribeVpcs", url.Values{"VpcId.1": {a}, "VpcId.3": {b}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	var out struct {
		IDs []string `xml:"vpcSet>item>vpcId"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "%s", body)
	assert.Equal(t, []string{a, b}, out.IDs)
}

func TestContract_ec2_filter_refusal_names_every_name_sorted(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	params := url.Values{
		"Filter.1.Name": {"zz"}, "Filter.1.Value.1": {"x"},
		"Filter.2.Name": {"aa"}, "Filter.2.Value.1": {"x"},
		"Filter.3.Name": {"zz"}, "Filter.3.Value.1": {"x"},
		"Filter.4.Name": {"vpc-id"}, "Filter.4.Value.1": {"vpc-1"},
		"GroupName.2": {"web"}, "GroupName.1": {"db"}, "AllowReassociation": {"true"},
	}
	resp, first := ec2Call(t, srv, tagRegion, "DescribeRouteTables", params)
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", first)
	assert.Equal(t, "NotImplemented", extractEC2Tag(first, "Code"))
	assert.Equal(t, "DescribeRouteTables: not modelled by fakeaws: AllowReassociation, GroupName.N, aa, zz", extractEC2Tag(first, "Message"))
	for range 20 {
		_, body := ec2Call(t, srv, tagRegion, "DescribeRouteTables", params)
		assert.Equal(t, string(first), string(body), "the same request reads the same refusal")
	}
}

// TestEC2_AnswersStoredAccount: under a stored account every ownerId,
// the instance's ENI and its IAM instance profile Arn carry that
// account, and so does every ARN in the ec2 block of /mock/state.
func TestEC2_AnswersStoredAccount(t *testing.T) {
	_, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AccountID: otherAccount})
	const region = "us-east-1"
	owned := func(action string, params url.Values) []byte {
		t.Helper()
		resp, body := ec2Call(t, srv, region, action, params)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", action, body)
		assert.Equal(t, otherAccount, extractEC2Tag(body, "ownerId"), "%s: %s", action, body)
		assert.NotContains(t, string(body), awsproto.FakeAccountID, action)
		return body
	}

	vpcID := extractEC2Tag(owned("CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}}), "vpcId")
	owned("DescribeVpcs", url.Values{"VpcId.1": {vpcID}})
	subnetID := extractEC2Tag(owned("CreateSubnet", url.Values{"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"}}), "subnetId")
	owned("CreateInternetGateway", nil)
	rtID := extractEC2Tag(owned("CreateRouteTable", url.Values{"VpcId": {vpcID}}), "routeTableId")
	owned("DescribeRouteTables", url.Values{"RouteTableId.1": {rtID}})
	// CreateSecurityGroup answers only the group id.
	sgID := createOK(t, srv, "CreateSecurityGroup", "groupId", url.Values{
		"GroupName": {"acct"}, "GroupDescription": {"acct"}, "VpcId": {vpcID},
	})
	owned("DescribeSecurityGroups", url.Values{"GroupId.1": {sgID}})

	resp, body := iamCall(t, srv, "CreateInstanceProfile", url.Values{"InstanceProfileName": {"acct-profile"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateInstanceProfile: %s", body)
	profileARN := xmlExtract(body, "Arn")
	require.Equal(t, "arn:aws:iam::"+otherAccount+":instance-profile/acct-profile", profileARN, "%s", body)

	params := topLevelParams(subnetID, []string{sgID})
	params.Set("IamInstanceProfile.Name", "acct-profile")
	run := owned("RunInstances", params)
	instID := extractEC2Tag(run, "instanceId")
	for action, body := range map[string][]byte{
		"RunInstances":      run,
		"DescribeInstances": owned("DescribeInstances", url.Values{"InstanceId.1": {instID}}),
	} {
		type instanceXML struct {
			ProfileARN string `xml:"iamInstanceProfile>arn"`
			ENIs       []struct {
				OwnerId         string `xml:"ownerId"`
				InstanceOwnerId string `xml:"attachment>instanceOwnerId"`
			} `xml:"networkInterfaceSet>item"`
		}
		var out struct {
			Run      []instanceXML `xml:"instancesSet>item"`
			Describe []instanceXML `xml:"reservationSet>item>instancesSet>item"`
		}
		require.NoError(t, xml.Unmarshal(body, &out), "%s: %s", action, body)
		insts := append(out.Run, out.Describe...)
		require.Len(t, insts, 1, "%s: %s", action, body)
		assert.Equal(t, profileARN, insts[0].ProfileARN, action)
		require.Len(t, insts[0].ENIs, 1, "%s: %s", action, body)
		assert.Equal(t, otherAccount, insts[0].ENIs[0].OwnerId, action)
		assert.Equal(t, otherAccount, insts[0].ENIs[0].InstanceOwnerId, action)
	}

	resp, body = doGet(t, srv, "/mock/state/ec2")
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state/ec2: %s", body)
	var state struct {
		EC2 map[string][]map[string]any `json:"ec2"`
	}
	require.NoError(t, json.Unmarshal(body, &state), "%s", body)
	for _, collection := range []string{"vpcs", "subnets", "internet_gateways", "route_tables", "security_groups", "instances"} {
		rows := state.EC2[collection]
		require.NotEmpty(t, rows, collection)
		for _, row := range rows {
			assert.Contains(t, row["arn"], ":"+otherAccount+":", collection)
		}
	}
	assert.NotContains(t, string(body), awsproto.FakeAccountID)
}

// TestEC2_LazySeedUnderStoredAccount: a region outside boot's list
// gets the AMI fixtures on first use under the stored account, so
// RunInstances finds the AL2023 fixture there.
func TestEC2_LazySeedUnderStoredAccount(t *testing.T) {
	_, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AccountID: otherAccount})
	const region = "ap-south-1"
	n := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")
	params := topLevelParams(n.subnet, n.sgs[:1])
	params.Set("ImageId", handlers.AL2023AMIID)

	resp, body := ec2Call(t, srv, region, "RunInstances", params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "RunInstances: %s", body)
	assert.Equal(t, otherAccount, extractEC2Tag(body, "ownerId"), "%s", body)
}

func TestEC2_UnreadableIdentityIs500(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	_, err := app.Repository().DB().Exec(`DROP TABLE identity`)
	require.NoError(t, err)

	resp, body := ec2Call(t, srv, "us-east-1", "DescribeVpcs", nil)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "body=%s", body)
	assert.Contains(t, string(body), "<Code>InternalFailure</Code>")
	assert.NotContains(t, string(body), awsproto.FakeAccountID)
}

// markLoaded marks the file database at dbPath loaded through
// repository.New, as fakeaws-loader does, with no Application open.
func markLoaded(t *testing.T, dbPath string, loaded bool) {
	t.Helper()
	repo, err := repository.New(dbPath)
	require.NoError(t, err)
	require.NoError(t, repo.SetLoaded(loaded, awsproto.FakeAccountID))
	require.NoError(t, repo.Close())
}

func amiRows(t *testing.T, app *handlers.Application, region string) int {
	t.Helper()
	var n int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_amis WHERE region = ?`, region).Scan(&n))
	return n
}

func appLoaded(t *testing.T, app *handlers.Application) bool {
	t.Helper()
	loaded, err := app.Repository().Loaded()
	require.NoError(t, err)
	return loaded
}

// runInstanceWith runs one instance of ami in a fresh subnet.
func runInstanceWith(t *testing.T, srv *httptest.Server, region, ami string) (*http.Response, []byte) {
	t.Helper()
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {extractEC2Tag(body, "vpcId")}, "CidrBlock": {"10.0.1.0/24"},
	})
	return ec2Call(t, srv, region, "RunInstances", url.Values{
		"SubnetId": {extractEC2Tag(body, "subnetId")}, "ImageId": {ami}, "InstanceType": {"t3.micro"},
	})
}

func seedImageBody(ami string) string {
	return `{"ami_id":"` + ami + `","name":"loaded","region":"us-east-1","root_device_name":"/dev/xvda"}`
}

func TestContract_ami_fixtures_not_seeded_when_loaded(t *testing.T) {
	const region = "us-east-1"
	dbPath := filepath.Join(t.TempDir(), "test.db")
	markLoaded(t, dbPath, true)
	app, srv := newTestApp(t, dbPath)
	assert.Zero(t, amiRows(t, app, region), "boot seeds no fixture")

	resp, body := ec2Call(t, srv, region, "DescribeImages", url.Values{"ImageId.1": {handlers.AL2023AMIID}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeImages: %s", body)
	assert.Contains(t, string(body), "ResourceNotFoundException")
	assert.Zero(t, amiRows(t, app, region), "DescribeImages seeds no fixture")

	resp, body = runInstanceWith(t, srv, region, handlers.AL2023AMIID)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "RunInstances: %s", body)
	assert.Contains(t, string(body), "InvalidAMIID.NotFound")

	status, _, body := ssmGetValue(t, srv, al2023Parameter)
	assert.Equal(t, http.StatusBadRequest, status, "GetParameter: %s", body)
	assert.Contains(t, string(body), "ParameterNotFound")

	resp, body = doPostJSON(t, srv, "/mock/images", seedImageBody(handlers.AL2023AMIID))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "POST /mock/images fixture id: %s", body)

	const loadedAMI = "ami-0123456789abcdef0"
	resp, body = doPostJSON(t, srv, "/mock/images", seedImageBody(loadedAMI))
	require.Equal(t, http.StatusOK, resp.StatusCode, "POST /mock/images: %s", body)
	assert.Equal(t, 1, amiRows(t, app, region))
	resp, body = runInstanceWith(t, srv, region, loadedAMI)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "RunInstances %s: %s", loadedAMI, body)
}

// The loader writes the public al2023 parameter as a row (PutParameter
// refuses aws-prefixed names). GetParameter reads it under the same
// account-less ARN as the unloaded answer; it is not listed or deletable.
func TestAMIFixtures_LoadedAL2023ParameterRow(t *testing.T) {
	const loadedAMI = "ami-0123456789abcdef0"
	dbPath := filepath.Join(t.TempDir(), "test.db")
	markLoaded(t, dbPath, true)
	app, srv := newTestApp(t, dbPath)
	_, err := app.Repository().PutSSMParameter(awsproto.FakeAccountID, &repository.SSMParameterPut{
		Name: al2023Parameter, Type: "String", Value: loadedAMI, Region: "us-east-1", Now: "2026-10-12T00:00:00Z",
	}, false)
	require.NoError(t, err)

	resp, body := ssmCall(t, srv, "GetParameter", fmt.Sprintf(`{"Name":%q}`, al2023Parameter))
	require.Equal(t, http.StatusOK, resp.StatusCode, "GetParameter: %s", body)
	var got struct{ Parameter struct{ ARN, Value string } }
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, loadedAMI, got.Parameter.Value)
	assert.Equal(t, "arn:aws:ssm:us-east-1::parameter"+al2023Parameter, got.Parameter.ARN)

	resp, body = ssmCall(t, srv, "DescribeParameters", `{}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeParameters: %s", body)
	assert.NotContains(t, string(body), al2023Parameter, "DescribeParameters lists the public parameter")
	resp, body = doGet(t, srv, "/mock/state")
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state: %s", body)
	assert.NotContains(t, string(body), al2023Parameter, "/mock/state lists the public parameter")

	resp, body = ssmCall(t, srv, "DeleteParameter", fmt.Sprintf(`{"Name":%q}`, al2023Parameter))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "DeleteParameter: %s", body)
	assert.Contains(t, string(body), "ParameterNotFound")
	status, value, body := ssmGetValue(t, srv, al2023Parameter)
	assert.Equal(t, http.StatusOK, status, "GetParameter after DeleteParameter: %s", body)
	assert.Equal(t, loadedAMI, value, "DeleteParameter left the loader's row")
}

// Marking a database loaded deletes nothing: removing the fixtures
// seeded before is fakeaws-loader's job, in its replace transaction.
func TestAMIFixtures_MarkedLoadedLaterKeepsSeededFixtures(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	app, _ := newTestApp(t, dbPath)
	seeded := amiRows(t, app, "us-east-1")
	require.Positive(t, seeded, "unloaded boot seeds the fixtures")
	require.NoError(t, app.Close())

	markLoaded(t, dbPath, true)
	app, srv := newTestApp(t, dbPath)
	assert.Equal(t, seeded, amiRows(t, app, "us-east-1"))
	resp, body := ec2Call(t, srv, "us-east-1", "DescribeImages", url.Values{"ImageId.1": {handlers.AL2023AMIID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
}

func TestAMIFixtures_LoadedFlagLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	markLoaded(t, dbPath, true)
	app, srv := newTestApp(t, dbPath)

	resp, body := doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusOK, resp.StatusCode, "snapshot: %s", body)
	require.NoError(t, app.Repository().SetLoaded(false, awsproto.FakeAccountID))
	require.False(t, appLoaded(t, app))
	resp, body = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, resp.StatusCode, "restore: %s", body)
	assert.True(t, appLoaded(t, app), "restore brings back the snapshot's flag")

	require.NoError(t, app.Close())
	app, srv = newTestApp(t, dbPath)
	assert.True(t, appLoaded(t, app), "reopen keeps the flag")
	assert.Zero(t, amiRows(t, app, "us-east-1"), "reopen seeds no fixture")

	resp, body = doPost(t, srv, "/mock/reset")
	require.Equal(t, http.StatusOK, resp.StatusCode, "reset: %s", body)
	assert.False(t, appLoaded(t, app), "reset clears the flag")
	resp, body = ec2Call(t, srv, "us-east-1", "DescribeImages", url.Values{"ImageId.1": {handlers.AL2023AMIID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages after reset seeds the fixtures: %s", body)
}

// The loaded column is dropped rather than the identity table: without
// the table the account read fails before any fixture site is reached,
// and repository.New would recreate it on reopen.
func TestAMIFixtures_UnreadableLoadedFlagSeedsNothing(t *testing.T) {
	const dropLoaded = `ALTER TABLE identity DROP COLUMN loaded`
	app, srv := newTestApp(t, ":memory:")
	_, err := app.Repository().DB().Exec(dropLoaded)
	require.NoError(t, err)

	ec2Call(t, srv, "sa-east-1", "DescribeImages", nil)
	assert.Zero(t, amiRows(t, app, "sa-east-1"), "lazy seed with an unreadable flag")
	status, _, body := ssmGetValue(t, srv, al2023Parameter)
	assert.Equal(t, http.StatusInternalServerError, status, "GetParameter: %s", body)
	status, _, body = ssmGetValue(t, srv, "/app/missing")
	assert.Equal(t, http.StatusBadRequest, status, "GetParameter of a stored name does not read the flag: %s", body)
	resp, body := doPostJSON(t, srv, "/mock/images", seedImageBody("ami-0123456789abcdef0"))
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "POST /mock/images: %s", body)

	dbPath := filepath.Join(t.TempDir(), "test.db")
	repo, err := repository.New(dbPath)
	require.NoError(t, err)
	_, err = repo.DB().Exec(dropLoaded)
	require.NoError(t, err)
	require.NoError(t, repo.Close())
	_, err = handlers.NewApplication(handlers.Options{DBPath: dbPath})
	assert.ErrorContains(t, err, "read loaded flag")
}

// ec2FilterParams sends each name/value pair as its own Filter.N.
func ec2FilterParams(kv ...string) url.Values {
	p := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		n := strconv.Itoa(i/2 + 1)
		p.Set("Filter."+n+".Name", kv[i])
		p.Set("Filter."+n+".Value.1", kv[i+1])
	}
	return p
}

// describedIDs are the ids an EC2 Describe answers, each from its own
// set.
type describedIDs struct {
	Vpcs              []string `xml:"vpcSet>item>vpcId"`
	Subnets           []string `xml:"subnetSet>item>subnetId"`
	Gateways          []string `xml:"internetGatewaySet>item>internetGatewayId"`
	RouteTables       []string `xml:"routeTableSet>item>routeTableId"`
	SecurityGroups    []string `xml:"securityGroupInfo>item>groupId"`
	Instances         []string `xml:"reservationSet>item>instancesSet>item>instanceId"`
	NetworkInterfaces []string `xml:"networkInterfaceSet>item>networkInterfaceId"`
	Addresses         []string `xml:"addressesSet>item>allocationId"`
	KeyPairs          []string `xml:"keySet>item>keyPairId"`
}

func describeIDs(t *testing.T, srv *httptest.Server, action string, params url.Values) describedIDs {
	t.Helper()
	resp, body := ec2Call(t, srv, tagRegion, action, params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s %v: %s", action, params, body)
	var out describedIDs
	require.NoError(t, xml.Unmarshal(body, &out), "%s", body)
	return out
}

// TestEC2_DescribeVpcsFilters: infrafactory's filtered read finds its
// run's VPC by tag-key, and data.aws_vpc sends cidr, isDefault and
// tag:<Key>; each must select, not 501 and not list every VPC.
func TestEC2_DescribeVpcsFilters(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	a := createOK(t, srv, "CreateVpc", "vpcId", withTagSpec(url.Values{"CidrBlock": {"10.0.0.0/16"}}, 1, "vpc",
		"infrafactory-run-id", "run-1", "Name", "a"))
	b := createOK(t, srv, "CreateVpc", "vpcId", withTagSpec(url.Values{"CidrBlock": {"10.1.0.0/16"}}, 1, "vpc", "Name", "b"))

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{[]string{"tag-key", "infrafactory-run-id"}, []string{a}},
		{[]string{"tag:Name", "b"}, []string{b}},
		{[]string{"tag-value", "run-1"}, []string{a}},
		{[]string{"cidr", "10.1.0.0/16"}, []string{b}},
		{[]string{"cidr-block-association.cidr-block", "10.0.0.0/16"}, []string{a}},
		{[]string{"vpc-id", b, "state", "available"}, []string{b}},
		{[]string{"owner-id", "000000000000"}, []string{a, b}},
		{[]string{"is-default", "false"}, []string{a, b}},
		{[]string{"isDefault", "true"}, nil},
		{[]string{"tag:Name", "matches-nothing"}, nil},
	} {
		assert.ElementsMatch(t, tc.want, describeIDs(t, srv, "DescribeVpcs", ec2FilterParams(tc.kv...)).Vpcs, "%v", tc.kv)
	}

	resp, body := ec2Call(t, srv, tagRegion, "DescribeVpcs", ec2FilterParams("dhcp-options-id", "dopt-fakeaws-default"))
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
	assert.Equal(t, "DescribeVpcs: not modelled by fakeaws: dhcp-options-id", extractEC2Tag(body, "Message"))
	assert.Equal(t, "filter-refused", lastClass(t, srv))
}

// TestEC2_DescribeSubnetsFilters: data.aws_subnet sends vpc-id with
// availabilityZone, cidrBlock and tag:<Key>, and wants one subnet.
func TestEC2_DescribeSubnetsFilters(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	vpc1, vpc2 := tagVPC(t, srv), tagVPC(t, srv)
	subnet := func(vpc, cidr, az, name string) string {
		return createOK(t, srv, "CreateSubnet", "subnetId", withTagSpec(url.Values{
			"VpcId": {vpc}, "CidrBlock": {cidr}, "AvailabilityZone": {az},
		}, 1, "subnet", "Name", name))
	}
	s1 := subnet(vpc1, "10.0.1.0/24", "us-east-1a", "one")
	s2 := subnet(vpc1, "10.0.2.0/24", "us-east-1b", "two")
	s3 := subnet(vpc2, "10.0.1.0/24", "us-east-1a", "three")
	all := []string{s1, s2, s3}

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{[]string{"vpc-id", vpc1, "availability-zone", "us-east-1a"}, []string{s1}},
		{[]string{"vpc-id", vpc1, "availabilityZone", "us-east-1b"}, []string{s2}},
		{[]string{"tag:Name", "three"}, []string{s3}},
		{[]string{"cidr-block", "10.0.2.0/24"}, []string{s2}},
		{[]string{"cidrBlock", "10.0.2.0/24"}, []string{s2}},
		{[]string{"cidr", "10.0.2.0/24"}, []string{s2}},
		{[]string{"availability-zone-id", "us-east-1b-az1"}, []string{s2}},
		{[]string{"availabilityZoneId", "us-east-1a-az1"}, []string{s1, s3}},
		{[]string{"subnet-id", s3}, []string{s3}},
		{[]string{"default-for-az", "true"}, nil},
		{[]string{"defaultForAz", "false", "state", "available", "owner-id", "000000000000"}, all},
		{[]string{"map-public-ip-on-launch", "false"}, all},
	} {
		assert.ElementsMatch(t, tc.want, describeIDs(t, srv, "DescribeSubnets", ec2FilterParams(tc.kv...)).Subnets, "%v", tc.kv)
	}
}

// TestEC2_DescribeInternetGatewaysFilters: a VPC's gateway is found by
// attachment.vpc-id, and attachment.state=available leaves out a
// detached gateway, which has no attachment.
func TestEC2_DescribeInternetGatewaysFilters(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	vpcA, vpcB := tagVPC(t, srv), tagVPC(t, srv)
	igw := func(vpc, name string) string {
		id := createOK(t, srv, "CreateInternetGateway", "internetGatewayId", withTagSpec(url.Values{}, 1, "internet-gateway", "Name", name))
		if vpc != "" {
			resp, body := ec2Call(t, srv, tagRegion, "AttachInternetGateway", url.Values{"InternetGatewayId": {id}, "VpcId": {vpc}})
			require.Equal(t, http.StatusOK, resp.StatusCode, "AttachInternetGateway: %s", body)
		}
		return id
	}
	igwA, igwB, detached := igw(vpcA, "a"), igw(vpcB, "b"), igw("", "detached")

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{[]string{"attachment.vpc-id", vpcA}, []string{igwA}},
		{[]string{"attachment.state", "available"}, []string{igwA, igwB}},
		{[]string{"internet-gateway-id", detached}, []string{detached}},
		{[]string{"tag:Name", "b"}, []string{igwB}},
		{[]string{"owner-id", "000000000000"}, []string{igwA, igwB, detached}},
	} {
		assert.ElementsMatch(t, tc.want, describeIDs(t, srv, "DescribeInternetGateways", ec2FilterParams(tc.kv...)).Gateways, "%v", tc.kv)
	}
}

// TestEC2_DescribeRouteTablesLookupFilters: data.aws_route_table sends
// route-table-id, vpc-id, association.subnet-id and tag:<Key>.
func TestEC2_DescribeRouteTablesLookupFilters(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	vpc := tagVPC(t, srv)
	rt := func(name string) string {
		return createOK(t, srv, "CreateRouteTable", "routeTableId", withTagSpec(url.Values{"VpcId": {vpc}}, 1, "route-table", "Name", name))
	}
	public, private := rt("public"), rt("private")
	other := createOK(t, srv, "CreateRouteTable", "routeTableId", withTagSpec(url.Values{"VpcId": {tagVPC(t, srv)}}, 1, "route-table", "Name", "public"))
	subnet := createOK(t, srv, "CreateSubnet", "subnetId", url.Values{"VpcId": {vpc}, "CidrBlock": {"10.0.1.0/24"}})
	createOK(t, srv, "AssociateRouteTable", "associationId", url.Values{"RouteTableId": {private}, "SubnetId": {subnet}})

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{[]string{"vpc-id", vpc, "tag:Name", "public"}, []string{public}},
		{[]string{"tag:Name", "public"}, []string{public, other}},
		{[]string{"route-table-id", private}, []string{private}},
		{[]string{"association.subnet-id", subnet}, []string{private}},
	} {
		assert.ElementsMatch(t, tc.want, describeIDs(t, srv, "DescribeRouteTables", ec2FilterParams(tc.kv...)).RouteTables, "%v", tc.kv)
	}
}

// TestEC2_DescribeSecurityGroupsFilters: a group name is unique only
// within a VPC, so group-name is read with vpc-id; infrafactory's
// absent-name lookup sends group-name with tag-key and wants an empty
// set, not a 501. aws_default_security_group's group-name=default is
// refused: every AWS VPC has that group and the rows have none.
func TestEC2_DescribeSecurityGroupsFilters(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	a, b := tagVPC(t, srv), tagVPC(t, srv)
	sg := func(vpc, desc string, tags ...string) string {
		return createOK(t, srv, "CreateSecurityGroup", "groupId", withTagSpec(url.Values{
			"GroupName": {"web"}, "GroupDescription": {desc}, "VpcId": {vpc},
		}, 1, "security-group", tags...))
	}
	webA := sg(a, "web in a", "infrafactory-run-id", "run-1")
	webB := sg(b, "web in b", "Name", "b")

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{[]string{"group-name", "web", "vpc-id", a}, []string{webA}},
		{[]string{"group-name", "absent", "tag-key", "infrafactory-run-id"}, nil},
		{[]string{"tag-key", "infrafactory-run-id"}, []string{webA}},
		{[]string{"tag:Name", "b"}, []string{webB}},
		{[]string{"tag-value", "run-1"}, []string{webA}},
		{[]string{"group-id", webB}, []string{webB}},
		{[]string{"description", "web in *"}, []string{webA, webB}},
		{[]string{"owner-id", "000000000000", "group-name", "web"}, []string{webA, webB}},
		{[]string{"group-name", "w?b", "vpc-id", b}, []string{webB}},
	} {
		assert.ElementsMatch(t, tc.want, describeIDs(t, srv, "DescribeSecurityGroups", ec2FilterParams(tc.kv...)).SecurityGroups, "%v", tc.kv)
	}

	for _, tc := range []struct {
		params url.Values
		want   string
	}{
		{ec2FilterParams("group-name", "default", "vpc-id", a), "group-name"},
		{ec2FilterParams("group-name", "def*"), "group-name"},
		{ec2FilterParams("group-name", "*", "vpc-id", a), "group-name"},
		{url.Values{"Filter.1.Name": {"group-name"}, "Filter.1.Value.1": {"web"}, "Filter.1.Value.2": {"default"}}, "group-name"},
		{ec2FilterParams("ip-permission.from-port", "22", "egress.ip-permission.cidr", "0.0.0.0/0", "group-name", "default"),
			"egress.ip-permission.cidr, group-name, ip-permission.from-port"},
	} {
		resp, body := ec2Call(t, srv, tagRegion, "DescribeSecurityGroups", tc.params)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%v: %s", tc.params, body)
		assert.Equal(t, "DescribeSecurityGroups: not modelled by fakeaws: "+tc.want, extractEC2Tag(body, "Message"), "%v", tc.params)
		assert.Equal(t, "filter-refused", lastClass(t, srv), "%v", tc.params)
	}
}

// UNVERIFIED(aws-code): VPCIdNotSpecified from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func TestContract_ec2_sg_group_name_default_vpc_only(t *testing.T) {
	groupName := func(srv *httptest.Server) (*http.Response, []byte) {
		t.Helper()
		createOK(t, srv, "CreateSecurityGroup", "groupId", url.Values{
			"GroupName": {"web"}, "GroupDescription": {"web"}, "VpcId": {tagVPC(t, srv)},
		})
		return ec2Call(t, srv, tagRegion, "DescribeSecurityGroups", url.Values{"GroupName.1": {"web"}})
	}

	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	resp, body := groupName(srv)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "unloaded: %s", body)
	assert.Equal(t, "VPCIdNotSpecified", extractEC2Tag(body, "Code"), "unloaded")
	assert.NotContains(t, string(body), "<groupId>", "unloaded: GroupName.N matches no group")
	assert.Equal(t, "answered-from-rows", lastClass(t, srv), "unloaded")

	dbPath := filepath.Join(t.TempDir(), "test.db")
	markLoaded(t, dbPath, true)
	_, srv = newRecordingApp(t, handlers.Options{DBPath: dbPath})
	resp, body = groupName(srv)
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "loaded: %s", body)
	assert.Equal(t, "NotImplemented", extractEC2Tag(body, "Code"), "loaded")
	assert.Equal(t, "DescribeSecurityGroups: not modelled by fakeaws: GroupName.N", extractEC2Tag(body, "Message"), "loaded")
	assert.Equal(t, "filter-refused", lastClass(t, srv), "loaded")

	// An unreadable flag is 500 for GroupName.N, never either branch,
	// and a GroupId.N lookup does not read it.
	app, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	_, err := app.Repository().DB().Exec(`ALTER TABLE identity DROP COLUMN loaded`)
	require.NoError(t, err)
	resp, body = groupName(srv)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "unreadable flag: %s", body)
	assert.NotContains(t, string(body), "<groupId>", "unreadable flag")
	sg := createOK(t, srv, "CreateSecurityGroup", "groupId", url.Values{
		"GroupName": {"db"}, "GroupDescription": {"db"}, "VpcId": {tagVPC(t, srv)},
	})
	assert.Equal(t, []string{sg}, describeIDs(t, srv, "DescribeSecurityGroups", url.Values{"GroupId.1": {sg}}).SecurityGroups,
		"GroupId.N with an unreadable flag")
}

// filteredNet is an instance network in 10.<octet>.0.0/16, so no two
// share a private IP, with its VPC id, which newInstanceNet does not
// return.
func filteredNet(t *testing.T, srv *httptest.Server, region, octet string) (instanceNet, string) {
	t.Helper()
	n := newInstanceNet(t, srv, region, "10."+octet+".0.0/16", "10."+octet+".1.0/24")
	resp, body := ec2Call(t, srv, region, "DescribeSubnets", url.Values{"SubnetId.1": {n.subnet}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeSubnets: %s", body)
	return n, extractEC2Tag(body, "vpcId")
}

// TestEC2_DescribeInstancesFilters: data.aws_instance and
// infrafactory's reads select an instance by its surroundings; each
// filter must select, not 501 and not list every instance, and the
// unfiltered list answers one region.
func TestEC2_DescribeInstancesFilters(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	netA, vpcA := filteredNet(t, srv, tagRegion, "1")
	netB, vpcB := filteredNet(t, srv, tagRegion, "2")
	netEU, _ := filteredNet(t, srv, "eu-west-2", "3")
	a := runInstance(t, srv, tagRegion, withTagSpec(topLevelParams(netA.subnet, netA.sgs), 1, "instance", "Name", "a"))
	gone := runInstance(t, srv, tagRegion, topLevelParams(netA.subnet, netA.sgs))
	resp, body := ec2Call(t, srv, tagRegion, "TerminateInstances", url.Values{"InstanceId.1": {gone}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "TerminateInstances: %s", body)
	b := runInstance(t, srv, tagRegion, nicParams(netB.subnet, netB.sgs[:1], true))
	runInstance(t, srv, "eu-west-2", topLevelParams(netEU.subnet, netEU.sgs))
	ipA, _ := describeInstance(t, srv, tagRegion, a)

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{nil, []string{a, gone, b}},
		{[]string{"vpc-id", vpcA}, []string{a, gone}},
		{[]string{"vpc-id", vpcB}, []string{b}},
		{[]string{"instance-state-name", "running"}, []string{a, b}},
		{[]string{"instance-id", b}, []string{b}},
		{[]string{"instance-type", "t3.micro", "vpc-id", vpcA}, []string{a, gone}},
		{[]string{"image-id", "ami-0abcd1234", "subnet-id", netB.subnet}, []string{b}},
		{[]string{"private-ip-address", ipA.PrivateIpAddress}, []string{a}},
		{[]string{"ip-address", "*"}, []string{b}},
		{[]string{"availability-zone", tagRegion + "a", "instance-state-name", "running"}, []string{a, b}},
		{[]string{"owner-id", "000000000000", "vpc-id", vpcB}, []string{b}},
		{[]string{"tag:Name", "a"}, []string{a}},
	} {
		assert.ElementsMatch(t, tc.want, describeIDs(t, srv, "DescribeInstances", ec2FilterParams(tc.kv...)).Instances, "%v", tc.kv)
	}

	resp, body = ec2Call(t, srv, tagRegion, "DescribeInstances", ec2FilterParams("reservation-id", "r-1"))
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
	assert.Equal(t, "DescribeInstances: not modelled by fakeaws: reservation-id", extractEC2Tag(body, "Message"))
}

func TestEC2_DescribeNetworkInterfacesFilters(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	netA, vpcA := filteredNet(t, srv, tagRegion, "1")
	netB, _ := filteredNet(t, srv, tagRegion, "2")
	a, _ := describeInstance(t, srv, tagRegion, runInstance(t, srv, tagRegion, withTagSpec(
		topLevelParams(netA.subnet, netA.sgs), 1, "network-interface", "Name", "a")))
	b, _ := describeInstance(t, srv, tagRegion, runInstance(t, srv, tagRegion, topLevelParams(netB.subnet, netB.sgs)))
	eniA, eniB := a.ENIs[0].ID, b.ENIs[0].ID
	resp, body := ec2Call(t, srv, tagRegion, "DescribeNetworkInterfaces", url.Values{"NetworkInterfaceId.1": {eniA}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeNetworkInterfaces: %s", body)
	attachA := extractEC2Tag(body, "attachmentId")
	require.NotEmpty(t, attachA, "%s", body)

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{[]string{"vpc-id", vpcA}, []string{eniA}},
		{[]string{"private-ip-address", b.PrivateIpAddress}, []string{eniB}},
		{[]string{"attachment.attachment-id", attachA}, []string{eniA}},
		{[]string{"owner-id", "000000000000"}, []string{eniA, eniB}},
		{[]string{"tag:Name", "a"}, []string{eniA}},
		{[]string{"subnet-id", netB.subnet}, []string{eniB}},
	} {
		assert.ElementsMatch(t, tc.want, describeIDs(t, srv, "DescribeNetworkInterfaces", ec2FilterParams(tc.kv...)).NetworkInterfaces, "%v", tc.kv)
	}
}

func TestEC2_DescribeAddressesFilters(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	a := createOK(t, srv, "AllocateAddress", "allocationId", withTagSpec(url.Values{"Domain": {"vpc"}}, 1, "elastic-ip", "Name", "a"))
	b := createOK(t, srv, "AllocateAddress", "allocationId", url.Values{"Domain": {"vpc"}})
	resp, body := ec2Call(t, srv, tagRegion, "DescribeAddresses", url.Values{"AllocationId.1": {b}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeAddresses: %s", body)
	ipB := extractEC2Tag(body, "publicIp")
	// a is associated, so instance-id, network-interface-id and
	// private-ip-address each select it and not the unassociated b.
	net, _ := filteredNet(t, srv, tagRegion, "1")
	inst := runInstance(t, srv, tagRegion, topLevelParams(net.subnet, net.sgs))
	nic, _ := describeInstance(t, srv, tagRegion, inst)
	createOK(t, srv, "AssociateAddress", "associationId", url.Values{"AllocationId": {a}, "InstanceId": {inst}})

	for _, tc := range []struct {
		params url.Values
		want   []string
	}{
		{url.Values{"PublicIp.1": {ipB}}, []string{b}},
		{ec2FilterParams("allocation-id", a), []string{a}},
		{ec2FilterParams("public-ip", ipB), []string{b}},
		{ec2FilterParams("domain", "vpc"), []string{a, b}},
		{ec2FilterParams("tag:Name", "a"), []string{a}},
		{ec2FilterParams("instance-id", inst), []string{a}},
		{ec2FilterParams("network-interface-id", nic.ENIs[0].ID), []string{a}},
		{ec2FilterParams("private-ip-address", nic.PrivateIpAddress), []string{a}},
		{ec2FilterParams("instance-id", "*"), []string{a}},
		{ec2FilterParams("network-interface-id", "i-*"), nil},
	} {
		assert.ElementsMatch(t, tc.want, describeIDs(t, srv, "DescribeAddresses", tc.params).Addresses, "%v", tc.params)
	}

	// UNVERIFIED(aws-code): InvalidAddress.NotFound from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
	resp, body = ec2Call(t, srv, tagRegion, "DescribeAddresses", url.Values{"PublicIp.1": {"198.51.100.1"}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s", body)
	assert.Equal(t, "InvalidAddress.NotFound", extractEC2Tag(body, "Code"))
}

func TestEC2_DescribeKeyPairsFilters(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	importKey := func(name string, tags ...string) string {
		return createOK(t, srv, "ImportKeyPair", "keyPairId", withTagSpec(url.Values{
			"KeyName": {name}, "PublicKeyMaterial": {"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + name},
		}, 1, "key-pair", tags...))
	}
	a, b := importKey("a", "Name", "a"), importKey("b", "Name", "b")
	resp, body := ec2Call(t, srv, tagRegion, "DescribeKeyPairs", url.Values{"KeyPairId.1": {b}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeKeyPairs: %s", body)
	fingerprintB := extractEC2Tag(body, "keyFingerprint")

	for _, tc := range []struct {
		params url.Values
		want   []string
	}{
		{url.Values{"KeyPairId.1": {a}}, []string{a}},
		{url.Values{"KeyName.1": {"b"}}, []string{b}},
		{ec2FilterParams("key-name", "a"), []string{a}},
		{ec2FilterParams("key-pair-id", b), []string{b}},
		{ec2FilterParams("fingerprint", fingerprintB, "key-name", "b"), []string{b}},
		{ec2FilterParams("tag:Name", "a"), []string{a}},
		{nil, []string{a, b}},
	} {
		assert.ElementsMatch(t, tc.want, describeIDs(t, srv, "DescribeKeyPairs", tc.params).KeyPairs, "%v", tc.params)
	}

	// UNVERIFIED(aws-code): InvalidKeyPair.NotFound from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
	// The provider's aws_key_pair read takes only this code as gone, by
	// KeyName.N as well as KeyPairId.N.
	for param, key := range map[string]string{"KeyPairId.1": "key-0000000000000000", "KeyName.1": "missing"} {
		resp, body = ec2Call(t, srv, tagRegion, "DescribeKeyPairs", url.Values{param: {key}})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s: %s", param, body)
		assert.Equal(t, "InvalidKeyPair.NotFound", extractEC2Tag(body, "Code"), param)
		assert.Contains(t, extractEC2Tag(body, "Message"), key, param)
	}
}
