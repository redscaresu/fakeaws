package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
)

// netRegion is the region of the testdata/ec2 fixtures.
const netRegion = "us-west-2"

// netRecorded is one recorded EC2 exchange: its action, params and body.
type netRecorded struct {
	action string
	params map[string]string
	body   string
}

func (r netRecorded) exchange() string {
	return loadPage("ec2", r.action, r.params, http.StatusOK, r.body)
}

// ec2Fixture reads testdata/ec2/<name>.xml.
func ec2Fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "ec2", name+".xml"))
	require.NoError(t, err)
	return string(b)
}

// fixtureVpcs are the VPCs DescribeVpcs.xml answers; the attribute
// fixtures answer the second, and the recording gives the other two
// the same answers under their own ids.
var fixtureVpcs = []string{"vpc-081ec835f3EXAMPLE", "vpc-0ee975135dEXAMPLE", "vpc-06e4ab6c6cEXAMPLE"}

// fixtureRecording is every testdata/ec2 fixture as an exchange of the
// request it answers.
func fixtureRecording(t *testing.T) []netRecorded {
	t.Helper()
	out := []netRecorded{
		{"DescribeAvailabilityZones", map[string]string{}, ec2Fixture(t, "DescribeAvailabilityZones")},
		{"DescribeVpcs", map[string]string{"VpcId.1": fixtureVpcs[0], "VpcId.2": fixtureVpcs[1], "VpcId.3": fixtureVpcs[2]}, ec2Fixture(t, "DescribeVpcs")},
		{"DescribeSubnets", map[string]string{}, ec2Fixture(t, "DescribeSubnets")},
		{"DescribeInternetGateways", map[string]string{}, ec2Fixture(t, "DescribeInternetGateways")},
	}
	for _, vpc := range fixtureVpcs {
		for _, attr := range []string{"enableDnsSupport", "enableDnsHostnames"} {
			body := strings.ReplaceAll(ec2Fixture(t, "DescribeVpcAttribute-"+attr), fixtureVpcs[1], vpc)
			out = append(out, netRecorded{"DescribeVpcAttribute", map[string]string{"VpcId": vpc, "Attribute": attr}, body})
		}
	}
	return out
}

// loadNet loads recorded under loadAccount and netRegion, which must
// answer 200, and returns the answer.
func loadNet(t *testing.T, srv *httptest.Server, recorded ...netRecorded) string {
	t.Helper()
	exchanges := make([]string, len(recorded))
	for i, r := range recorded {
		exchanges[i] = r.exchange()
	}
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, netRegion, exchanges...))
	require.Equal(t, http.StatusOK, status, body)
	return body
}

// resend sends r's request to fakeaws and returns the body it answers.
func resend(t *testing.T, srv *httptest.Server, r netRecorded) string {
	t.Helper()
	params := url.Values{}
	for k, v := range r.params {
		params.Set(k, v)
	}
	return string(mustOK(t)(ec2Call(t, srv, netRegion, r.action, params)))
}

// diffAnswer diffs r's recorded body against what fakeaws answers to
// its request now.
func diffAnswer(t *testing.T, srv *httptest.Server, r netRecorded) (recordedOnly, renderedOnly []string) {
	t.Helper()
	recorded, err := handlers.ParseXML([]byte(r.body))
	require.NoError(t, err)
	answered, err := handlers.ParseXML([]byte(resend(t, srv, r)))
	require.NoError(t, err)
	return handlers.Diff(handlers.LoadKey{Service: "ec2", Action: r.action}, recorded, answered)
}

func TestLoadEC2Network_FixturesAnswerAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	recorded := fixtureRecording(t)
	var answer struct {
		Loaded     map[string]int
		Unresolved map[string][]string
	}
	require.NoError(t, json.Unmarshal([]byte(loadNet(t, srv, recorded...)), &answer))
	assert.Equal(t, map[string]int{"availability-zone": 4, "vpc": 3, "vpc-attribute": 6, "subnet": 2, "internet-gateway": 2}, answer.Loaded)
	assert.Equal(t, map[string][]string{"dhcp-options": {"dopt-19edf471", "dopt-f30d649a"}}, answer.Unresolved)
	for _, r := range recorded {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s %v: recorded only", r.action, r.params)
		assert.Empty(t, ren, "%s %v: answered only", r.action, r.params)
	}
}

func TestLoadEC2Network_RecordedSubnetArnAnswersAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadNet(t, srv, fixtureRecording(t)...)
	const id = "subnet-0bb1c79de301436ee"
	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeSubnets", url.Values{"SubnetId.1": {id}}))
	assert.Equal(t, "arn:aws:ec2:us-west-2:111122223333:subnet/subnet-0bb1c79de3EXAMPLE", extractEC2Tag(body, "subnetArn"))
	assert.NotEqual(t, awsproto.BuildEC2SubnetARN(netRegion, loadAccount, id), extractEC2Tag(body, "subnetArn"))
}

func TestLoadEC2Network_MutateOnce(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	recorded := fixtureRecording(t)
	loadNet(t, srv, recorded...)
	vpcs, subnets, igws := recorded[1], recorded[2], recorded[3]

	mustOK(t)(ec2Call(t, srv, netRegion, "ModifySubnetAttribute", url.Values{
		"SubnetId": {"subnet-0bb1c79de301436ee"}, "MapPublicIpOnLaunch.Value": {"true"}}))
	rec, ren := diffAnswer(t, srv, subnets)
	assert.Equal(t, []string{"subnetSet/item[0]/mapPublicIpOnLaunch"}, rec)
	assert.Equal(t, []string{"subnetSet/item[1]/mapPublicIpOnLaunch"}, ren, "answered by id, so the subnet is second")

	mustOK(t)(ec2Call(t, srv, netRegion, "ModifyVpcAttribute", url.Values{
		"VpcId": {fixtureVpcs[1]}, "EnableDnsHostnames.Value": {"false"}}))
	rec, ren = diffAnswer(t, srv, vpcs)
	assert.Empty(t, rec)
	assert.Empty(t, ren)

	mustOK(t)(ec2Call(t, srv, netRegion, "DetachInternetGateway", url.Values{
		"InternetGatewayId": {"igw-0EXAMPLE"}, "VpcId": {fixtureVpcs[1]}}))
	rec, ren = diffAnswer(t, srv, igws)
	assert.Equal(t, []string{"internetGatewaySet/item[1]/attachmentSet/item[0]"}, rec)
	assert.Empty(t, ren)
}

// netVpc is a DescribeVpcs item of VPC id, then more (its isDefault, a
// tagSet).
func netVpc(id, more string) string {
	return "<item><vpcId>" + id + "</vpcId><ownerId>" + loadAccount + "</ownerId><state>available</state><cidrBlock>10.0.0.0/16</cidrBlock>" +
		"<cidrBlockAssociationSet><item><cidrBlock>10.0.0.0/16</cidrBlock><associationId>vpc-cidr-assoc-0" + id[4:] +
		"</associationId><cidrBlockState><state>associated</state></cidrBlockState></item></cidrBlockAssociationSet>" +
		"<dhcpOptionsId>dopt-0abc</dhcpOptionsId><instanceTenancy>default</instanceTenancy>" + more + "</item>"
}

func netVpcs(items ...string) netRecorded {
	return netRecorded{"DescribeVpcs", map[string]string{}, "<DescribeVpcsResponse><vpcSet>" + strings.Join(items, "") + "</vpcSet></DescribeVpcsResponse>"}
}

func netVpcAttribute(vpc, attr string, value bool) netRecorded {
	return netRecorded{"DescribeVpcAttribute", map[string]string{"VpcId": vpc, "Attribute": attr},
		fmt.Sprintf("<DescribeVpcAttributeResponse><vpcId>%s</vpcId><%s><value>%t</value></%[2]s></DescribeVpcAttributeResponse>", vpc, attr, value)}
}

// netDNS are vpc's two DescribeVpcAttribute answers, both value.
func netDNS(vpc string, value bool) []netRecorded {
	return []netRecorded{netVpcAttribute(vpc, "enableDnsSupport", value), netVpcAttribute(vpc, "enableDnsHostnames", value)}
}

// netSubnet is a DescribeSubnets item of subnet id in vpc, in a zone no
// exchange loads, then more (a tagSet).
func netSubnet(id, vpc, more string) string {
	return "<item><subnetId>" + id + "</subnetId><subnetArn>arn:aws:ec2:" + netRegion + ":" + loadAccount + ":subnet/" + id + "</subnetArn>" +
		"<state>available</state><ownerId>" + loadAccount + "</ownerId><vpcId>" + vpc + "</vpcId><cidrBlock>10.0.1.0/24</cidrBlock>" +
		"<availableIpAddressCount>251</availableIpAddressCount><availabilityZone>" + netRegion + "a</availabilityZone>" +
		"<defaultForAz>false</defaultForAz><mapPublicIpOnLaunch>false</mapPublicIpOnLaunch><assignIpv6AddressOnCreation>false</assignIpv6AddressOnCreation>" +
		more + "</item>"
}

func netSubnets(items ...string) netRecorded {
	return netRecorded{"DescribeSubnets", map[string]string{}, "<DescribeSubnetsResponse><subnetSet>" + strings.Join(items, "") + "</subnetSet></DescribeSubnetsResponse>"}
}

func netTags(kv ...string) string {
	var b strings.Builder
	for i := 0; i < len(kv); i += 2 {
		b.WriteString("<item><key>" + kv[i] + "</key><value>" + kv[i+1] + "</value></item>")
	}
	return "<tagSet>" + b.String() + "</tagSet>"
}

// vpcAttribute is what DescribeVpcAttribute answers for vpc's attr.
func vpcAttribute(t *testing.T, srv *httptest.Server, vpc, attr string) string {
	t.Helper()
	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeVpcAttribute", url.Values{"VpcId": {vpc}, "Attribute": {attr}}))
	return extractEC2Tag([]byte(extractEC2Tag(body, attr)), "value")
}

func TestLoadEC2Network_VpcAttributesAnswerAndPersist(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	const vpc, enabled = "vpc-0default", "vpc-0enabled"
	recording := []netRecorded{netVpcs(netVpc(vpc, "<isDefault>true</isDefault>"), netVpc(enabled, "<isDefault>false</isDefault>"))}
	recording = append(append(recording, netDNS(vpc, false)...), netDNS(enabled, true)...)
	loadNet(t, srv, recording...)
	assert.Equal(t, "true", vpcAttribute(t, srv, enabled, "enableDnsSupport"))
	assert.Equal(t, "true", vpcAttribute(t, srv, enabled, "enableDnsHostnames"))

	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeVpcs", url.Values{"VpcId.1": {vpc}}))
	assert.Equal(t, "true", extractEC2Tag(body, "isDefault"))
	assert.Equal(t, "dopt-0abc", extractEC2Tag(body, "dhcpOptionsId"))
	assert.Equal(t, "false", vpcAttribute(t, srv, vpc, "enableDnsSupport"))
	assert.Equal(t, "false", vpcAttribute(t, srv, vpc, "enableDnsHostnames"))

	mustOK(t)(ec2Call(t, srv, netRegion, "ModifyVpcAttribute", url.Values{"VpcId": {vpc}, "EnableDnsSupport.Value": {"true"}}))
	assert.Equal(t, "true", vpcAttribute(t, srv, vpc, "enableDnsSupport"))
	assert.Equal(t, "false", vpcAttribute(t, srv, vpc, "enableDnsHostnames"))

	mustOK(t)(ec2Call(t, srv, netRegion, "ModifyVpcAttribute", url.Values{"VpcId": {vpc}, "EnableDnsHostnames.Value": {"true"}}))
	assert.Equal(t, "true", vpcAttribute(t, srv, vpc, "enableDnsHostnames"))

	resp, body := ec2Call(t, srv, netRegion, "ModifyVpcAttribute", url.Values{"VpcId": {vpc}, "EnableDnsSupport.Value": {"yes"}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "InvalidParameterValue")
	assert.Equal(t, "true", vpcAttribute(t, srv, vpc, "enableDnsSupport"))
}

func TestLoadEC2Network_TagFiltersSelectLoadedRows(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	recording := []netRecorded{
		netVpcs(netVpc("vpc-0tagged", "<isDefault>false</isDefault>"+netTags("infrafactory-run-id", "run-1", "Name", "web")),
			netVpc("vpc-0other", "<isDefault>false</isDefault>")),
		netSubnets(netSubnet("subnet-0tagged", "vpc-0tagged", netTags("Name", "web-a")), netSubnet("subnet-0other", "vpc-0other", "")),
	}
	recording = append(recording, netDNS("vpc-0tagged", true)...)
	recording = append(recording, netDNS("vpc-0other", true)...)
	loadNet(t, srv, recording...)

	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeVpcs", url.Values{"Filter.1.Name": {"tag-key"}, "Filter.1.Value.1": {"infrafactory-run-id"}}))
	assert.Equal(t, 1, strings.Count(string(body), "<vpcId>"), "%s", body)
	assert.Equal(t, "vpc-0tagged", extractEC2Tag(body, "vpcId"))

	body = mustOK(t)(ec2Call(t, srv, netRegion, "DescribeSubnets", url.Values{"Filter.1.Name": {"tag:Name"}, "Filter.1.Value.1": {"web-a"}}))
	assert.Equal(t, 1, strings.Count(string(body), "<subnetId>"), "%s", body)
	assert.Equal(t, "subnet-0tagged", extractEC2Tag(body, "subnetId"))
}

func TestContract_mock_load_refuses_dangling_reference(t *testing.T) {
	vpc := netVpcs(netVpc("vpc-0a", "<isDefault>false</isDefault>"))
	dns := netDNS("vpc-0a", true)
	cases := map[string]struct {
		recording []netRecorded
		want      string
	}{
		"an element the model cannot hold": {
			append([]netRecorded{netVpcs(netVpc("vpc-0a", "<isDefault>false</isDefault><fooBar><x>1</x></fooBar>"))}, dns...),
			"exchange 0: ec2 DescribeVpcs: vpc vpc-0a: the model cannot hold recorded vpcSet/item[0]/fooBar/x",
		},
		"a subnet whose VPC was not recorded": {
			append([]netRecorded{vpc, netSubnets(netSubnet("subnet-0a", "vpc-0missing", ""))}, dns...),
			"exchange 1: ec2 DescribeSubnets: subnet subnet-0a names vpc vpc-0missing, which no exchange loaded",
		},
		"a VPC whose DNS attributes were not recorded": {
			[]netRecorded{vpc, dns[1]},
			"exchange 0: ec2 DescribeVpcs: vpc vpc-0a references vpc-attribute vpc-0a/enableDnsSupport, which no exchange loaded",
		},
		"a DNS attribute of a VPC that was not recorded": {
			append([]netRecorded{vpc, netVpcAttribute("vpc-0missing", "enableDnsSupport", true)}, dns...),
			"exchange 1: ec2 DescribeVpcAttribute: vpc-attribute vpc-0missing/enableDnsSupport names vpc vpc-0missing, which no exchange loaded",
		},
		"an attribute answer holding neither DNS attribute": {
			append([]netRecorded{vpc, {"DescribeVpcAttribute", map[string]string{"VpcId": "vpc-0a", "Attribute": "enableNetworkAddressUsageMetrics"},
				"<DescribeVpcAttributeResponse><vpcId>vpc-0a</vpcId><enableNetworkAddressUsageMetrics><value>false</value></enableNetworkAddressUsageMetrics></DescribeVpcAttributeResponse>"}}, dns...),
			"exchange 1: ec2 DescribeVpcAttribute: it answers neither enableDnsSupport nor enableDnsHostnames",
		},
		"a gateway attached to a VPC that was not recorded": {
			append([]netRecorded{vpc, {"DescribeInternetGateways", map[string]string{},
				"<DescribeInternetGatewaysResponse><internetGatewaySet><item><internetGatewayId>igw-0a</internetGatewayId><ownerId>" + loadAccount +
					"</ownerId><attachmentSet><item><vpcId>vpc-0missing</vpcId><state>available</state></item></attachmentSet></item></internetGatewaySet></DescribeInternetGatewaysResponse>"}}, dns...),
			"exchange 1: ec2 DescribeInternetGateways: internet-gateway igw-0a references vpc vpc-0missing, which no exchange loaded",
		},
		"a value that does not decode": {
			append([]netRecorded{netVpcs(netVpc("vpc-0a", "<isDefault>maybe</isDefault>"))}, dns...),
			"exchange 0: ec2 DescribeVpcs: its body does not decode as DescribeVpcs's answer",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
			seedLoadRows(t, srv)
			before := loadedState(t, app, srv)
			exchanges := make([]string, len(c.recording))
			for i, r := range c.recording {
				exchanges[i] = r.exchange()
			}
			status, body := postLoad(t, srv, loadEnvelope(loadAccount, netRegion, exchanges...))
			require.Equal(t, http.StatusBadRequest, status, body)
			assert.Contains(t, loadRefusals(t, body), c.want)
			assert.Equal(t, before, loadedState(t, app, srv), "a refused load stored something")
		})
	}
}

// TestLoadEC2Network_CreatedAfterLoadAnswerAsBefore: a VPC and subnet
// created on a loaded database answer what they answered before loaders
// existed, but for the loaded zone's id.
func TestLoadEC2Network_CreatedAfterLoadAnswerAsBefore(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadNet(t, srv, fixtureRecording(t)...)
	vpc := extractEC2Tag(mustOK(t)(ec2Call(t, srv, netRegion, "CreateVpc", url.Values{"CidrBlock": {"10.9.0.0/16"}})), "vpcId")
	subnet := extractEC2Tag(mustOK(t)(ec2Call(t, srv, netRegion, "CreateSubnet", url.Values{"VpcId": {vpc}, "CidrBlock": {"10.9.1.0/24"}})), "subnetId")

	wantVpc := netRecorded{"DescribeVpcs", map[string]string{"VpcId.1": vpc}, fmt.Sprintf(`<DescribeVpcsResponse><vpcSet><item>
		<vpcId>%[1]s</vpcId><state>available</state><cidrBlock>10.9.0.0/16</cidrBlock><dhcpOptionsId>dopt-fakeaws-default</dhcpOptionsId>
		<instanceTenancy>default</instanceTenancy><ownerId>%[2]s</ownerId><isDefault>false</isDefault>
		<cidrBlockAssociationSet><item><associationId>vpc-cidr-assoc-%[1]s</associationId><cidrBlock>10.9.0.0/16</cidrBlock>
		<cidrBlockState><state>associated</state></cidrBlockState></item></cidrBlockAssociationSet>
		</item></vpcSet></DescribeVpcsResponse>`, vpc, loadAccount)}
	wantSubnet := netRecorded{"DescribeSubnets", map[string]string{"SubnetId.1": subnet}, fmt.Sprintf(`<DescribeSubnetsResponse><subnetSet><item>
		<subnetId>%[1]s</subnetId><vpcId>%[2]s</vpcId><state>available</state><cidrBlock>10.9.1.0/24</cidrBlock>
		<availabilityZone>us-west-2a</availabilityZone><availabilityZoneId>usw2-az1</availabilityZoneId>
		<availableIpAddressCount>251</availableIpAddressCount><ownerId>%[3]s</ownerId><subnetArn>%[4]s</subnetArn>
		<defaultForAz>false</defaultForAz><mapPublicIpOnLaunch>false</mapPublicIpOnLaunch><mapCustomerOwnedIpOnLaunch>false</mapCustomerOwnedIpOnLaunch>
		<assignIpv6AddressOnCreation>false</assignIpv6AddressOnCreation><enableDns64>false</enableDns64><ipv6Native>false</ipv6Native>
		<privateDnsNameOptionsOnLaunch><hostnameType>ip-name</hostnameType><enableResourceNameDnsARecord>false</enableResourceNameDnsARecord>
		<enableResourceNameDnsAAAARecord>false</enableResourceNameDnsAAAARecord></privateDnsNameOptionsOnLaunch>
		</item></subnetSet></DescribeSubnetsResponse>`, subnet, vpc, loadAccount, awsproto.BuildEC2SubnetARN(netRegion, loadAccount, subnet))}
	for _, want := range []netRecorded{wantVpc, wantSubnet} {
		rec, ren := diffAnswer(t, srv, want)
		assert.Empty(t, rec, want.action)
		assert.Empty(t, ren, want.action)
	}
	assert.Equal(t, "true", vpcAttribute(t, srv, vpc, "enableDnsSupport"))
	assert.Equal(t, "true", vpcAttribute(t, srv, vpc, "enableDnsHostnames"))
}

// TestLoadEC2Network_CurrentShapeLoads plants what a current answer
// carries beyond the API reference's examples: Block Public Access
// states, a VPC's encryption control, IPv6 blocks with their source and address attribute, CIDR
// state messages, a subnet's type and every optional subnet field, and
// a zone's messages. Each loads, modelled or ignored, and answers as
// recorded.
func TestLoadEC2Network_CurrentShapeLoads(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	const bpa = "<blockPublicAccessStates><internetGatewayBlockMode>off</internetGatewayBlockMode></blockPublicAccessStates>"
	vpc := "<item><vpcId>vpc-0now</vpcId><ownerId>" + loadAccount + "</ownerId><state>available</state><cidrBlock>10.0.0.0/16</cidrBlock>" +
		"<cidrBlockAssociationSet><item><cidrBlock>10.0.0.0/16</cidrBlock><associationId>vpc-cidr-assoc-0now</associationId>" +
		"<cidrBlockState><state>associated</state><statusMessage>ok</statusMessage></cidrBlockState></item></cidrBlockAssociationSet>" +
		"<ipv6CidrBlockAssociationSet><item><ipv6CidrBlock>2600:1f14:abc:de00::/56</ipv6CidrBlock><associationId>vpc-cidr-assoc-0v6</associationId>" +
		"<ipv6CidrBlockState><state>associated</state><statusMessage>ok</statusMessage></ipv6CidrBlockState><networkBorderGroup>us-west-2</networkBorderGroup>" +
		"<ipv6Pool>Amazon</ipv6Pool><ipSource>amazon</ipSource><ipv6AddressAttribute>public</ipv6AddressAttribute></item></ipv6CidrBlockAssociationSet>" +
		"<dhcpOptionsId>dopt-0now</dhcpOptionsId><instanceTenancy>default</instanceTenancy><isDefault>false</isDefault>" + bpa +
		"<encryptionControl><vpcId>vpc-0now</vpcId><vpcEncryptionControlId>vpcec-0now</vpcEncryptionControlId><mode>monitor</mode>" +
		"<state>available</state></encryptionControl></item>"
	subnet := netSubnet("subnet-0now", "vpc-0now", "<availabilityZoneId>usw2-az1</availabilityZoneId>"+
		"<mapCustomerOwnedIpOnLaunch>false</mapCustomerOwnedIpOnLaunch><enableDns64>false</enableDns64><ipv6Native>false</ipv6Native>"+
		"<enableLniAtDeviceIndex>1</enableLniAtDeviceIndex><customerOwnedIpv4Pool>ipv4pool-coip-0now</customerOwnedIpv4Pool>"+
		"<outpostArn>arn:aws:outposts:us-west-2:"+loadAccount+":outpost/op-0now</outpostArn><type>Elastic VMware Service</type>"+
		"<ipv6CidrBlockAssociationSet><item><ipv6CidrBlock>2600:1f14:abc:de00::/64</ipv6CidrBlock><associationId>subnet-cidr-assoc-0now</associationId>"+
		"<ipv6CidrBlockState><state>associated</state><statusMessage>ok</statusMessage></ipv6CidrBlockState>"+
		"<ipSource>amazon</ipSource><ipv6AddressAttribute>public</ipv6AddressAttribute></item></ipv6CidrBlockAssociationSet>"+
		"<privateDnsNameOptionsOnLaunch><hostnameType>resource-name</hostnameType><enableResourceNameDnsARecord>true</enableResourceNameDnsARecord>"+
		"<enableResourceNameDnsAAAARecord>false</enableResourceNameDnsAAAARecord></privateDnsNameOptionsOnLaunch>"+bpa)
	zone := netRecorded{"DescribeAvailabilityZones", map[string]string{}, "<DescribeAvailabilityZonesResponse><availabilityZoneInfo><item>" +
		"<groupName>us-west-2-zg-1</groupName><optInStatus>opt-in-not-required</optInStatus><zoneName>us-west-2a</zoneName><zoneId>usw2-az1</zoneId>" +
		"<zoneState>available</zoneState><zoneType>availability-zone</zoneType><regionName>us-west-2</regionName>" +
		"<messageSet><item><message>scheduled maintenance</message></item></messageSet><networkBorderGroup>us-west-2</networkBorderGroup>" +
		"</item></availabilityZoneInfo></DescribeAvailabilityZonesResponse>"}
	recording := append([]netRecorded{zone, netVpcs(vpc), netSubnets(subnet)}, netDNS("vpc-0now", true)...)
	loadNet(t, srv, recording...)
	for _, r := range recording[:3] {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s: recorded only", r.action)
		assert.Empty(t, ren, "%s: answered only", r.action)
	}
}
