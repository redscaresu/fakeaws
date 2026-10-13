package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

// The fixture's route table, its VPC and its main association.
const (
	fixtureRT      = "rtb-1122334455667788a"
	fixtureRTVpc   = "vpc-0ee975135dEXAMPLE"
	fixtureRTAssoc = "rtbassoc-04ca27a6914a0b4fc"
)

// routeTablesFixture is DescribeRouteTables.xml as the exchange of the
// request it answers.
func routeTablesFixture(t *testing.T) netRecorded {
	t.Helper()
	return netRecorded{"DescribeRouteTables", map[string]string{}, ec2Fixture(t, "DescribeRouteTables")}
}

// netRouteTables is a DescribeRouteTables answer holding items.
func netRouteTables(items ...string) netRecorded {
	return netRecorded{"DescribeRouteTables", map[string]string{},
		"<DescribeRouteTablesResponse><routeTableSet>" + strings.Join(items, "") + "</routeTableSet></DescribeRouteTablesResponse>"}
}

// netRouteTable is a routeTableSet item of route table id in vpc, with
// its local route, then more (associations, more routes).
func netRouteTable(id, vpc, more string) string {
	return "<item><routeTableId>" + id + "</routeTableId><vpcId>" + vpc + "</vpcId><ownerId>" + loadAccount + "</ownerId>" +
		"<routeSet><item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId>" +
		"<state>active</state><origin>CreateRouteTable</origin></item></routeSet>" + more + "</item>"
}

// netAssociation is an associationSet holding association id of route
// table rt: main when subnet is "", else subnet's.
func netAssociation(id, rt, subnet string) string {
	link := "<main>true</main>"
	if subnet != "" {
		link = "<subnetId>" + subnet + "</subnetId><main>false</main>"
	}
	return "<associationSet><item><routeTableAssociationId>" + id + "</routeTableAssociationId><routeTableId>" + rt + "</routeTableId>" +
		link + "<associationState><state>associated</state></associationState></item></associationSet>"
}

func TestLoadEC2Routes_FixtureAnswersAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	rts := routeTablesFixture(t)
	var answer struct{ Loaded map[string]int }
	require.NoError(t, json.Unmarshal([]byte(loadNet(t, srv, append(fixtureRecording(t), rts)...)), &answer))
	assert.Equal(t, 1, answer.Loaded["route-table"])
	rec, ren := diffAnswer(t, srv, rts)
	assert.Empty(t, rec, "recorded only")
	assert.Empty(t, ren, "answered only")
}

func TestLoadEC2Routes_MainAssociationAnswersAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadNet(t, srv, append(fixtureRecording(t), routeTablesFixture(t))...)

	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeRouteTables", ec2FilterParams("association.main", "true")))
	assert.Equal(t, 1, strings.Count(string(body), "<vpcId>"), "one route table: %s", body)
	assert.Equal(t, fixtureRT, extractEC2Tag(body, "routeTableId"))
	assoc := extractEC2Tag(body, "associationSet")
	assert.Equal(t, fixtureRTAssoc, extractEC2Tag([]byte(assoc), "routeTableAssociationId"))
	assert.Equal(t, "true", extractEC2Tag([]byte(assoc), "main"))
	assert.NotContains(t, assoc, "subnetId")

	body = mustOK(t)(ec2Call(t, srv, netRegion, "DescribeRouteTables", ec2FilterParams("association.main", "false")))
	assert.NotContains(t, string(body), fixtureRT)
}

func TestLoadEC2Routes_MutateOnce(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	rts := routeTablesFixture(t)
	loadNet(t, srv, append(fixtureRecording(t), rts)...)

	mustOK(t)(ec2Call(t, srv, netRegion, "CreateRoute", url.Values{
		"RouteTableId": {fixtureRT}, "DestinationCidrBlock": {"192.168.0.0/16"}, "GatewayId": {"igw-0EXAMPLE"}}))
	rec, ren := diffAnswer(t, srv, rts)
	assert.Empty(t, rec)
	assert.Equal(t, []string{"routeTableSet/item[0]/routeSet/item[3]"}, ren)
}

// TestLoadEC2Routes_MainAssociationStays: DisassociateRouteTable on a
// main association is refused, and the association is still answered.
//
// UNVERIFIED(aws-code): InvalidParameterValue from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func TestLoadEC2Routes_MainAssociationStays(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	rts := routeTablesFixture(t)
	loadNet(t, srv, append(fixtureRecording(t), rts)...)

	resp, body := ec2Call(t, srv, netRegion, "DisassociateRouteTable", url.Values{"AssociationId": {fixtureRTAssoc}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s", body)
	assert.Equal(t, "InvalidParameterValue", extractEC2Tag(body, "Code"))
	assert.Contains(t, extractEC2Tag(body, "Message"), fixtureRTAssoc)
	rec, ren := diffAnswer(t, srv, rts)
	assert.Empty(t, rec)
	assert.Empty(t, ren)
}

// TestLoadEC2Routes_SubnetAssociations: a loaded subnet association
// answers as recorded beside its VPC's main one. DeleteSubnet drops it
// and leaves the main association, and a loaded subnet association
// disassociates.
func TestLoadEC2Routes_SubnetAssociations(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	const vpc = "vpc-0a"
	rts := netRouteTables(
		netRouteTable("rtb-0main", vpc, netAssociation("rtbassoc-0main", "rtb-0main", "")),
		netRouteTable("rtb-0a", vpc, netAssociation("rtbassoc-0a", "rtb-0a", "subnet-0a")),
		netRouteTable("rtb-0b", vpc, netAssociation("rtbassoc-0b", "rtb-0b", "subnet-0b")),
	)
	recording := append([]netRecorded{netVpcs(netVpc(vpc, "<isDefault>false</isDefault>")),
		netSubnets(netSubnet("subnet-0a", vpc, ""), netSubnet("subnet-0b", vpc, "")), rts}, netDNS(vpc, true)...)
	loadNet(t, srv, recording...)
	rec, ren := diffAnswer(t, srv, rts)
	assert.Empty(t, rec)
	assert.Empty(t, ren)

	mustOK(t)(ec2Call(t, srv, netRegion, "DeleteSubnet", url.Values{"SubnetId": {"subnet-0a"}}))
	mustOK(t)(ec2Call(t, srv, netRegion, "DisassociateRouteTable", url.Values{"AssociationId": {"rtbassoc-0b"}}))
	rec, ren = diffAnswer(t, srv, rts)
	assert.ElementsMatch(t, []string{"routeTableSet/item[1]/associationSet/item[0]", "routeTableSet/item[2]/associationSet/item[0]"}, rec)
	assert.Empty(t, ren)
	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeRouteTables", ec2FilterParams("association.main", "true")))
	assert.Contains(t, string(body), "<routeTableAssociationId>rtbassoc-0main</routeTableAssociationId>")
}

func TestLoadEC2Routes_Refusals(t *testing.T) {
	const vpc = "vpc-0a"
	base := append([]netRecorded{netVpcs(netVpc(vpc, "<isDefault>false</isDefault>"))}, netDNS(vpc, true)...)
	cases := map[string]struct {
		rts  netRecorded
		want string
	}{
		"a second main association of one VPC": {
			netRouteTables(netRouteTable("rtb-0a", vpc, netAssociation("rtbassoc-0a", "rtb-0a", "")),
				netRouteTable("rtb-0b", vpc, netAssociation("rtbassoc-0b", "rtb-0b", ""))),
			"exchange 3: ec2 DescribeRouteTables: route-table rtb-0b: association rtbassoc-0b is a second main association of vpc vpc-0a",
		},
		"a route table whose VPC was not recorded": {
			netRouteTables(netRouteTable("rtb-0a", "vpc-0missing", "")),
			"exchange 3: ec2 DescribeRouteTables: route-table rtb-0a names vpc vpc-0missing, which no exchange loaded",
		},
		"an association whose subnet was not recorded": {
			netRouteTables(netRouteTable("rtb-0a", vpc, netAssociation("rtbassoc-0a", "rtb-0a", "subnet-0missing"))),
			"exchange 3: ec2 DescribeRouteTables: route-table rtb-0a: association rtbassoc-0a names subnet subnet-0missing, which no exchange loaded",
		},
		"an IPv6 route": {
			netRouteTables(strings.Replace(netRouteTable("rtb-0a", vpc, ""), "</routeSet>",
				"<item><destinationIpv6CidrBlock>::/0</destinationIpv6CidrBlock><gatewayId>local</gatewayId><state>active</state><origin>CreateRouteTable</origin></item></routeSet>", 1)),
			"exchange 3: ec2 DescribeRouteTables: route-table rtb-0a holds a route with no destinationCidrBlock, which fakeaws cannot hold",
		},
		"a propagating gateway": {
			netRouteTables(netRouteTable("rtb-0a", vpc, "<propagatingVgwSet><item><gatewayId>vgw-0a</gatewayId></item></propagatingVgwSet>")),
			"exchange 3: ec2 DescribeRouteTables: route-table: the model cannot hold recorded routeTableSet/item[0]/propagatingVgwSet/item[0]",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
			seedLoadRows(t, srv)
			before := loadedState(t, app, srv)
			var exchanges []string
			for _, r := range append(base, c.rts) {
				exchanges = append(exchanges, r.exchange())
			}
			status, body := postLoad(t, srv, loadEnvelope(loadAccount, netRegion, exchanges...))
			require.Equal(t, http.StatusBadRequest, status, body)
			assert.Contains(t, loadRefusals(t, body), c.want)
			assert.Equal(t, before, loadedState(t, app, srv), "a refused load stored something")
		})
	}
}
