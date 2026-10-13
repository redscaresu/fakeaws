package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

// The fixtures' standalone interfaces, the address associated with the
// first, and the key pair.
const (
	fixtureENI      = "eni-0f62d866"
	fixtureENI2     = "eni-a66ed5cf"
	fixtureEIP      = "eipalloc-08229861"
	fixtureEIPAssoc = "eipassoc-f0229899"
	fixtureKeyPair  = "key-0123456789abcdef0"
)

// computeFixtures are DescribeNetworkInterfaces.xml, DescribeAddresses.xml
// and DescribeKeyPairs.xml as the exchanges of the requests they answer.
func computeFixtures(t *testing.T) (enis, eips, keys netRecorded) {
	t.Helper()
	return netRecorded{"DescribeNetworkInterfaces", map[string]string{}, ec2Fixture(t, "DescribeNetworkInterfaces")},
		netRecorded{"DescribeAddresses", map[string]string{"AllocationId.1": fixtureEIP}, ec2Fixture(t, "DescribeAddresses")},
		netRecorded{"DescribeKeyPairs", map[string]string{"KeyName.1": "my-key-pair"}, ec2Fixture(t, "DescribeKeyPairs")}
}

func TestLoadEC2Compute_FixturesAnswerAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	enis, eips, keys := computeFixtures(t)
	var answer struct{ Loaded map[string]int }
	require.NoError(t, json.Unmarshal([]byte(loadNet(t, srv, sgRecording(t, enis, eips, keys)...)), &answer))
	assert.Equal(t, 2, answer.Loaded["network-interface"])
	assert.Equal(t, 1, answer.Loaded["elastic-ip"])
	assert.Equal(t, 1, answer.Loaded["key-pair"])
	for _, r := range []netRecorded{enis, eips, keys} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s recorded only", r.action)
		assert.Empty(t, ren, "%s answered only", r.action)
	}
}

// TestLoadEC2Compute_StandaloneENI: a loaded interface with no instance
// answers no attachment, matches no attachment filter, and answers the
// association of the address associated with it, which answers its
// recorded association ids.
func TestLoadEC2Compute_StandaloneENI(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	enis, eips, _ := computeFixtures(t)
	loadNet(t, srv, sgRecording(t, enis, eips)...)
	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeNetworkInterfaces", url.Values{"NetworkInterfaceId.1": {fixtureENI}}))
	assert.NotContains(t, string(body), "<attachment>")
	assert.Equal(t, fixtureEIP, extractEC2Tag(body, "allocationId"))
	assert.Equal(t, fixtureEIPAssoc, extractEC2Tag(body, "associationId"))
	for _, filter := range []string{"attachment.instance-id", "attachment.attachment-id"} {
		body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeNetworkInterfaces", ec2FilterParams(filter, "*")))
		assert.NotContains(t, string(body), "<networkInterfaceId>", filter)
	}
	body = mustOK(t)(ec2Call(t, srv, netRegion, "DescribeAddresses", url.Values{"AllocationId.1": {fixtureEIP}}))
	assert.Equal(t, fixtureEIPAssoc, extractEC2Tag(body, "associationId"))
	assert.Equal(t, fixtureENI, extractEC2Tag(body, "networkInterfaceId"))
}

// TestLoadEC2Compute_KeyPairAsRecorded: a loaded key pair answers its
// keyType and createTime as recorded, and KeyPairId.N finds it.
func TestLoadEC2Compute_KeyPairAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	_, _, keys := computeFixtures(t)
	loadNet(t, srv, sgRecording(t, keys)...)
	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeKeyPairs", url.Values{"KeyPairId.1": {fixtureKeyPair}}))
	assert.Equal(t, "my-key-pair", extractEC2Tag(body, "keyName"))
	assert.Equal(t, "rsa", extractEC2Tag(body, "keyType"))
	assert.Equal(t, "2023-05-16T19:56:57.000Z", extractEC2Tag(body, "createTime"))
}

// TestLoadEC2Compute_MutateOnce: each Describe answers the recording
// but for the one change made after the load.
func TestLoadEC2Compute_MutateOnce(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	enis, eips, keys := computeFixtures(t)
	loadNet(t, srv, sgRecording(t, enis, eips, keys)...)

	mustOK(t)(ec2Call(t, srv, netRegion, "ModifyNetworkInterfaceAttribute", url.Values{
		"NetworkInterfaceId": {fixtureENI2}, "Description.Value": {"changed"}}))
	rec, ren := diffAnswer(t, srv, enis)
	assert.Equal(t, []string{"networkInterfaceSet/item[1]/description"}, rec)
	assert.Equal(t, []string{"networkInterfaceSet/item[1]/description"}, ren)

	mustOK(t)(ec2Call(t, srv, netRegion, "DisassociateAddress", url.Values{"AssociationId": {fixtureEIPAssoc}}))
	rec, ren = diffAnswer(t, srv, eips)
	assert.Equal(t, []string{"addressesSet/item[0]/associationId", "addressesSet/item[0]/networkInterfaceId",
		"addressesSet/item[0]/networkInterfaceOwnerId", "addressesSet/item[0]/privateIpAddress"}, rec)
	assert.Empty(t, ren)

	mustOK(t)(ec2Call(t, srv, netRegion, "CreateTags", url.Values{"ResourceId.1": {fixtureKeyPair}, "Tag.1.Key": {"Name"}, "Tag.1.Value": {"k"}}))
	rec, ren = diffAnswer(t, srv, keys)
	assert.Empty(t, rec)
	assert.Equal(t, []string{"keySet/item[0]/tagSet/item[0]"}, ren)
}

// TestLoadEC2Compute_ModifyENIRefusesAnUnmodelledAttribute: an
// attribute fakeaws does not model beside Description.Value is refused
// 501 naming it, and the description stays as recorded.
func TestLoadEC2Compute_ModifyENIRefusesAnUnmodelledAttribute(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	enis, eips, _ := computeFixtures(t)
	loadNet(t, srv, sgRecording(t, enis, eips)...)
	resp, body := ec2Call(t, srv, netRegion, "ModifyNetworkInterfaceAttribute", url.Values{
		"NetworkInterfaceId": {fixtureENI2}, "Description.Value": {"changed"}, "SourceDestCheck.Value": {"false"}})
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	assert.Contains(t, string(body), "SourceDestCheck.Value")
	rec, ren := diffAnswer(t, srv, enis)
	assert.Empty(t, rec)
	assert.Empty(t, ren)
}

func TestLoadEC2Compute_Refusals(t *testing.T) {
	enis, eips, _ := computeFixtures(t)
	base := sgRecording(t)
	at := func(i int, action string) string { return fmt.Sprintf("exchange %d: ec2 %s: ", len(base)+i, action) }
	attached := strings.Replace(enis.body, "<groupSet>", "<attachment><attachmentId>eni-attach-6537fc0c</attachmentId>"+
		"<instanceId>i-1234567890abcdef0</instanceId><deviceIndex>0</deviceIndex><status>attached</status></attachment><groupSet>", 1)
	cases := map[string]struct {
		recording []netRecorded
		want      string
	}{
		"an interface attached to an instance not recorded": {
			[]netRecorded{{enis.action, enis.params, attached}, eips},
			at(0, "DescribeNetworkInterfaces") + "network-interface " + fixtureENI + " is attached to instance i-1234567890abcdef0, which no exchange loaded",
		},
		"an interface associated with an address not recorded": {
			[]netRecorded{enis},
			at(0, "DescribeNetworkInterfaces") + "network-interface " + fixtureENI + " references elastic-ip " + fixtureEIP + ", which no exchange loaded",
		},
		"an address associated with an instance": {
			[]netRecorded{enis, {eips.action, eips.params, strings.Replace(eips.body, "<domain>vpc</domain>", "<domain>vpc</domain><instanceId>i-0598c7d356eba48d7</instanceId>", 1)}},
			at(1, "DescribeAddresses") + "elastic-ip " + fixtureEIP + " references instance i-0598c7d356eba48d7, which no exchange loaded",
		},
		"an interface in a subnet not recorded": {
			[]netRecorded{{enis.action, enis.params, strings.Replace(enis.body, "<subnetId>subnet-02bf4c428bf44ebce<", "<subnetId>subnet-0missing<", 1)}, eips},
			at(0, "DescribeNetworkInterfaces") + "network-interface " + fixtureENI2 + " references subnet subnet-0missing, which no exchange loaded",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
			seedLoadRows(t, srv)
			before := loadedState(t, app, srv)
			var exchanges []string
			for _, r := range append(base, c.recording...) {
				exchanges = append(exchanges, r.exchange())
			}
			status, body := postLoad(t, srv, loadEnvelope(loadAccount, netRegion, exchanges...))
			require.Equal(t, http.StatusBadRequest, status, body)
			assert.Contains(t, loadRefusals(t, body), c.want)
			assert.Equal(t, before, loadedState(t, app, srv), "a refused load stored something")
		})
	}
}
