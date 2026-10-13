package handlers_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
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

// TestLoadEC2Compute_AttachedWithoutInstanceRefusedByItsAttachment: an
// interface attached at device index 1 with no instance (a NAT gateway's
// or a load balancer's) is refused as before instances loaded, by the
// rendering diff naming its attachment, which no row holds; never as an
// instance's secondary interface.
func TestLoadEC2Compute_AttachedWithoutInstanceRefusedByItsAttachment(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	enis, eips, _ := computeFixtures(t)
	const tags = "</groupSet>\n         <tagSet>\n           <item>"
	require.Contains(t, enis.body, tags)
	enis.body = strings.Replace(enis.body, tags, "</groupSet><attachment><attachmentId>ela-attach-0abc</attachmentId>"+
		"<instanceOwnerId>amazon-elb</instanceOwnerId><deviceIndex>1</deviceIndex><networkCardIndex>0</networkCardIndex>"+
		"<status>attached</status><deleteOnTermination>false</deleteOnTermination></attachment><tagSet><item>", 1)
	var exchanges []string
	for _, r := range sgRecording(t, enis, eips) {
		exchanges = append(exchanges, r.exchange())
	}
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, netRegion, exchanges...))
	require.Equal(t, http.StatusBadRequest, status, body)
	refusals := loadRefusals(t, body)
	assert.Contains(t, refusals, fmt.Sprintf("exchange %d: ec2 DescribeNetworkInterfaces: network-interface %s: the model cannot hold recorded networkInterfaceSet/item[1]/attachment/deviceIndex",
		len(sgRecording(t)), fixtureENI2))
	for _, r := range refusals {
		assert.NotContains(t, r, "device index", "refused as a secondary interface")
	}
}

// TestLoadEC2Compute_ModifyENIOneAttributePerCall: an attribute fakeaws
// does not model beside Description.Value, or Groups and Description in
// one call, which EC2 refuses, is refused 501 naming each, and the
// interface stays as recorded.
func TestLoadEC2Compute_ModifyENIOneAttributePerCall(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	enis, eips, _ := computeFixtures(t)
	loadNet(t, srv, sgRecording(t, enis, eips)...)
	for name, c := range map[string]struct {
		param, value string
		named        []string
	}{
		"an unmodelled attribute": {"SourceDestCheck.Value", "false", []string{"SourceDestCheck.Value"}},
		"groups and description":  {"SecurityGroupId.1", fixtureSG, []string{"SecurityGroupId.N", "Description.Value"}},
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := ec2Call(t, srv, netRegion, "ModifyNetworkInterfaceAttribute", url.Values{
				"NetworkInterfaceId": {fixtureENI2}, "Description.Value": {"changed"}, c.param: {c.value}})
			assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
			for _, n := range c.named {
				assert.Contains(t, string(body), n)
			}
			rec, ren := diffAnswer(t, srv, enis)
			assert.Empty(t, rec)
			assert.Empty(t, ren)
		})
	}
}

// TestLoadEC2Compute_SecondaryPrivateIPsHeld: a private IP a loaded
// interface holds beside its primary one is refused to RunInstances as
// the primary's would be, and a free one beside them launches.
func TestLoadEC2Compute_SecondaryPrivateIPsHeld(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	enis, eips, _ := computeFixtures(t)
	loadNet(t, srv, sgRecording(t, enis, eips)...)
	const ami = "ami-0123456789abcdef0"
	mockOK(t, srv, http.MethodPost, "/mock/images", `{"ami_id":"`+ami+`","name":"al2023","region":"`+netRegion+`","root_device_name":"/dev/xvda","account_id":"`+loadAccount+`"}`)
	run := func(ip string) (*http.Response, []byte) {
		return ec2Call(t, srv, netRegion, "RunInstances", url.Values{"ImageId": {ami}, "InstanceType": {"t3.micro"},
			"SubnetId": {"subnet-0bb1c79de301436ee"}, "SecurityGroupId.1": {fixtureSG}, "PrivateIpAddress": {ip}})
	}
	for _, ip := range []string{"10.0.2.146", "10.0.2.148", "10.0.2.150"} {
		resp, body := run(ip)
		assert.Equal(t, http.StatusConflict, resp.StatusCode, "%s: %s", ip, body)
		assert.Equal(t, "ConflictException", extractEC2Tag(body, "Code"), ip)
	}
	resp, body := run("10.0.2.149")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a free address: %s", body)
}

// TestLoadEC2Compute_StandaloneENIHoldsItsNetwork: a loaded interface
// with no instance keeps its subnet, VPC and group from deletion, as an
// instance's interface does (the subnet and VPC 409 ResourceInUseException,
// the group 400 DependencyViolation), and still answers; the refused
// DeleteVpc leaves the VPC's internet gateway attached.
func TestLoadEC2Compute_StandaloneENIHoldsItsNetwork(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	enis, eips, _ := computeFixtures(t)
	loadNet(t, srv, sgRecording(t, enis, eips)...)
	for _, c := range []struct {
		action, param, id string
		status            int
		code              string
	}{
		{"DeleteSubnet", "SubnetId", "subnet-0bb1c79de301436ee", http.StatusConflict, "ResourceInUseException"},
		{"DeleteVpc", "VpcId", fixtureSGVpc, http.StatusConflict, "ResourceInUseException"},
		{"DeleteSecurityGroup", "GroupId", fixtureSG, http.StatusBadRequest, "DependencyViolation"},
	} {
		resp, body := ec2Call(t, srv, netRegion, c.action, url.Values{c.param: {c.id}})
		assert.Equal(t, c.status, resp.StatusCode, "%s: %s", c.action, body)
		assert.Equal(t, c.code, extractEC2Tag(body, "Code"), c.action)
	}
	igws := fixtureRecording(t)[3]
	for _, r := range []netRecorded{enis, igws} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s recorded only", r.action)
		assert.Empty(t, ren, "%s answered only", r.action)
	}
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
			at(0, "DescribeNetworkInterfaces") + "network-interface " + fixtureENI2 + " names subnet subnet-0missing, which no exchange loaded",
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
			refusals := loadRefusals(t, body)
			assert.Contains(t, refusals, c.want)
			for _, r := range refusals {
				assert.NotContains(t, r, "the load stopped there", "a refusal, never an abort")
			}
			assert.Equal(t, before, loadedState(t, app, srv), "a refused load stored something")
		})
	}
}

// TestLoadEC2Instances_InterfaceKeptOnTermination: an instance whose
// primary interface, holding an Elastic IP, was attached with
// deleteOnTermination false (a network_interface block naming an
// existing interface) loads, and both the instance and the interface
// answer false. Terminating the instance detaches the interface, which
// stays available with its address, as on EC2.
func TestLoadEC2Instances_InterfaceKeptOnTermination(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	_, _, keys := computeFixtures(t)
	_, _, attrs, _ := instanceFixtures(t)
	byID, eni, eips := instanceWithEIP(t)
	keep := strings.NewReplacer("<deleteOnTermination>true</deleteOnTermination>", "<deleteOnTermination>false</deleteOnTermination>")
	byID.body, eni.body = keep.Replace(byID.body), keep.Replace(eni.body)
	loadNet(t, srv, sgRecording(t, append([]netRecorded{keys, byID, eni, eips}, attrs...)...)...)
	for _, r := range []netRecorded{byID, eni} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s: recorded only", r.action)
		assert.Empty(t, ren, "%s: answered only", r.action)
		assert.Equal(t, "false", extractEC2Tag([]byte(resend(t, srv, r)), "deleteOnTermination"), r.action)
	}

	mustOK(t)(ec2Call(t, srv, netRegion, "TerminateInstances", url.Values{"InstanceId.1": {fixtureInstance}}))
	kept := []byte(resend(t, srv, eni))
	assert.Equal(t, "available", extractEC2Tag(kept, "status"))
	assert.NotContains(t, string(kept), "<attachment>")
	assert.Equal(t, fixtureEIP, extractEC2Tag(kept, "allocationId"), "the address stays associated with the interface")
	address := []byte(resend(t, srv, eips))
	assert.Equal(t, fixtureInstanceENI, extractEC2Tag(address, "networkInterfaceId"))
	assert.Empty(t, extractEC2Tag(address, "instanceId"))
}

// DescribeInstances.xml's instance, its interface, image and profile.
const (
	fixtureInstance    = "i-1234567890abcdef0"
	fixtureInstanceENI = "eni-551ba033"
	fixtureImage       = "ami-bff32ccc"
	fixtureProfileARN  = "arn:aws:iam::123456789012:instance-profile/application_abc/component_xyz/Webserver"
	fixtureProfileID   = "AIPACZLS2TD2HEXAMPLE"
)

// instanceFixtures are DescribeInstances.xml as the answer to a read by
// id and to one by vpc-id, each DescribeInstanceAttribute-*.xml, and
// DescribeNetworkInterfaces-instance.xml.
func instanceFixtures(t *testing.T) (byID, byVpc netRecorded, attrs []netRecorded, eni netRecorded) {
	t.Helper()
	body := ec2Fixture(t, "DescribeInstances")
	byID = netRecorded{"DescribeInstances", map[string]string{"InstanceId.1": fixtureInstance}, body}
	byVpc = netRecorded{"DescribeInstances", map[string]string{"Filter.1.Name": "vpc-id", "Filter.1.Value.1": fixtureSGVpc}, body}
	for _, attr := range handlers.InstanceReadAttributes {
		attrs = append(attrs, netRecorded{"DescribeInstanceAttribute", map[string]string{"InstanceId": fixtureInstance, "Attribute": attr},
			ec2Fixture(t, "DescribeInstanceAttribute-"+attr)})
	}
	eni = netRecorded{"DescribeNetworkInterfaces", map[string]string{"NetworkInterfaceId.1": fixtureInstanceENI}, ec2Fixture(t, "DescribeNetworkInterfaces-instance")}
	return byID, byVpc, attrs, eni
}

// instanceRecording is sgRecording with the key pair, the instance read
// both ways, its attributes and its interface.
func instanceRecording(t *testing.T) []netRecorded {
	t.Helper()
	_, _, keys := computeFixtures(t)
	byID, byVpc, attrs, eni := instanceFixtures(t)
	return sgRecording(t, append([]netRecorded{keys, byID, byVpc, eni}, attrs...)...)
}

// TestLoadEC2Instances_AnswerAsRecorded: a loaded instance with no block
// device answers DescribeInstances by id and by vpc-id, each attribute
// and its interface as recorded, its launchTime, privateDnsName and its
// profile's recorded AIPA id included; its image and profile, which no
// exchange holds, are unresolved.
func TestLoadEC2Instances_AnswerAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	recording := instanceRecording(t)
	var answer struct {
		Loaded     map[string]int
		Unresolved map[string][]string
	}
	require.NoError(t, json.Unmarshal([]byte(loadNet(t, srv, recording...)), &answer))
	assert.Equal(t, 1, answer.Loaded["instance"], "read by id and by vpc-id, it loads once")
	assert.Equal(t, 4, answer.Loaded["instance-attribute"])
	assert.Equal(t, 1, answer.Loaded["network-interface"])
	assert.Equal(t, map[string][]string{"dhcp-options": {"dopt-19edf471", "dopt-f30d649a"},
		"image": {fixtureImage}, "instance-profile": {"Webserver"}}, answer.Unresolved)
	for _, r := range recording {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s %v: recorded only", r.action, r.params)
		assert.Empty(t, ren, "%s %v: answered only", r.action, r.params)
	}
	byID, _, _, _ := instanceFixtures(t)
	body := []byte(resend(t, srv, byID))
	assert.Equal(t, "2018-05-08T16:46:19.000Z", extractEC2Tag(body, "launchTime"))
	assert.Equal(t, "ip-10-0-2-88.us-west-2.compute.internal", extractEC2Tag(body, "privateDnsName"))
	assert.Equal(t, fixtureProfileID, extractEC2Tag(body, "id"))
	assert.Equal(t, fixtureProfileARN, extractEC2Tag(body, "arn"))
}

// TestLoadEC2Instances_UserDataByteExact: userData answers its recorded
// base64, whose script keeps its CR and its trailing newline.
func TestLoadEC2Instances_UserDataByteExact(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadNet(t, srv, instanceRecording(t)...)
	_, _, attrs, _ := instanceFixtures(t)
	userData := attrs[slices.Index(handlers.InstanceReadAttributes, "userData")]
	value := extractEC2Tag([]byte(resend(t, srv, userData)), "value")
	assert.Equal(t, extractEC2Tag([]byte(userData.body), "value"), value)
	script, err := base64.StdEncoding.DecodeString(value)
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/bash\r\nyum update -y\n", string(script))
}

// TestLoadEC2Instances_MutateOnce: after ModifyInstanceAttribute sets
// DisableApiTermination, DescribeInstances answers the recording, and of
// the attributes only disableApiTermination changed.
func TestLoadEC2Instances_MutateOnce(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadNet(t, srv, instanceRecording(t)...)
	mustOK(t)(ec2Call(t, srv, netRegion, "ModifyInstanceAttribute", url.Values{
		"InstanceId": {fixtureInstance}, "DisableApiTermination.Value": {"true"}}))
	byID, byVpc, attrs, _ := instanceFixtures(t)
	for _, r := range []netRecorded{byID, byVpc} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%v: recorded only", r.params)
		assert.Empty(t, ren, "%v: answered only", r.params)
	}
	for _, r := range attrs {
		var want []string
		if r.params["Attribute"] == "disableApiTermination" {
			want = []string{"disableApiTermination/value"}
		}
		rec, ren := diffAnswer(t, srv, r)
		assert.Equal(t, want, rec, r.params["Attribute"])
		assert.Equal(t, want, ren, r.params["Attribute"])
	}
}

// TestLoadEC2Instances_ElasticIPAnswersItsOwner: an instance whose
// interface holds an Elastic IP answers that association as recorded,
// the account its owner and without the address's ids, which only the
// interface's own item answers.
func TestLoadEC2Instances_ElasticIPAnswersItsOwner(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	_, _, keys := computeFixtures(t)
	_, _, attrs, _ := instanceFixtures(t)
	byID, eni, eips := instanceWithEIP(t)
	recording := sgRecording(t, append([]netRecorded{keys, byID, eni, eips}, attrs...)...)
	loadNet(t, srv, recording...)
	for _, r := range []netRecorded{byID, eni, eips} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s: recorded only", r.action)
		assert.Empty(t, ren, "%s: answered only", r.action)
	}
}

// instanceWithEIP is DescribeInstances.xml read by id, its interface
// and DescribeAddresses.xml, edited so the address is associated with
// the instance's interface.
func instanceWithEIP(t *testing.T) (byID, eni, eips netRecorded) {
	t.Helper()
	_, eips, _ = computeFixtures(t)
	byID, _, _, eni = instanceFixtures(t)
	association := "<association><publicIp>203.0.113.41</publicIp><ipOwnerId>" + loadAccount + "</ipOwnerId>"
	byID.body = strings.NewReplacer(
		"<privateIpAddress>10.0.2.88</privateIpAddress>\n                    <sourceDestCheck>",
		"<privateIpAddress>10.0.2.88</privateIpAddress><ipAddress>203.0.113.41</ipAddress><sourceDestCheck>",
		"</attachment>", "</attachment>"+association+"</association>").Replace(byID.body)
	eni.body = strings.Replace(eni.body, "</attachment>", "</attachment>"+association+
		"<allocationId>"+fixtureEIP+"</allocationId><associationId>"+fixtureEIPAssoc+"</associationId></association>", 1)
	eips.body = strings.NewReplacer(fixtureENI, fixtureInstanceENI, "10.0.2.146", "10.0.2.88",
		"<domain>vpc</domain>", "<domain>vpc</domain><instanceId>"+fixtureInstance+"</instanceId>").Replace(eips.body)
	return byID, eni, eips
}

// TestLoadEC2Instances_RunInstancesAnswersStoredProfileARN: an instance
// launched with a loaded profile answers the profile's recorded ARN,
// path included, and its id, not an ARN built from the name.
func TestLoadEC2Instances_RunInstancesAnswersStoredProfileARN(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	var exchanges []string
	for _, r := range fixtureRecording(t) {
		exchanges = append(exchanges, r.exchange())
	}
	for _, r := range iamRoleRead {
		exchanges = append(exchanges, loadPage("iam", r.action, r.params, http.StatusOK, iamFixture(t, r.fixture)))
	}
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, netRegion, exchanges...))
	require.Equal(t, http.StatusOK, status, body)
	const ami = "ami-0123456789abcdef0"
	mockOK(t, srv, http.MethodPost, "/mock/images", `{"ami_id":"`+ami+`","name":"al2023","region":"`+netRegion+`","root_device_name":"/dev/xvda","account_id":"`+loadAccount+`"}`)
	run := mustOK(t)(ec2Call(t, srv, netRegion, "RunInstances", url.Values{"ImageId": {ami}, "InstanceType": {"t3.micro"},
		"SubnetId": {"subnet-0bb1c79de301436ee"}, "IamInstanceProfile.Name": {"Webserver"}}))
	described := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeInstances", url.Values{"InstanceId.1": {extractEC2Tag(run, "instanceId")}}))
	for action, body := range map[string][]byte{"RunInstances": run, "DescribeInstances": described} {
		assert.Equal(t, fixtureProfileARN, extractEC2Tag(body, "arn"), action)
		assert.Equal(t, fixtureProfileID, extractEC2Tag(body, "id"), action)
	}
}

func TestLoadEC2Instances_Refusals(t *testing.T) {
	_, _, keys := computeFixtures(t)
	byID, _, attrs, eni := instanceFixtures(t)
	base := sgRecording(t)
	at := func(i int, action string) string { return fmt.Sprintf("exchange %d: ec2 %s: ", len(base)+i, action) }
	edit := func(r netRecorded, old, new string) netRecorded {
		require.Contains(t, r.body, old)
		return netRecorded{r.action, r.params, strings.Replace(r.body, old, new, 1)}
	}
	instance := "instance " + fixtureInstance
	cases := map[string]struct {
		recording []netRecorded
		want      string
	}{
		"a block device volume not recorded": {
			append([]netRecorded{keys, eni, edit(byID, "<blockDeviceMapping/>", "<blockDeviceMapping><item><deviceName>/dev/xvda</deviceName>"+
				"<ebs><volumeId>vol-0abc</volumeId><status>attached</status><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMapping>")}, attrs...),
			at(2, "DescribeInstances") + instance + " references volume vol-0abc, which no exchange loaded",
		},
		"a primary interface whose private IP differs from its own item": {
			append([]netRecorded{keys, edit(eni, "<privateIpAddress>10.0.2.88</privateIpAddress>\n         <privateDnsName>",
				"<privateIpAddress>10.0.2.89</privateIpAddress>\n         <privateDnsName>"), byID}, attrs...),
			at(2, "DescribeInstances") + instance + ": its network-interface " + fixtureInstanceENI + "'s privateIpAddress differs from exchange " +
				fmt.Sprint(len(base)+1) + "'s (ec2 DescribeNetworkInterfaces)",
		},
		"a secondary interface attached to the instance": {
			append([]netRecorded{keys, eni, byID, {eni.action, map[string]string{"NetworkInterfaceId.1": "eni-0secondary"},
				strings.NewReplacer(fixtureInstanceENI, "eni-0secondary", "10.0.2.88", "10.0.2.90", "ip-10-0-2-88", "ip-10-0-2-90",
					"<deviceIndex>0<", "<deviceIndex>1<", "eni-attach-39697adc", "eni-attach-0secondary").Replace(eni.body)}}, attrs...),
			at(3, "DescribeNetworkInterfaces") + "network-interface eni-0secondary is attached to instance " + fixtureInstance +
				" at device index 1: only an instance's primary interface (device index 0) is modelled",
		},
		"a primary interface naming a group not recorded": {
			append([]netRecorded{keys, {eni.action, eni.params, strings.ReplaceAll(eni.body, fixtureSG, "sg-0missing")}, byID}, attrs...),
			at(1, "DescribeNetworkInterfaces") + "network-interface " + fixtureInstanceENI + " references security-group sg-0missing, which no exchange loaded",
		},
		"a key pair not recorded": {
			append([]netRecorded{eni, byID}, attrs...),
			at(1, "DescribeInstances") + instance + " references key-pair my-key-pair, which no exchange loaded",
		},
		"an attribute not recorded": {
			append([]netRecorded{keys, eni, byID}, attrs[1:]...),
			at(2, "DescribeInstances") + instance + " references instance-attribute " + fixtureInstance + "/" + handlers.InstanceReadAttributes[0] + ", which no exchange loaded",
		},
		"an attribute of an instance not recorded": {
			append([]netRecorded{keys, eni, byID}, append(attrs, edit(attrs[0], "<instanceId>"+fixtureInstance, "<instanceId>i-0missing"))...),
			at(7, "DescribeInstanceAttribute") + "instance-attribute i-0missing/" + handlers.InstanceReadAttributes[0] + " names instance i-0missing, which no exchange loaded",
		},
		"an instance in a subnet not recorded": {
			append([]netRecorded{keys, eni, edit(byID, "<subnetId>subnet-0bb1c79de301436ee</subnetId>\n                    <vpcId>",
				"<subnetId>subnet-0missing</subnetId>\n                    <vpcId>")}, attrs...),
			at(2, "DescribeInstances") + instance + " names subnet subnet-0missing, which no exchange loaded",
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
			refusals := loadRefusals(t, body)
			assert.Contains(t, refusals, c.want)
			for _, r := range refusals {
				assert.NotContains(t, r, "the load stopped there", "a refusal, never an abort")
			}
			assert.Equal(t, before, loadedState(t, app, srv), "a refused load stored something")
		})
	}
}

// DescribeVolumes.xml's volume, the root volume of DescribeInstances.xml's
// instance, its snapshot and its KMS key.
const (
	fixtureVolume   = "vol-1234567890abcdef0"
	fixtureSnapshot = "snap-0abc1234567890def"
	fixtureKMSKey   = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
)

// volumeFixtures are DescribeVolumes.xml, through edit, as the answer
// to a read by VolumeId.1 and to one by attachment.instance-id.
func volumeFixtures(t *testing.T, edit *strings.Replacer) (byID, byInstance netRecorded) {
	t.Helper()
	body := edit.Replace(ec2Fixture(t, "DescribeVolumes"))
	return netRecorded{"DescribeVolumes", map[string]string{"VolumeId.1": fixtureVolume}, body},
		netRecorded{"DescribeVolumes", map[string]string{"Filter.1.Name": "attachment.instance-id", "Filter.1.Value.1": fixtureInstance}, body}
}

// deleteOnTermination sets DescribeVolumes.xml's attachment's
// deleteOnTermination to v.
func deleteOnTermination(v string) *strings.Replacer {
	return strings.NewReplacer("<deleteOnTermination>true<", "<deleteOnTermination>"+v+"<")
}

// volumeRecording is instanceRecording with the instance's root volume
// in its blockDeviceMapping, deleted on termination as onTermination
// says, and both volumeFixtures reads.
func volumeRecording(t *testing.T, onTermination string) []netRecorded {
	t.Helper()
	_, _, keys := computeFixtures(t)
	byID, byVpc, attrs, eni := instanceFixtures(t)
	root := strings.NewReplacer("<blockDeviceMapping/>", "<blockDeviceMapping><item><deviceName>/dev/xvda</deviceName><ebs>"+
		"<volumeId>"+fixtureVolume+"</volumeId><status>attached</status><attachTime>2018-05-08T16:46:19.000Z</attachTime>"+
		"<deleteOnTermination>"+onTermination+"</deleteOnTermination></ebs></item></blockDeviceMapping>")
	byID.body, byVpc.body = root.Replace(byID.body), root.Replace(byVpc.body)
	vols, volsByInstance := volumeFixtures(t, deleteOnTermination(onTermination))
	return sgRecording(t, append([]netRecorded{keys, byID, byVpc, eni, vols, volsByInstance}, attrs...)...)
}

// TestLoadEC2Volumes_AnswerAsRecorded: an instance loaded with its
// root volume loads, the volume once though read by id and by
// attachment.instance-id; every read answers as recorded, and the
// volume's snapshot and KMS key are unresolved.
func TestLoadEC2Volumes_AnswerAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	recording := volumeRecording(t, "true")
	var answer struct {
		Loaded     map[string]int
		Unresolved map[string][]string
	}
	require.NoError(t, json.Unmarshal([]byte(loadNet(t, srv, recording...)), &answer))
	assert.Equal(t, 1, answer.Loaded["instance"])
	assert.Equal(t, 1, answer.Loaded["volume"])
	assert.Equal(t, []string{fixtureSnapshot}, answer.Unresolved["snapshot"])
	assert.Equal(t, []string{fixtureKMSKey}, answer.Unresolved["kms-key"])
	for _, r := range recording {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s %v: recorded only", r.action, r.params)
		assert.Empty(t, ren, "%s %v: answered only", r.action, r.params)
	}
}

// ec2VolumesState is /mock/state's ec2.volumes ids.
func ec2VolumesState(t *testing.T, srv *httptest.Server) []string {
	t.Helper()
	var state struct {
		EC2 struct {
			Volumes []struct{ ID string } `json:"volumes"`
		} `json:"ec2"`
	}
	require.NoError(t, json.Unmarshal([]byte(mockOK(t, srv, http.MethodGet, "/mock/state", "")), &state))
	ids := []string{}
	for _, v := range state.EC2.Volumes {
		ids = append(ids, v.ID)
	}
	return ids
}

// TestContract_ec2_volume_removed_on_terminate: /mock/state lists the
// loaded volume; terminating its instance deletes it, as its
// deleteOnTermination says, so VolumeId.1 answers InvalidVolume.NotFound
// and /mock/state lists none.
func TestContract_ec2_volume_removed_on_terminate(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadNet(t, srv, volumeRecording(t, "true")...)
	assert.Equal(t, []string{fixtureVolume}, ec2VolumesState(t, srv))

	mustOK(t)(ec2Call(t, srv, netRegion, "TerminateInstances", url.Values{"InstanceId.1": {fixtureInstance}}))
	resp, body := ec2Call(t, srv, netRegion, "DescribeVolumes", url.Values{"VolumeId.1": {fixtureVolume}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s", body)
	assert.Equal(t, "InvalidVolume.NotFound", extractEC2Tag(body, "Code"))
	assert.Empty(t, ec2VolumesState(t, srv))
}

// TestLoadEC2Volumes_MutateOnce: a volume attached with
// deleteOnTermination false stays after its instance terminates, and
// answers the recording but for its status, available, and its
// attachment, which is gone.
func TestLoadEC2Volumes_MutateOnce(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadNet(t, srv, volumeRecording(t, "false")...)
	mustOK(t)(ec2Call(t, srv, netRegion, "TerminateInstances", url.Values{"InstanceId.1": {fixtureInstance}}))

	byID, byInstance := volumeFixtures(t, deleteOnTermination("false"))
	rec, ren := diffAnswer(t, srv, byID)
	assert.Equal(t, []string{"volumeSet/item[0]/attachmentSet/item[0]", "volumeSet/item[0]/status"}, rec)
	assert.Equal(t, []string{"volumeSet/item[0]/status"}, ren)
	assert.Equal(t, "available", extractEC2Tag([]byte(resend(t, srv, byID)), "status"))
	assert.NotContains(t, resend(t, srv, byInstance), "<volumeId>", "detached, it matches no attachment.instance-id")
	assert.Equal(t, []string{fixtureVolume}, ec2VolumesState(t, srv))
}

// TestLoadEC2Volumes_Filters: each modelled filter selects the loaded
// volume by its value and drops it by another; an unmodelled one is
// refused.
func TestLoadEC2Volumes_Filters(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadNet(t, srv, volumeRecording(t, "true")...)
	for name, values := range map[string][2]string{
		"volume-id":                        {fixtureVolume, "vol-0other"},
		"attachment.instance-id":           {fixtureInstance, "i-0other"},
		"attachment.delete-on-termination": {"true", "false"},
		"status":                           {"in-use", "available"},
		"availability-zone":                {"us-west-2c", "us-west-2a"},
		"tag:Name":                         {"Server_1-root", "other"},
	} {
		body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeVolumes", ec2FilterParams(name, values[0])))
		assert.Equal(t, fixtureVolume, extractEC2Tag(body, "volumeId"), name)
		body = mustOK(t)(ec2Call(t, srv, netRegion, "DescribeVolumes", ec2FilterParams(name, values[1])))
		assert.NotContains(t, string(body), "<volumeId>", name)
	}
	resp, body := ec2Call(t, srv, netRegion, "DescribeVolumes", ec2FilterParams("volume-type", "gp3"))
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
	assert.Contains(t, string(body), "volume-type")
}

// TestLoadEC2Volumes_AttachedToAnInstanceNotRecorded: a volume attached
// to an instance no exchange loaded is refused naming both, and the
// load stores nothing.
func TestLoadEC2Volumes_AttachedToAnInstanceNotRecorded(t *testing.T) {
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	seedLoadRows(t, srv)
	before := loadedState(t, app, srv)
	vols, _ := volumeFixtures(t, strings.NewReplacer("<instanceId>"+fixtureInstance, "<instanceId>i-0missing"))
	var exchanges []string
	for _, r := range sgRecording(t, vols) {
		exchanges = append(exchanges, r.exchange())
	}
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, netRegion, exchanges...))
	require.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, loadRefusals(t, body), fmt.Sprintf("exchange %d: ec2 DescribeVolumes: volume %s is attached to instance i-0missing, which no exchange loaded",
		len(sgRecording(t)), fixtureVolume))
	assert.Equal(t, before, loadedState(t, app, srv), "a refused load stored something")
}

// TestLoadEC2Volumes_Tags: CreateTags and DeleteTags take a loaded
// volume's id, and DescribeVolumes answers the change.
func TestLoadEC2Volumes_Tags(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadNet(t, srv, volumeRecording(t, "true")...)
	mustOK(t)(ec2Call(t, srv, netRegion, "CreateTags", url.Values{"ResourceId.1": {fixtureVolume}, "Tag.1.Key": {"Env"}, "Tag.1.Value": {"prod"}}))
	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeVolumes", ec2FilterParams("tag:Env", "prod")))
	assert.Equal(t, fixtureVolume, extractEC2Tag(body, "volumeId"))

	mustOK(t)(ec2Call(t, srv, netRegion, "DeleteTags", url.Values{"ResourceId.1": {fixtureVolume}, "Tag.1.Key": {"Name"}}))
	byID, _ := volumeFixtures(t, deleteOnTermination("true"))
	answered := resend(t, srv, byID)
	assert.Contains(t, answered, "<key>Env</key>")
	assert.NotContains(t, answered, "<key>Name</key>")
}

// TestLoadEC2Volumes_AttachmentDisagreesWithBlockDeviceMapping: a volume
// whose attachment differs from its instance's blockDeviceMapping item,
// or which that blockDeviceMapping does not name, is refused naming
// both; so is an instance whose blockDeviceMapping names a volume not
// attached to it. The load stores nothing.
func TestLoadEC2Volumes_AttachmentDisagreesWithBlockDeviceMapping(t *testing.T) {
	for name, c := range map[string]struct {
		recording func(t *testing.T) []netRecorded
		want      string
	}{
		"deleteOnTermination false in the instance, true in the volume": {
			func(t *testing.T) []netRecorded {
				recording := volumeRecording(t, "false")
				for i, r := range recording {
					if r.action == "DescribeVolumes" {
						recording[i].body = strings.ReplaceAll(r.body, "<deleteOnTermination>false<", "<deleteOnTermination>true<")
					}
				}
				return recording
			},
			"volume " + fixtureVolume + ": its attachment to instance " + fixtureInstance + " differs from the instance's blockDeviceMapping at deleteOnTermination",
		},
		"a blockDeviceMapping volume recorded available, with no attachment": {
			func(t *testing.T) []netRecorded {
				recording := volumeRecording(t, "true")
				detached := regexp.MustCompile(`(?s)<attachmentSet>.*</attachmentSet>`)
				for i, r := range recording {
					if r.action == "DescribeVolumes" {
						recording[i].body = strings.Replace(detached.ReplaceAllString(r.body, "<attachmentSet/>"), "<status>in-use<", "<status>available<", 1)
					}
				}
				return recording
			},
			"instance " + fixtureInstance + ": its blockDeviceMapping names volume " + fixtureVolume + ", which is not attached to it",
		},
		"an instance with no block device": {
			func(t *testing.T) []netRecorded {
				vols, _ := volumeFixtures(t, deleteOnTermination("true"))
				return append(instanceRecording(t), vols)
			},
			"volume " + fixtureVolume + " is attached to instance " + fixtureInstance + ", whose blockDeviceMapping does not name it",
		},
	} {
		t.Run(name, func(t *testing.T) {
			app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
			seedLoadRows(t, srv)
			before := loadedState(t, app, srv)
			var exchanges []string
			for _, r := range c.recording(t) {
				exchanges = append(exchanges, r.exchange())
			}
			status, body := postLoad(t, srv, loadEnvelope(loadAccount, netRegion, exchanges...))
			require.Equal(t, http.StatusBadRequest, status, body)
			assert.True(t, slices.ContainsFunc(loadRefusals(t, body), func(r string) bool { return strings.HasSuffix(r, ": "+c.want) }), body)
			assert.Equal(t, before, loadedState(t, app, srv), "a refused load stored something")
		})
	}
}
