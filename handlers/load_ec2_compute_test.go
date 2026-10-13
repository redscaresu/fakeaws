package handlers_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
// primary interface was attached with deleteOnTermination false (a
// network_interface block naming an existing interface) loads, and
// both the instance and the interface answer false.
func TestLoadEC2Instances_InterfaceKeptOnTermination(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	_, _, keys := computeFixtures(t)
	byID, _, attrs, eni := instanceFixtures(t)
	keep := strings.NewReplacer("<deleteOnTermination>true</deleteOnTermination>", "<deleteOnTermination>false</deleteOnTermination>")
	byID.body, eni.body = keep.Replace(byID.body), keep.Replace(eni.body)
	loadNet(t, srv, sgRecording(t, append([]netRecorded{keys, byID, eni}, attrs...)...)...)
	for _, r := range []netRecorded{byID, eni} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s: recorded only", r.action)
		assert.Empty(t, ren, "%s: answered only", r.action)
		assert.Equal(t, "false", extractEC2Tag([]byte(resend(t, srv, r)), "deleteOnTermination"), r.action)
	}
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
	_, eips, keys := computeFixtures(t)
	byID, _, attrs, eni := instanceFixtures(t)
	association := "<association><publicIp>203.0.113.41</publicIp><ipOwnerId>" + loadAccount + "</ipOwnerId>"
	byID.body = strings.NewReplacer(
		"<privateIpAddress>10.0.2.88</privateIpAddress>\n                    <sourceDestCheck>",
		"<privateIpAddress>10.0.2.88</privateIpAddress><ipAddress>203.0.113.41</ipAddress><sourceDestCheck>",
		"</attachment>", "</attachment>"+association+"</association>").Replace(byID.body)
	eni.body = strings.Replace(eni.body, "</attachment>", "</attachment>"+association+
		"<allocationId>"+fixtureEIP+"</allocationId><associationId>"+fixtureEIPAssoc+"</associationId></association>", 1)
	eips.body = strings.NewReplacer(fixtureENI, fixtureInstanceENI, "10.0.2.146", "10.0.2.88",
		"<domain>vpc</domain>", "<domain>vpc</domain><instanceId>"+fixtureInstance+"</instanceId>").Replace(eips.body)
	recording := sgRecording(t, append([]netRecorded{keys, byID, eni, eips}, attrs...)...)
	loadNet(t, srv, recording...)
	for _, r := range []netRecorded{byID, eni, eips} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s: recorded only", r.action)
		assert.Empty(t, ren, "%s: answered only", r.action)
	}
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
