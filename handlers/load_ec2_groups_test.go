package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/repository"
)

// The fixtures' group, its VPC and its rules.
const (
	fixtureSG    = "sg-1234567890abcdef0"
	fixtureSGVpc = "vpc-0ee975135dEXAMPLE"
)

var fixtureSGRules = []string{"sgr-abcdef01234567890", "sgr-bcdef01234567890a", "sgr-cdef01234567890ab"}

// sgFixtures are DescribeSecurityGroups.xml and
// DescribeSecurityGroupRules.xml as the exchanges of the requests they
// answer.
func sgFixtures(t *testing.T) (groups, rules netRecorded) {
	t.Helper()
	return netRecorded{"DescribeSecurityGroups", map[string]string{"GroupId.1": fixtureSG}, ec2Fixture(t, "DescribeSecurityGroups")},
		netRecorded{"DescribeSecurityGroupRules", map[string]string{"Filter.1.Name": "group-id", "Filter.1.Value.1": fixtureSG},
			ec2Fixture(t, "DescribeSecurityGroupRules")}
}

// sgRecording is fixtureRecording with the group fixtures, then more.
func sgRecording(t *testing.T, more ...netRecorded) []netRecorded {
	groups, rules := sgFixtures(t)
	return append(append(fixtureRecording(t), groups, rules), more...)
}

// netGroups is a DescribeSecurityGroups answer to params holding items.
func netGroups(params map[string]string, items ...string) netRecorded {
	return netRecorded{"DescribeSecurityGroups", params,
		"<DescribeSecurityGroupsResponse><securityGroupInfo>" + strings.Join(items, "") + "</securityGroupInfo></DescribeSecurityGroupsResponse>"}
}

// netGroup is a securityGroupInfo item of group id named name in vpc,
// then more (permissions, tags).
func netGroup(id, vpc, name, more string) string {
	return "<item><ownerId>" + loadAccount + "</ownerId><groupId>" + id + "</groupId><groupName>" + name + "</groupName>" +
		"<groupDescription>" + name + "</groupDescription><vpcId>" + vpc + "</vpcId>" + more + "</item>"
}

// netIngress is an ipPermissions holding one tcp permission on port
// with sources, its items under list (ipRanges, groups, prefixListIds).
func netIngress(port, list, sources string) string {
	return "<ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>" + port + "</fromPort><toPort>" + port + "</toPort>" +
		"<" + list + ">" + sources + "</" + list + "></item></ipPermissions>"
}

// netRules is a DescribeSecurityGroupRules answer holding items.
func netRules(items ...string) netRecorded {
	return netRecorded{"DescribeSecurityGroupRules", map[string]string{},
		"<DescribeSecurityGroupRulesResponse><securityGroupRuleSet>" + strings.Join(items, "") + "</securityGroupRuleSet></DescribeSecurityGroupRulesResponse>"}
}

// netRule is an ingress tcp rule id of group on port with source.
func netRule(id, group, port, source string) string {
	return "<item><securityGroupRuleId>" + id + "</securityGroupRuleId><groupId>" + group + "</groupId><groupOwnerId>" + loadAccount +
		"</groupOwnerId><isEgress>false</isEgress><ipProtocol>tcp</ipProtocol><fromPort>" + port + "</fromPort><toPort>" + port +
		"</toPort>" + source + "</item>"
}

// netPair is a referencedGroupInfo of group in account.
func netPair(group, account string) string {
	return "<referencedGroupInfo><groupId>" + group + "</groupId><userId>" + account + "</userId></referencedGroupInfo>"
}

func TestLoadEC2Groups_FixturesAnswerAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	groups, rules := sgFixtures(t)
	var answer struct{ Loaded map[string]int }
	require.NoError(t, json.Unmarshal([]byte(loadNet(t, srv, sgRecording(t)...)), &answer))
	assert.Equal(t, 1, answer.Loaded["security-group"])
	assert.Equal(t, len(fixtureSGRules), answer.Loaded["security-group-rule"])
	for _, r := range []netRecorded{groups, rules} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec, "%s recorded only", r.action)
		assert.Empty(t, ren, "%s answered only", r.action)
	}
	body := resend(t, srv, groups)
	assert.Equal(t, "arn:aws:ec2:"+netRegion+":"+loadAccount+":security-group/"+fixtureSG, extractEC2Tag([]byte(body), "securityGroupArn"))
	assert.Less(t, strings.Index(body, "203.0.113.0/24"), strings.Index(body, "198.51.100.0/24"), "sources out of recorded order: %s", body)
}

// TestLoadEC2Groups_GroupStoredWithoutOwnerAnswersTheAccount: a group
// row stored before groups kept their owner answers the stored account.
func TestLoadEC2Groups_GroupStoredWithoutOwnerAnswersTheAccount(t *testing.T) {
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	vpc := extractEC2Tag(mustOK(t)(ec2Call(t, srv, netRegion, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})), "vpcId")
	require.NoError(t, app.Repository().CreateSecurityGroup(awsproto.FakeAccountID, &repository.EC2SecurityGroup{
		ID: "sg-0old", VPCID: vpc, GroupName: "old", Description: "old", Region: netRegion}))
	body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeSecurityGroups", url.Values{"GroupId.1": {"sg-0old"}}))
	assert.Equal(t, awsproto.FakeAccountID, extractEC2Tag(body, "ownerId"))
}

// TestLoadEC2Groups_SameGroupInTwoReadsLoadsOnce: a group the step-0
// read answers both to a tag-key and to a vpc-id DescribeSecurityGroups
// loads once and counts once. It holds no securityGroupArn, and answers
// none: a loaded group's ARN is never minted.
func TestLoadEC2Groups_SameGroupInTwoReadsLoadsOnce(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	group := netGroup("sg-0tagged", fixtureSGVpc, "tagged", netTags("infrafactory-run-id", "r1"))
	byTag := netGroups(map[string]string{"Filter.1.Name": "tag-key", "Filter.1.Value.1": "infrafactory-run-id"}, group)
	byVpc := netGroups(map[string]string{"Filter.1.Name": "vpc-id", "Filter.1.Value.1": fixtureSGVpc}, group)
	var answer struct{ Loaded map[string]int }
	require.NoError(t, json.Unmarshal([]byte(loadNet(t, srv, append(fixtureRecording(t), byTag, byVpc)...)), &answer))
	assert.Equal(t, 1, answer.Loaded["security-group"])
	for _, r := range []netRecorded{byTag, byVpc} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec)
		assert.Empty(t, ren)
	}
}

// TestLoadEC2Groups_DefaultGroupNeverMinted: a VPC's recorded default
// group answers under its recorded id, with its rule allowing itself, and a VPC whose recording holds
// none has none, after the load and after a snapshot and restore.
func TestLoadEC2Groups_DefaultGroupNeverMinted(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: filepath.Join(t.TempDir(), "state.db")})
	self := netGroups(map[string]string{"GroupId.1": "sg-0default"}, netGroup("sg-0default", fixtureVpcs[0], "default",
		"<ipPermissions><item><ipProtocol>-1</ipProtocol><groups><item><userId>"+loadAccount+"</userId><groupId>sg-0default</groupId></item></groups></item></ipPermissions>"))
	selfRule := netRules(strings.Replace(netRule("sgr-0self", "sg-0default", "-1", netPair("sg-0default", loadAccount)),
		"<ipProtocol>tcp</ipProtocol>", "<ipProtocol>-1</ipProtocol>", 1))
	selfRule.params = map[string]string{"Filter.1.Name": "group-id", "Filter.1.Value.1": "sg-0default"}
	loadNet(t, srv, sgRecording(t, self, selfRule)...)
	for _, r := range []netRecorded{self, selfRule} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec)
		assert.Empty(t, ren)
	}
	defaults := func(vpc string) string {
		body := mustOK(t)(ec2Call(t, srv, netRegion, "DescribeSecurityGroups", ec2FilterParams("group-name", "default", "vpc-id", vpc)))
		return extractEC2Tag(body, "groupId")
	}
	check := func(when string) {
		assert.Equal(t, "sg-0default", defaults(fixtureVpcs[0]), when)
		assert.Empty(t, defaults(fixtureVpcs[1]), "%s: a default group was minted", when)
		assert.Empty(t, defaults(fixtureVpcs[2]), "%s: a default group was minted", when)
	}
	check("after the load")
	mockOK(t, srv, http.MethodPost, "/mock/snapshot", "")
	mockOK(t, srv, http.MethodPost, "/mock/restore", "")
	check("after snapshot and restore")
}

// TestLoadEC2Groups_MutateOnce: after a new CIDR is authorized on the
// loaded group, both Describes answer the recording but for the new
// rule, every recorded sgr- id unchanged.
func TestLoadEC2Groups_MutateOnce(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	groups, rules := sgFixtures(t)
	loadNet(t, srv, sgRecording(t)...)

	mustOK(t)(ec2Call(t, srv, netRegion, "AuthorizeSecurityGroupIngress", url.Values{"GroupId": {fixtureSG},
		"IpPermissions.1.IpProtocol": {"tcp"}, "IpPermissions.1.FromPort": {"22"}, "IpPermissions.1.ToPort": {"22"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"192.0.2.0/24"}}))
	rec, ren := diffAnswer(t, srv, groups)
	assert.Empty(t, rec)
	assert.Equal(t, []string{"securityGroupInfo/item[0]/ipPermissions/item[0]/ipRanges/item[2]"}, ren)
	rec, ren = diffAnswer(t, srv, rules)
	assert.Empty(t, rec, "a recorded rule changed")
	assert.Equal(t, []string{"securityGroupRuleSet/item[2]"}, ren)
	body := resend(t, srv, rules)
	for _, id := range fixtureSGRules {
		assert.Contains(t, body, "<securityGroupRuleId>"+id+"</securityGroupRuleId>")
	}
}

// TestLoadEC2Groups_AllTrafficRuleRevokesAsSent: the loaded all-traffic
// egress rule goes on the revoke terraform-provider-aws sends for it,
// protocol -1 with ports 0.
func TestLoadEC2Groups_AllTrafficRuleRevokesAsSent(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	_, rules := sgFixtures(t)
	loadNet(t, srv, sgRecording(t)...)
	mustOK(t)(ec2Call(t, srv, netRegion, "RevokeSecurityGroupEgress", url.Values{"GroupId": {fixtureSG},
		"IpPermissions.1.IpProtocol": {"-1"}, "IpPermissions.1.FromPort": {"0"}, "IpPermissions.1.ToPort": {"0"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"}}))
	rec, ren := diffAnswer(t, srv, rules)
	assert.Equal(t, []string{"securityGroupRuleSet/item[2]"}, rec)
	assert.Empty(t, ren)
}

// TestLoadEC2Groups_UnreadSourcesUnresolved: a rule referencing another
// account's group, or a prefix list, loads and names it unresolved; a
// rule's tags load with it.
func TestLoadEC2Groups_UnreadSourcesUnresolved(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	groups := netGroups(map[string]string{"GroupId.1": "sg-0web"}, netGroup("sg-0web", fixtureSGVpc, "web",
		netIngress("443", "groups", "<item><userId>444455556666</userId><groupId>sg-0peer</groupId></item>")+
			"<ipPermissionsEgress><item><ipProtocol>tcp</ipProtocol><fromPort>5432</fromPort><toPort>5432</toPort>"+
			"<prefixListIds><item><prefixListId>pl-0a</prefixListId></item></prefixListIds></item></ipPermissionsEgress>"))
	rules := netRules(netRule("sgr-0peer", "sg-0web", "443", netPair("sg-0peer", "444455556666")+netTags("Name", "peer")),
		strings.Replace(netRule("sgr-0pl", "sg-0web", "5432", "<prefixListId>pl-0a</prefixListId>"), "<isEgress>false", "<isEgress>true", 1))
	var answer struct{ Unresolved map[string][]string }
	require.NoError(t, json.Unmarshal([]byte(loadNet(t, srv, append(fixtureRecording(t), groups, rules)...)), &answer))
	assert.Equal(t, []string{"sg-0peer"}, answer.Unresolved["security-group"])
	assert.Equal(t, []string{"pl-0a"}, answer.Unresolved["prefix-list"])
	for _, r := range []netRecorded{groups, rules} {
		rec, ren := diffAnswer(t, srv, r)
		assert.Empty(t, rec)
		assert.Empty(t, ren)
	}
}

func TestLoadEC2Groups_Refusals(t *testing.T) {
	groups, rules := sgFixtures(t)
	base := fixtureRecording(t)
	at := func(i int, action string) string { return fmt.Sprintf("exchange %d: ec2 %s: ", len(base)+i, action) }
	cases := map[string]struct {
		recording []netRecorded
		want      string
	}{
		"a group CIDR no recorded rule holds": {
			[]netRecorded{{groups.action, groups.params, strings.Replace(groups.body, "<cidrIp>198.51.100.0/24</cidrIp>",
				"<cidrIp>198.51.100.0/24</cidrIp></item><item><cidrIp>192.0.2.0/24</cidrIp>", 1)}, rules},
			at(0, "DescribeSecurityGroups") + "security-group " + fixtureSG + ": the model cannot hold recorded securityGroupInfo/item[0]/ipPermissions/item[0]/ipRanges/item[2]",
		},
		"a rule referencing an absent group of the account": {
			[]netRecorded{groups, rules, netRules(netRule("sgr-0pair", fixtureSG, "443", netPair("sg-0absent", loadAccount)))},
			at(2, "DescribeSecurityGroupRules") + "security-group-rule sgr-0pair references security-group sg-0absent, which no exchange loaded",
		},
		"a rule whose group was not recorded": {
			[]netRecorded{groups, rules, netRules(netRule("sgr-0orphan", "sg-0missing", "443", "<cidrIpv4>10.0.0.0/8</cidrIpv4>"))},
			at(2, "DescribeSecurityGroupRules") + "security-group-rule sgr-0orphan names security-group sg-0missing, which did not load",
		},
		"a rule repeating a source of its permission": {
			[]netRecorded{groups, rules, netRules(netRule("sgr-0dup", fixtureSG, "22", "<cidrIpv4>203.0.113.0/24</cidrIpv4>"))},
			at(2, "DescribeSecurityGroupRules") + "security-group-rule sgr-0dup repeats a source another rule of security-group " + fixtureSG + " holds",
		},
		"a rule whose group was refused": {
			[]netRecorded{netGroups(map[string]string{}, netGroup("sg-0a", "vpc-0missing", "a", "")),
				netRules(netRule("sgr-0a", "sg-0a", "443", "<cidrIpv4>10.0.0.0/8</cidrIpv4>"))},
			at(1, "DescribeSecurityGroupRules") + "security-group-rule sgr-0a names security-group sg-0a, which did not load",
		},
		"a group whose VPC was not recorded": {
			[]netRecorded{netGroups(map[string]string{}, netGroup("sg-0a", "vpc-0missing", "a", ""))},
			at(0, "DescribeSecurityGroups") + "security-group sg-0a names vpc vpc-0missing, which no exchange loaded",
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
