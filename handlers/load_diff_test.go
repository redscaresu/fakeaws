package handlers

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var describeVpcsKey = LoadKey{Service: "ec2", Action: "DescribeVpcs"}

func mustXML(t *testing.T, body string) *Tree {
	t.Helper()
	tree, err := ParseXML([]byte(body))
	require.NoError(t, err)
	return tree
}

func mustJSON(t *testing.T, body string) *Tree {
	t.Helper()
	tree, err := ParseJSON([]byte(body))
	require.NoError(t, err)
	return tree
}

func diffXML(t *testing.T, recorded, rendered string) ([]string, []string) {
	t.Helper()
	return Diff(describeVpcsKey, mustXML(t, recorded), mustXML(t, rendered))
}

func diffJSON(t *testing.T, recorded, rendered string) ([]string, []string) {
	t.Helper()
	return Diff(LoadKey{Service: "ssm", Action: "GetParameter"}, mustJSON(t, recorded), mustJSON(t, rendered))
}

func vpcItem(id, isDefault string) string {
	return fmt.Sprintf("<item><vpcId>%s</vpcId><cidrBlock>10.0.0.0/16</cidrBlock><isDefault>%s</isDefault></item>", id, isDefault)
}

func vpcs(items ...string) string {
	return "<DescribeVpcsResponse><requestId>r-1</requestId><vpcSet>" + strings.Join(items, "") + "</vpcSet></DescribeVpcsResponse>"
}

func TestLoadDiffUnknownFieldIsRecordedOnly(t *testing.T) {
	rec, ren := diffXML(t,
		vpcs("<item><vpcId>vpc-1</vpcId><fooBar><x>1</x></fooBar></item>"),
		vpcs("<item><vpcId>vpc-1</vpcId></item>"))
	assert.Equal(t, []string{"vpcSet/item[0]/fooBar/x"}, rec)
	assert.Empty(t, ren)

	rec, ren = diffJSON(t,
		`{"Parameter":{"Name":"/app/a","Type":"String","Foo":"bar"}}`,
		`{"Parameter":{"Name":"/app/a","Type":"String"}}`)
	assert.Equal(t, []string{"Parameter/Foo"}, rec)
	assert.Empty(t, ren)
}

func TestLoadDiffAddedFieldIsRenderedOnly(t *testing.T) {
	rec, ren := diffXML(t,
		vpcs("<item><vpcId>vpc-1</vpcId></item>"),
		vpcs("<item><vpcId>vpc-1</vpcId><dhcpOptionsId>dopt-1</dhcpOptionsId></item>"))
	assert.Empty(t, rec)
	assert.Equal(t, []string{"vpcSet/item[0]/dhcpOptionsId"}, ren)
}

func TestLoadDiffRootNamesMustMatch(t *testing.T) {
	item := vpcItem("vpc-1", "false")
	rec, ren := diffXML(t, vpcs(item), strings.ReplaceAll(vpcs(item), "DescribeVpcsResponse", "DescribeSubnetsResponse"))
	assert.Equal(t, []string{"DescribeVpcsResponse"}, rec)
	assert.Equal(t, []string{"DescribeSubnetsResponse"}, ren)

	rec, ren = Diff(describeVpcsKey, nil, mustXML(t, vpcs(item)))
	assert.Empty(t, rec)
	assert.Equal(t, []string{"vpcSet/item[0]"}, ren, "a nil tree is an empty body, whatever the other root is called")
}

func TestLoadDiffSetsAreMultisets(t *testing.T) {
	a, b, c := vpcItem("vpc-1", "false"), vpcItem("vpc-2", "true"), vpcItem("vpc-3", "false")

	t.Run("swapped vpcSet items", func(t *testing.T) {
		rec, ren := diffXML(t, vpcs(a, b), vpcs(b, a))
		assert.Empty(t, rec)
		assert.Empty(t, ren)
	})

	t.Run("swapped rules and ranges", func(t *testing.T) {
		rule := func(port, ranges string) string {
			return "<item><ipProtocol>tcp</ipProtocol><fromPort>" + port + "</fromPort><toPort>" + port +
				"</toPort><ipRanges>" + ranges + "</ipRanges></item>"
		}
		r1, r2 := "<item><cidrIp>10.0.0.0/16</cidrIp></item>", "<item><cidrIp>10.1.0.0/16</cidrIp></item>"
		sg := func(perms ...string) string {
			return "<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-1</groupId><ipPermissions>" +
				strings.Join(perms, "") + "</ipPermissions></item></securityGroupInfo></DescribeSecurityGroupsResponse>"
		}
		rec, ren := diffXML(t, sg(rule("443", r1+r2), rule("80", r1)), sg(rule("80", r1), rule("443", r2+r1)))
		assert.Empty(t, rec)
		assert.Empty(t, ren)
	})

	t.Run("swapped availability zones", func(t *testing.T) {
		az := func(name, id string) string {
			return "<item><zoneName>" + name + "</zoneName><zoneId>" + id + "</zoneId><zoneState>available</zoneState></item>"
		}
		body := func(items ...string) string {
			return "<DescribeAvailabilityZonesResponse><availabilityZoneInfo>" + strings.Join(items, "") +
				"</availabilityZoneInfo></DescribeAvailabilityZonesResponse>"
		}
		rec, ren := diffXML(t, body(az("eu-west-1a", "euw1-az1"), az("eu-west-1b", "euw1-az2")),
			body(az("eu-west-1b", "euw1-az2"), az("eu-west-1a", "euw1-az1")))
		assert.Empty(t, rec)
		assert.Empty(t, ren)
	})

	t.Run("one differing leaf names its item", func(t *testing.T) {
		rec, ren := diffXML(t, vpcs(a, b), vpcs(a, vpcItem("vpc-2", "false")))
		assert.Equal(t, []string{"vpcSet/item[1]/isDefault"}, rec)
		assert.Equal(t, []string{"vpcSet/item[1]/isDefault"}, ren)
	})

	t.Run("each side names its own index", func(t *testing.T) {
		rec, ren := diffXML(t, vpcs(a, b), vpcs(vpcItem("vpc-2", "false"), a))
		assert.Equal(t, []string{"vpcSet/item[1]/isDefault"}, rec)
		assert.Equal(t, []string{"vpcSet/item[0]/isDefault"}, ren)
	})

	t.Run("an unmatched item pairs with the one it differs from least", func(t *testing.T) {
		vpc := func(id, cidr, isDefault string) string {
			return "<item><vpcId>" + id + "</vpcId><cidrBlock>" + cidr + "</cidrBlock><isDefault>" + isDefault + "</isDefault></item>"
		}
		// Item 0 differs from rendered item 0 on vpcId and cidrBlock, from
		// rendered item 1 on isDefault alone, so they pair across indexes.
		rec, ren := diffXML(t,
			vpcs(vpc("vpc-1", "10.0.0.0/16", "false"), vpc("vpc-2", "10.1.0.0/16", "true")),
			vpcs(vpc("vpc-2", "10.1.0.0/16", "false"), vpc("vpc-1", "10.0.0.0/16", "true")))
		assert.Equal(t, []string{"vpcSet/item[0]/isDefault", "vpcSet/item[1]/isDefault"}, rec)
		assert.Equal(t, []string{"vpcSet/item[0]/isDefault", "vpcSet/item[1]/isDefault"}, ren)
	})

	t.Run("a set one item short names that item only", func(t *testing.T) {
		rec, ren := diffXML(t, vpcs(a, b, c), vpcs(c, a))
		assert.Equal(t, []string{"vpcSet/item[1]"}, rec)
		assert.Empty(t, ren)
	})

	t.Run("JSON array elements", func(t *testing.T) {
		rec, ren := diffJSON(t,
			`{"Parameters":[{"Name":"/a"},{"Name":"/b"}],"Nested":[[1,2],[3]]}`,
			`{"Parameters":[{"Name":"/b"},{"Name":"/a"}],"Nested":[[3],[2,1]]}`)
		assert.Empty(t, rec)
		assert.Empty(t, ren)

		rec, ren = diffJSON(t, `{"Nested":[[1,2],[3]]}`, `{"Nested":[[1,2],[4]]}`)
		assert.Equal(t, []string{"Nested[1]/[0]"}, rec)
		assert.Equal(t, []string{"Nested[1]/[0]"}, ren)
	})
}

func TestLoadDiffWhitespaceEmptiesAndNumbers(t *testing.T) {
	t.Run("indented recording against compact rendering", func(t *testing.T) {
		indented := `<?xml version="1.0" encoding="UTF-8"?>
<DescribeVpcsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    <requestId>r-2</requestId>
    <vpcSet>
        <item>
            <vpcId>vpc-1</vpcId>
            <cidrBlock>10.0.0.0/16</cidrBlock>
            <isDefault>false</isDefault>
        </item>
    </vpcSet>
</DescribeVpcsResponse>
`
		rec, ren := diffXML(t, indented, vpcs(vpcItem("vpc-1", "false")))
		assert.Empty(t, rec)
		assert.Empty(t, ren)
	})

	t.Run("a trailing newline is a difference", func(t *testing.T) {
		rec, ren := diffXML(t,
			vpcs("<item><vpcId>vpc-1</vpcId><description>web\n</description></item>"),
			vpcs("<item><vpcId>vpc-1</vpcId><description>web</description></item>"))
		assert.Equal(t, []string{"vpcSet/item[0]/description"}, rec)
		assert.Equal(t, []string{"vpcSet/item[0]/description"}, ren)
	})

	t.Run("an empty element is absent", func(t *testing.T) {
		rec, ren := diffXML(t,
			vpcs("<item><vpcId>vpc-1</vpcId><tagSet/></item>"),
			vpcs("<item><vpcId>vpc-1</vpcId></item>"))
		assert.Empty(t, rec)
		assert.Empty(t, ren)
	})

	t.Run("an element holding only empty elements is absent, indentation and all", func(t *testing.T) {
		rec, ren := diffXML(t,
			vpcs("<item><vpcId>vpc-1</vpcId><tagSet>\n    <item>\n        <value/>\n    </item>\n</tagSet></item>"),
			vpcs("<item><vpcId>vpc-1</vpcId></item>"))
		assert.Empty(t, rec)
		assert.Empty(t, ren)
	})

	t.Run("JSON numbers compare by value", func(t *testing.T) {
		rec, ren := diffJSON(t, `{"Parameter":{"Version":1.7E9}}`, `{"Parameter":{"Version":1700000000}}`)
		assert.Empty(t, rec)
		assert.Empty(t, ren)

		rec, ren = diffJSON(t, `{"Parameter":{"Version":1.7E9}}`, `{"Parameter":{"Version":1700000001}}`)
		assert.Equal(t, []string{"Parameter/Version"}, rec)
		assert.Equal(t, []string{"Parameter/Version"}, ren)

		rec, ren = diffJSON(t, `{"Parameter":{"Version":1}}`, `{"Parameter":{"Version":"1"}}`)
		assert.Equal(t, []string{"Parameter/Version"}, rec)
		assert.Equal(t, []string{"Parameter/Version"}, ren)
	})

	t.Run("an attribute is a field, a namespace declaration is not", func(t *testing.T) {
		rec, ren := diffXML(t, `<a xmlns:xsi="urn:x" kind="1"><b>1</b></a>`, `<a><b>1</b></a>`)
		assert.Equal(t, []string{"@kind"}, rec)
		assert.Empty(t, ren)
	})
}

func TestLoadDiffIgnoresPagingAndRequestIDs(t *testing.T) {
	rec, ren := diffXML(t,
		strings.Replace(vpcs(vpcItem("vpc-1", "false")), "</vpcSet>", "</vpcSet><nextToken>tok</nextToken>", 1),
		vpcs(vpcItem("vpc-1", "false")))
	assert.Empty(t, rec)
	assert.Empty(t, ren)

	rec, ren = diffXML(t,
		"<ListRolesResponse><ListRolesResult><IsTruncated>true</IsTruncated><Marker>m-1</Marker>"+
			"<Roles><member><RoleName>web</RoleName></member></Roles></ListRolesResult>"+
			"<ResponseMetadata><RequestId>r-3</RequestId></ResponseMetadata></ListRolesResponse>",
		"<ListRolesResponse><ListRolesResult><Roles><member><RoleName>web</RoleName></member></Roles></ListRolesResult></ListRolesResponse>")
	assert.Empty(t, rec)
	assert.Empty(t, ren)

	rec, ren = diffJSON(t, `{"Parameters":[{"Name":"/a"}]}`, `{"Parameters":[{"Name":"/a"}],"NextToken":"tok"}`)
	assert.Empty(t, rec)
	assert.Empty(t, ren)
}

// withIgnores replaces the registered ignore entries for one test.
func withIgnores(t *testing.T, entries ...IgnoreEntry) {
	t.Helper()
	saved := loadIgnores
	loadIgnores = nil
	registerIgnores(entries...)
	t.Cleanup(func() { loadIgnores = saved })
}

func TestLoadDiffIgnoreEntryIsScopedToItsKey(t *testing.T) {
	withIgnores(t, IgnoreEntry{
		Key:  describeVpcsKey,
		Path: "vpcSet/item/dhcpOptionsId",
		Cite: "terraform-provider-aws@v5.100.0/internal/service/ec2/vpc_.go",
	})
	without := vpcs("<item><vpcId>vpc-1</vpcId><isDefault>false</isDefault></item>")
	with := vpcs("<item><vpcId>vpc-1</vpcId><isDefault>true</isDefault><dhcpOptionsId>dopt-1</dhcpOptionsId></item>")

	rec, ren := diffXML(t, without, with)
	assert.Equal(t, []string{"vpcSet/item[0]/isDefault"}, rec, "only the entry's own path is suppressed")
	assert.Equal(t, []string{"vpcSet/item[0]/isDefault"}, ren)

	rec, ren = diffXML(t, with, without)
	assert.Equal(t, []string{"vpcSet/item[0]/isDefault"}, rec, "suppressed in both directions")
	assert.Equal(t, []string{"vpcSet/item[0]/isDefault"}, ren)

	rec, ren = Diff(LoadKey{Service: "ec2", Action: "DescribeSubnets"}, mustXML(t, without), mustXML(t, with))
	assert.Equal(t, []string{"vpcSet/item[0]/isDefault"}, rec)
	assert.Equal(t, []string{"vpcSet/item[0]/dhcpOptionsId", "vpcSet/item[0]/isDefault"}, ren, "another key's diff keeps the path")
}

var (
	// citeRE is how an ignore entry cites the provider source file in
	// which its field is never read.
	citeRE = regexp.MustCompile(`^terraform-provider-aws@v5\.100\.0/internal/[a-z0-9_]+(/[a-z0-9_]+)*\.go$`)
	// ignorePathRE allows element names and keys only, so a path cannot
	// carry an index or a value.
	ignorePathRE = regexp.MustCompile(`^@?[A-Za-z][A-Za-z0-9]*(/@?[A-Za-z][A-Za-z0-9]*)*$`)
)

func ignoreEntryProblems(entries []IgnoreEntry) []string {
	var problems []string
	for _, e := range entries {
		switch {
		case e.Key.Service == "" || e.Key.Action == "":
			problems = append(problems, fmt.Sprintf("%v %s: key needs a service and an action", e.Key, e.Path))
		case !ignorePathRE.MatchString(e.Path):
			problems = append(problems, fmt.Sprintf("%v: path is not an index-free path of names", e.Key))
		case !citeRE.MatchString(e.Cite) || strings.HasSuffix(e.Cite, "_test.go"):
			problems = append(problems, fmt.Sprintf("%v %s: cite %q is not a terraform-provider-aws v5.100.0 source file", e.Key, e.Path, e.Cite))
		}
	}
	return problems
}

// TestLoadDiffIgnoreList walks every registered ignore entry, so each
// loader file's entries are checked when it lands.
func TestLoadDiffIgnoreList(t *testing.T) {
	assert.Empty(t, ignoreEntryProblems(loadIgnores))

	good := IgnoreEntry{Key: describeVpcsKey, Path: "vpcSet/item/dhcpOptionsId", Cite: "terraform-provider-aws@v5.100.0/internal/service/ec2/vpc_.go"}
	assert.Empty(t, ignoreEntryProblems([]IgnoreEntry{good}))

	for name, mutate := range map[string]func(*IgnoreEntry){
		"empty cite":           func(e *IgnoreEntry) { e.Cite = "" },
		"no version":           func(e *IgnoreEntry) { e.Cite = "internal/service/ec2/vpc_.go" },
		"another version":      func(e *IgnoreEntry) { e.Cite = "terraform-provider-aws@v5.99.0/internal/service/ec2/vpc_.go" },
		"a test file":          func(e *IgnoreEntry) { e.Cite = "terraform-provider-aws@v5.100.0/internal/service/ec2/vpc_test.go" },
		"not a go file":        func(e *IgnoreEntry) { e.Cite = "terraform-provider-aws@v5.100.0/website/docs/r/vpc.html.markdown" },
		"a path with an index": func(e *IgnoreEntry) { e.Path = "vpcSet/item[0]/dhcpOptionsId" },
		"a path with a value":  func(e *IgnoreEntry) { e.Path = "vpcSet/item/dhcpOptionsId=dopt-1" },
		"no action":            func(e *IgnoreEntry) { e.Key.Action = "" },
	} {
		bad := good
		mutate(&bad)
		assert.NotEmpty(t, ignoreEntryProblems([]IgnoreEntry{bad}), name)
	}
}

func TestLoadDiffNeverReturnsAValue(t *testing.T) {
	const secret = "SECRET-MARKER"
	var got []string
	rec, ren := diffXML(t,
		vpcs("<item><vpcId>vpc-1</vpcId><description>"+secret+"</description></item>", vpcItem("vpc-9", secret)),
		vpcs("<item><vpcId>vpc-1</vpcId><description>other</description></item>"))
	assert.Equal(t, []string{"vpcSet/item[0]/description", "vpcSet/item[1]"}, rec)
	assert.Equal(t, []string{"vpcSet/item[0]/description"}, ren)
	got = append(append(got, rec...), ren...)

	rec, ren = diffJSON(t, `{"Parameter":{"Value":"`+secret+`"}}`, `{"Parameter":{"Value":"other"}}`)
	assert.Equal(t, []string{"Parameter/Value"}, rec)
	got = append(append(got, rec...), ren...)

	rec, ren = diffJSON(t, `{"Item":{"`+secret+`":{"S":"a"},"email":{"S":"b"},"Owner":{"S":"c"}}}`, `{"Item":{}}`)
	assert.Equal(t, []string{"Item/Owner/S", "Item/{key}/S", "Item/{key}/S"}, rec, "a key outside member spelling shows as {key}")
	assert.Empty(t, ren)
	got = append(append(got, rec...), ren...)

	rec, ren = diffXML(t, "<a><"+secret+">1</"+secret+"></a>", "<a/>")
	assert.Equal(t, []string{"{key}"}, rec)
	got = append(append(got, rec...), ren...)

	rec, ren = diffXML(t, "<"+secret+"/>", "<a/>")
	assert.Equal(t, []string{"{key}"}, rec)
	got = append(append(got, rec...), ren...)

	_, err := ParseXML([]byte("<a>&" + secret + ";</a>"))
	require.Error(t, err)
	got = append(got, err.Error())
	_, err = ParseJSON([]byte(`{"a":` + secret + `}`))
	require.Error(t, err)
	got = append(got, err.Error())

	for _, s := range got {
		assert.NotContains(t, s, secret)
	}
}

func TestLoadDiffParseRefusesMalformedBodies(t *testing.T) {
	for _, body := range []string{"", "<a>", "<a></b>", "<a/><b/>", "<a/>text"} {
		_, err := ParseXML([]byte(body))
		assert.Error(t, err, "%q", body)
	}
	for _, body := range []string{"", "{", `{"a":1} {"b":2}`} {
		_, err := ParseJSON([]byte(body))
		assert.Error(t, err, "%q", body)
	}
}

func TestLoadDiffSubtree(t *testing.T) {
	body := mustXML(t, vpcs(vpcItem("vpc-1", "false"), vpcItem("vpc-2", "true"), vpcItem("vpc-3", "false")))
	rec, ren := Diff(describeVpcsKey, body.Subtree("vpcSet/item", 1), mustXML(t, vpcs(vpcItem("vpc-2", "true"))))
	assert.Empty(t, rec)
	assert.Empty(t, ren)
	assert.Nil(t, body.Subtree("vpcSet/item", 3))

	instance := func(id string) string { return "<item><instanceId>" + id + "</instanceId></item>" }
	reservation := func(id string, instances ...string) string {
		return "<item><reservationId>" + id + "</reservationId><instancesSet>" + strings.Join(instances, "") + "</instancesSet></item>"
	}
	instances := mustXML(t, "<DescribeInstancesResponse><reservationSet>"+
		reservation("r-1", instance("i-1"), instance("i-2"))+reservation("r-2", instance("i-3"))+
		"</reservationSet></DescribeInstancesResponse>")
	rec, ren = Diff(describeVpcsKey, instances.Subtree("reservationSet/item/instancesSet/item", 2),
		mustXML(t, "<DescribeInstancesResponse><reservationSet><item><instancesSet>"+instance("i-3")+
			"</instancesSet></item></reservationSet></DescribeInstancesResponse>"))
	assert.Empty(t, rec, "the third instance in document order, under its ancestors only")
	assert.Empty(t, ren)

	parameter := mustJSON(t, `{"Parameter":{"Name":"/app/a","Tags":[{"Key":"a"},{"Key":"b"}]}}`)
	rec, ren = Diff(describeVpcsKey, parameter.Subtree("Parameter/Tags", 1), mustJSON(t, `{"Parameter":{"Tags":[{"Key":"b"}]}}`))
	assert.Empty(t, rec, "a JSON subtree's ancestors stay JSON")
	assert.Empty(t, ren)
}

func TestLoadDiffMergePages(t *testing.T) {
	a, b, c := vpcItem("vpc-1", "false"), vpcItem("vpc-2", "true"), vpcItem("vpc-3", "false")
	page1 := mustXML(t, strings.Replace(vpcs(a, b), "</vpcSet>", "</vpcSet><nextToken>tok</nextToken>", 1))
	page2 := mustXML(t, vpcs(c))

	rec, ren := Diff(describeVpcsKey, MergePages(page1, page2), mustXML(t, vpcs(c, b, a)))
	assert.Empty(t, rec)
	assert.Empty(t, ren)

	rec, ren = Diff(describeVpcsKey, page1, mustXML(t, vpcs(a, b)))
	assert.Empty(t, rec, "merging leaves its pages unchanged")
	assert.Empty(t, ren)

	merged := MergePages(mustJSON(t, `{"Parameters":[{"Name":"/a"}],"NextToken":"tok"}`), mustJSON(t, `{"Parameters":[{"Name":"/b"}]}`))
	rec, ren = Diff(describeVpcsKey, merged, mustJSON(t, `{"Parameters":[{"Name":"/b"},{"Name":"/a"}]}`))
	assert.Empty(t, rec)
	assert.Empty(t, ren)
}
