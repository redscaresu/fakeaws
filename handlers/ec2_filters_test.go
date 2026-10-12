package handlers

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/repository"
)

// eniTable runs the engine over the existing DescribeNetworkInterfaces
// row table, tagged by ENI id.
var eniTable = ec2FilterTable[*repository.EC2NetworkInterface]{
	values: eniFilterValues,
	tagID:  func(e *repository.EC2NetworkInterface) string { return e.ID },
}

var testENIs = []*repository.EC2NetworkInterface{
	{ID: "eni-a", SubnetID: "subnet-1", SecurityGroupIDs: []string{"sg-a"}},
	{ID: "eni-b", SubnetID: "subnet-2", SecurityGroupIDs: []string{"sg-b"}},
	{ID: "eni-ab", SubnetID: "subnet-1", SecurityGroupIDs: []string{"sg-a", "sg-b"}},
	{ID: "eni-none", SubnetID: "subnet-3"},
}

// matchingENIs parses query and returns the ids of testENIs passing it,
// failing the test if the table refuses any of it.
func matchingENIs(t *testing.T, query string, tags map[string][]ec2ResourceTagXML) []string {
	t.Helper()
	p, err := url.ParseQuery(query)
	require.NoError(t, err)
	filters := parseEC2Filters(p)
	require.Empty(t, eniTable.unmodelled(filters), query)
	ids := []string{}
	for _, e := range testENIs {
		if eniTable.matches(e, filters, tags) {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

func TestEC2Filter_AndAcrossOrWithin(t *testing.T) {
	cases := []struct {
		name, query string
		want        []string
	}{
		{"same name in two Filter.N is ANDed",
			"Filter.1.Name=group-id&Filter.1.Value.1=sg-a&Filter.2.Name=group-id&Filter.2.Value.1=sg-b",
			[]string{"eni-ab"}},
		{"two values in one Filter.N are ORed",
			"Filter.1.Name=group-id&Filter.1.Value.1=sg-a&Filter.1.Value.2=sg-b",
			[]string{"eni-a", "eni-b", "eni-ab"}},
		{"Filter.1 and Filter.3 with no Filter.2 both apply",
			"Filter.1.Name=subnet-id&Filter.1.Value.1=subnet-1&Filter.3.Name=group-id&Filter.3.Value.1=sg-b",
			[]string{"eni-ab"}},
		{"Value.1 and Value.3 with no Value.2 are ORed",
			"Filter.1.Name=group-id&Filter.1.Value.1=sg-a&Filter.1.Value.3=sg-b",
			[]string{"eni-a", "eni-b", "eni-ab"}},
		{"no filter passes every row", "",
			[]string{"eni-a", "eni-b", "eni-ab", "eni-none"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, matchingENIs(t, c.query, nil))
		})
	}
}

func TestEC2Filter_WildcardCrossesSlash(t *testing.T) {
	nameTable := ec2FilterTable[string]{values: map[string]func(string) []string{
		"name": func(s string) []string { return []string{s} },
	}}
	cases := []struct {
		value, row string
		want       bool
	}{
		{`ubuntu/images/*`, "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04", true},
		{`ubuntu/images/*`, "ubuntu/other/hvm-ssd", false},
		{`amzn2-ami-hvm-2.?`, "amzn2-ami-hvm-2.0", true},
		{`amzn2-ami-hvm-2.?`, "amzn2-ami-hvm-2.10", false},
		{`amzn2-ami-hvm-2.?`, "amzn2-ami-hvmx2.0", false},
		{`a\*`, "a*", true},
		{`a\*`, "ab", false},
		{`a\*`, "a", false},
	}
	for _, c := range cases {
		filters := parseEC2Filters(url.Values{"Filter.1.Name": {"name"}, "Filter.1.Value.1": {c.value}})
		assert.Equal(t, c.want, nameTable.matches(c.row, filters, nil), "%s against %s", c.value, c.row)
	}
}

func TestEC2Filter_Tags(t *testing.T) {
	tags := map[string][]ec2ResourceTagXML{
		"eni-a": {{Key: "Name", Value: "web"}},
		"eni-b": {{Key: "Name", Value: "db"}, {Key: "Role", Value: "web"}},
	}
	assert.Equal(t, []string{"eni-a"}, matchingENIs(t, "Filter.1.Name=tag:Name&Filter.1.Value.1=web", tags))
	assert.Equal(t, []string{"eni-b"}, matchingENIs(t, "Filter.1.Name=tag-key&Filter.1.Value.1=Role", tags))
	assert.Equal(t, []string{"eni-a", "eni-b"}, matchingENIs(t, "Filter.1.Name=tag-value&Filter.1.Value.1=web", tags))

	rtTable := ec2FilterTable[ec2RouteTableXML]{values: rtFilterValues}
	for _, name := range []string{"tag:Name", "tag-key", "tag-value"} {
		filters := parseEC2Filters(url.Values{"Filter.1.Name": {name}, "Filter.1.Value.1": {"web"}})
		assert.Equal(t, []string{name}, rtTable.unmodelled(filters), "a table without tags refuses %s", name)
	}
}

// refusal calls refuse once and returns the response, its error code
// and message.
func refusal(t *testing.T, query string, unread []string) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	p, err := url.ParseQuery(query)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	require.True(t, eniTable.refuse(w, "DescribeNetworkInterfaces", parseEC2Filters(p), unread))
	var e struct {
		Code    string `xml:"Errors>Error>Code"`
		Message string `xml:"Errors>Error>Message"`
	}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &e))
	return w, e.Code, e.Message
}

func TestEC2Filter_RefusalNamesEveryNameSorted(t *testing.T) {
	query := "Filter.1.Name=zz&Filter.1.Value.1=x&Filter.2.Name=aa&Filter.2.Value.1=x" +
		"&Filter.3.Name=zz&Filter.3.Value.1=x&Filter.4.Name=subnet-id&Filter.5.Value.1=x"
	first, code, msg := refusal(t, query, nil)
	assert.Equal(t, http.StatusNotImplemented, first.Code)
	assert.Equal(t, "NotImplemented", code)
	assert.Equal(t, "DescribeNetworkInterfaces: not modelled by fakeaws: Filter.4, Filter.5, aa, zz", msg)
	for range 20 {
		w, _, _ := refusal(t, query, nil)
		assert.Equal(t, first.Body.String(), w.Body.String())
	}

	_, _, msg = refusal(t, "Filter.1.Name=zz&Filter.1.Value.1=x&Filter.2.Name=subnet-id&Filter.2.Value.1=x&Filter.2.Bogus=x",
		[]string{"GroupName.2", "GroupName.1", "AllowReassociation"})
	assert.Equal(t, "DescribeNetworkInterfaces: not modelled by fakeaws: AllowReassociation, Filter.2, GroupName.N, zz", msg)

	w := httptest.NewRecorder()
	p, err := url.ParseQuery("Filter.1.Name=subnet-id&Filter.1.Value.1=x")
	require.NoError(t, err)
	assert.False(t, eniTable.refuse(w, "DescribeNetworkInterfaces", parseEC2Filters(p), nil))
	assert.Empty(t, w.Body.String())
}
