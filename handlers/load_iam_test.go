package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

// iamLoadAccount is the account the testdata/iam fixtures' ARNs name.
const iamLoadAccount = "123456789012"

const (
	iamLoadCustomerPolicy = "arn:aws:iam::123456789012:policy/application_abc/ApplicationBucketWrite"
	iamLoadBoundary       = "arn:aws:iam::123456789012:policy/application_abc/Boundary"
)

// iamRead is one exchange of the IAM reader's read of role S3Access: an
// action, its params and the testdata/iam fixture it answered.
type iamRead struct {
	action  string
	params  map[string]string
	fixture string
}

// iamRoleRead is the reader's read of S3Access, in the order it sends it
// (infrafactory internal/harness/aws_reader_iam.go readIAMRole).
var iamRoleRead = []iamRead{
	{"GetRole", map[string]string{"RoleName": "S3Access"}, "GetRole"},
	{"ListRolePolicies", map[string]string{"RoleName": "S3Access"}, "ListRolePolicies"},
	{"GetRolePolicy", map[string]string{"RoleName": "S3Access", "PolicyName": "CloudwatchPutMetricPolicy"}, "GetRolePolicy-CloudwatchPutMetricPolicy"},
	{"GetRolePolicy", map[string]string{"RoleName": "S3Access", "PolicyName": "S3AccessPolicy"}, "GetRolePolicy-S3AccessPolicy"},
	{"ListAttachedRolePolicies", map[string]string{"RoleName": "S3Access"}, "ListAttachedRolePolicies"},
	{"ListInstanceProfilesForRole", map[string]string{"RoleName": "S3Access"}, "ListInstanceProfilesForRole"},
}

func iamFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "iam", name+".xml"))
	require.NoError(t, err)
	return string(b)
}

// iamReadEnvelope is reads recorded as an envelope under iamLoadAccount,
// each body its fixture passed through edit.
func iamReadEnvelope(t *testing.T, reads []iamRead, edit func(fixture, body string) string) string {
	t.Helper()
	exchanges := make([]string, len(reads))
	for i, r := range reads {
		exchanges[i] = loadPage("iam", r.action, r.params, http.StatusOK, edit(r.fixture, iamFixture(t, r.fixture)))
	}
	return loadEnvelope(iamLoadAccount, loadRegion, exchanges...)
}

func asRecorded(_, body string) string { return body }

// loadIAMRead loads iamRoleRead into a fresh fakeaws and returns it.
func loadIAMRead(t *testing.T) (*handlers.Application, *httptest.Server, string) {
	t.Helper()
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, body := postLoad(t, srv, iamReadEnvelope(t, iamRoleRead, asRecorded))
	require.Equal(t, http.StatusOK, status, body)
	return app, srv, body
}

// iamResend sends r's action with its recorded params and returns the
// 200 body.
func iamResend(t *testing.T, srv *httptest.Server, r iamRead) string {
	t.Helper()
	params := url.Values{}
	for k, v := range r.params {
		params.Set(k, v)
	}
	resp, body := iamCall(t, srv, r.action, params)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", r.action, body)
	return string(body)
}

// iamDiff is load_diff.go's diff of fixture against an answer.
func iamDiff(t *testing.T, action, fixture, answer string) (recordedOnly, renderedOnly []string) {
	t.Helper()
	recorded, err := handlers.ParseXML([]byte(iamFixture(t, fixture)))
	require.NoError(t, err)
	rendered, err := handlers.ParseXML([]byte(answer))
	require.NoError(t, err)
	return handlers.Diff(handlers.LoadKey{Service: "iam", Action: action}, recorded, rendered)
}

func TestLoadIAM_ReSentReadsAnswerTheRecording(t *testing.T) {
	app, srv, body := loadIAMRead(t)
	var answer struct {
		Loaded map[string]int
	}
	require.NoError(t, json.Unmarshal([]byte(body), &answer))
	assert.Equal(t, map[string]int{
		"role": 1, "role-policy": 2, "role-policy-name": 2, "role-policy-attachment": 2, "instance-profile": 1,
	}, answer.Loaded)

	for _, r := range iamRoleRead {
		rec, ren := iamDiff(t, r.action, r.fixture, iamResend(t, srv, r))
		assert.Empty(t, rec, "%s %v: the recording holds what fakeaws does not answer", r.action, r.params)
		assert.Empty(t, ren, "%s %v: fakeaws answers what the recording does not hold", r.action, r.params)
	}

	role := iamResend(t, srv, iamRoleRead[0])
	assert.Contains(t, role, "<RoleId>AROADBQP57FF2AEXAMPLE</RoleId>")
	assert.Contains(t, role, "<CreateDate>2012-05-08T23:34:01Z</CreateDate>")
	assert.Contains(t, iamResend(t, srv, iamRoleRead[5]), "<InstanceProfileId>AIPACZLS2TD2HEXAMPLE</InstanceProfileId>")
	list := iamResend(t, srv, iamRead{action: "ListRoles"})
	assert.Contains(t, list, "<RoleId>AROADBQP57FF2AEXAMPLE</RoleId>")
	assert.NotContains(t, list, "PermissionsBoundary", "ListRoles never answers a permissions boundary")

	doc, err := app.Repository().GetRolePolicy(iamLoadAccount, "S3Access", "CloudwatchPutMetricPolicy")
	require.NoError(t, err)
	assert.Equal(t, "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n"+
		"      \"Action\": \"cloudwatch:PutMetricData\",\n      \"Resource\": \"*\"\n    }\n  ]\n}", doc,
		"an inline document is stored byte-exact once URL-decoded")
}

func TestLoadIAM_UpdateRoleChangesOnlyMaxSessionDuration(t *testing.T) {
	_, srv, _ := loadIAMRead(t)
	resp, body := iamCall(t, srv, "UpdateRole", url.Values{"RoleName": {"S3Access"}, "MaxSessionDuration": {"7200"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	got := iamResend(t, srv, iamRoleRead[0])
	rec, ren := iamDiff(t, "GetRole", "GetRole", got)
	want := []string{"GetRoleResult/Role/MaxSessionDuration"}
	assert.Equal(t, want, rec, "RoleId, CreateDate and every other field answer as recorded")
	assert.Equal(t, want, ren)
	assert.Contains(t, got, "<MaxSessionDuration>7200</MaxSessionDuration>")
}

func TestLoadIAM_CustomerManagedPolicyIsUnresolved(t *testing.T) {
	_, srv, body := loadIAMRead(t)
	var answer struct {
		Unresolved map[string][]string
	}
	require.NoError(t, json.Unmarshal([]byte(body), &answer))
	assert.Equal(t, map[string][]string{"policy": {iamLoadCustomerPolicy, iamLoadBoundary}}, answer.Unresolved)

	resp, got := iamCall(t, srv, "GetPolicy", url.Values{"PolicyArn": {iamLoadCustomerPolicy}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, string(got), "<Code>NoSuchEntity</Code>")
}

func TestLoadIAM_ListedPolicyWithNoGetRolePolicyRefuses(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	reads := slices.DeleteFunc(slices.Clone(iamRoleRead), func(r iamRead) bool { return r.fixture == "GetRolePolicy-S3AccessPolicy" })
	status, body := postLoad(t, srv, iamReadEnvelope(t, reads, asRecorded))
	require.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, loadRefusals(t, body),
		"exchange 1: iam ListRolePolicies: role-policy-name S3Access/S3AccessPolicy references role-policy S3Access/S3AccessPolicy, which no exchange loaded")
}

func TestLoadIAM_UnknownRoleElementRefuses(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	plant := func(fixture, body string) string {
		if fixture != "GetRole" {
			return body
		}
		return strings.Replace(body, "<RoleName>", "<AccessAudit>enabled</AccessAudit><RoleName>", 1)
	}
	status, body := postLoad(t, srv, iamReadEnvelope(t, iamRoleRead, plant))
	require.Equal(t, http.StatusBadRequest, status, body)
	assert.Equal(t, []string{"exchange 0: iam GetRole: role: the model cannot hold recorded GetRoleResult/Role/AccessAudit"}, loadRefusals(t, body))
}
