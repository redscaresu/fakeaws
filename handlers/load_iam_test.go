package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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

// iamDiff is load_diff.go's diff of a recorded body against an answer.
func iamDiff(t *testing.T, action, body, answer string) (recordedOnly, renderedOnly []string) {
	t.Helper()
	recorded, err := handlers.ParseXML([]byte(body))
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
		"role": 1, "role-policy": 2, "role-policy-attachment": 2, "instance-profile": 1,
	}, answer.Loaded, "loaded counts rows written: a ListRolePolicies name writes none")

	for _, r := range iamRoleRead {
		rec, ren := iamDiff(t, r.action, iamFixture(t, r.fixture), iamResend(t, srv, r))
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
	rec, ren := iamDiff(t, "GetRole", iamFixture(t, "GetRole"), got)
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

// TestLoadIAM_TagCallsFindAPathedRoleAndProfile: a loaded role and
// profile keep their recorded ARNs, path included, and a tag call by name
// finds them there rather than under an ARN built without the path.
func TestLoadIAM_TagCallsFindAPathedRoleAndProfile(t *testing.T) {
	_, srv, _ := loadIAMRead(t)
	for _, tc := range []struct{ kind, param, name, has string }{
		{"Role", "RoleName", "S3Access", "<Key>team</Key>"},
		{"InstanceProfile", "InstanceProfileName", "Webserver", ""},
	} {
		resp, body := iamCall(t, srv, "Tag"+tc.kind, url.Values{tc.param: {tc.name}, "Tags.member.1.Key": {"env"}, "Tags.member.1.Value": {"prod"}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "Tag%s: %s", tc.kind, body)
		resp, body = iamCall(t, srv, "List"+tc.kind+"Tags", url.Values{tc.param: {tc.name}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "List%sTags: %s", tc.kind, body)
		assert.Contains(t, string(body), "<Key>env</Key>")
		assert.Contains(t, string(body), tc.has)
		resp, body = iamCall(t, srv, "Untag"+tc.kind, url.Values{tc.param: {tc.name}, "TagKeys.member.1": {"env"}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "Untag%s: %s", tc.kind, body)
	}
	rec, ren := iamDiff(t, "GetRole", iamFixture(t, "GetRole"), iamResend(t, srv, iamRoleRead[0]))
	assert.Empty(t, rec, "GetRole answers the recorded tags once env is untagged")
	assert.Empty(t, ren)
}

// iamDocument is an IAM policy document element's recorded text.
var iamDocument = regexp.MustCompile(`<(AssumeRolePolicyDocument|PolicyDocument)>([^<]*)<`)

// otherEncoding re-encodes body's documents as another encoder might: *
// and : left raw, the rest of the reserved bytes in lower-case hex.
func otherEncoding(_, body string) string {
	return iamDocument.ReplaceAllStringFunc(body, func(m string) string {
		parts := iamDocument.FindStringSubmatch(m)
		doc, err := url.QueryUnescape(parts[2])
		if err != nil {
			panic(err)
		}
		var b strings.Builder
		for _, c := range []byte(doc) {
			if c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~*:", c) >= 0) {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "%%%02x", c)
			}
		}
		return "<" + parts[1] + ">" + b.String() + "<"
	})
}

// TestLoadIAM_DocumentsCompareDecoded: a document IAM encodes otherwise
// than fakeaws does loads, reads back decoded as recorded, and answers
// equal to the recording by Diff, which compares documents decoded.
func TestLoadIAM_DocumentsCompareDecoded(t *testing.T) {
	recorded := otherEncoding("", iamFixture(t, "GetRolePolicy-S3AccessPolicy"))
	require.Contains(t, recorded, "s3:*", "the other encoding leaves * raw")
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, body := postLoad(t, srv, iamReadEnvelope(t, iamRoleRead, otherEncoding))
	require.Equal(t, http.StatusOK, status, body)

	doc, err := app.Repository().GetRolePolicy(iamLoadAccount, "S3Access", "S3AccessPolicy")
	require.NoError(t, err)
	assert.Equal(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["*"]}]}`, doc)
	role, err := app.Repository().GetRole(iamLoadAccount, "S3Access")
	require.NoError(t, err)
	assert.Equal(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}`,
		role.AssumeRolePolicyDocument)
	for _, r := range iamRoleRead {
		rec, ren := iamDiff(t, r.action, otherEncoding("", iamFixture(t, r.fixture)), iamResend(t, srv, r))
		assert.Empty(t, rec, "%s %v", r.action, r.params)
		assert.Empty(t, ren, "%s %v", r.action, r.params)
	}
}

// TestLoadIAM_RoleWithNoKeyRefuses: a role is keyed by its name and its
// tags by its ARN, so a GetRole answering either empty is refused naming
// the first missing, in order, never stored under "".
func TestLoadIAM_RoleWithNoKeyRefuses(t *testing.T) {
	arn, name := regexp.MustCompile(`<Arn>[^<]*</Arn>`), regexp.MustCompile(`<RoleName>[^<]*</RoleName>`)
	for _, tc := range []struct {
		name, field string
		cut         []*regexp.Regexp
	}{
		{"no Arn", "Arn", []*regexp.Regexp{arn}},
		{"no RoleName", "RoleName", []*regexp.Regexp{name}},
		{"neither", "RoleName", []*regexp.Regexp{arn, name}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
			status, body := postLoad(t, srv, iamReadEnvelope(t, iamRoleRead[:1], func(_, body string) string {
				for _, re := range tc.cut {
					body = re.ReplaceAllString(body, "")
				}
				return body
			}))
			require.Equal(t, http.StatusBadRequest, status, body)
			assert.Equal(t, []string{"exchange 0: iam GetRole: GetRoleResult/Role holds no " + tc.field}, loadRefusals(t, body))
		})
	}
}

// TestLoadIAM_ProfileWithNoKeyRefuses: a profile is keyed by its name
// and its tags by its ARN, so one answering either empty is refused,
// never stored under "".
func TestLoadIAM_ProfileWithNoKeyRefuses(t *testing.T) {
	for field, cut := range map[string]*regexp.Regexp{
		"InstanceProfileName": regexp.MustCompile(`<InstanceProfileName>[^<]*</InstanceProfileName>`),
		// The profile's own Arn, after its Roles.
		"Arn": regexp.MustCompile(`(</Roles>[\s\S]*)<Arn>[^<]*</Arn>`),
	} {
		t.Run(field, func(t *testing.T) {
			_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
			status, body := postLoad(t, srv, iamReadEnvelope(t, iamRoleRead, func(fixture, body string) string {
				if fixture != "ListInstanceProfilesForRole" {
					return body
				}
				return cut.ReplaceAllString(body, "$1")
			}))
			require.Equal(t, http.StatusBadRequest, status, body)
			assert.Equal(t, []string{"exchange 5: iam ListInstanceProfilesForRole: ListInstanceProfilesForRoleResult/InstanceProfiles/member holds no " + field},
				loadRefusals(t, body))
		})
	}
}

// TestLoadIAM_RepeatedProfileComparesDocumentsDecoded: a profile two
// ListInstanceProfilesForRole reads answer, its role's trust policy
// encoded otherwise in the second, loads once: the repeat compares the
// document decoded, under the entry re-rooted at the profile.
func TestLoadIAM_RepeatedProfileComparesDocumentsDecoded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	exchanges := []string{}
	for _, r := range iamRoleRead {
		exchanges = append(exchanges, loadPage("iam", r.action, r.params, http.StatusOK, iamFixture(t, r.fixture)))
	}
	again := otherEncoding("", iamFixture(t, "ListInstanceProfilesForRole"))
	require.NotEqual(t, iamFixture(t, "ListInstanceProfilesForRole"), again)
	exchanges = append(exchanges, loadPage("iam", "ListInstanceProfilesForRole", map[string]string{"RoleName": "S3Access"}, http.StatusOK, again))
	status, body := postLoad(t, srv, loadEnvelope(iamLoadAccount, loadRegion, exchanges...))
	require.Equal(t, http.StatusOK, status, body)
	var answer struct{ Loaded map[string]int }
	require.NoError(t, json.Unmarshal([]byte(body), &answer))
	assert.Equal(t, 1, answer.Loaded["instance-profile"])
}
