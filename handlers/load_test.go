package handlers_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
)

const (
	loadAccount = "111122223333"
	loadRegion  = "eu-west-1"
	loadLimit   = 1 << 20
)

// loadPage is one exchange of a recorded read, as JSON.
func loadPage(service, action string, params map[string]string, status int, body string) string {
	b, _ := json.Marshal(map[string]any{
		"service": service, "protocol": "query", "action": action, "params": params,
		"status": status, "body": body,
	})
	return string(b)
}

// loadExchange is loadPage answering 200 to empty params.
func loadExchange(service, action, body string) string {
	return loadPage(service, action, map[string]string{}, http.StatusOK, body)
}

// jsonPage is a json-protocol exchange of a fakeaws-test action, whose
// body is JSON.
func jsonPage(action string, params map[string]any, status int, body string) string {
	b, _ := json.Marshal(map[string]any{
		"service": "fakeaws-test", "protocol": "json", "action": action, "params": params,
		"status": status, "body": body,
	})
	return string(b)
}

// textBody is the body of an exchange whose loader decodes no item: a
// root element holding text.
func textBody(text string) string { return "<Text>" + text + "</Text>" }

// textExchange is a fakeaws-test action exchange whose body holds text.
func textExchange(action, text string) string {
	return loadExchange("fakeaws-test", action, textBody(text))
}

// vpcBody is a test VPC loader's body for action: a vpcSet of items
// (vpcItem), then tail (a paging field).
func vpcBody(action, tail string, items ...string) string {
	return fmt.Sprintf("<%[1]sResponse><vpcSet>%s</vpcSet>%s</%[1]sResponse>", action, strings.Join(items, ""), tail)
}

// vpcItem is a VPC item with id and a CIDR, then more (a refSet).
func vpcItem(id string, more ...string) string {
	return "<item><vpcId>" + id + "</vpcId><cidrBlock>10.0.0.0/16</cidrBlock>" + strings.Join(more, "") + "</item>"
}

// refSet is an item's refSet naming refs, each "<type> <id>", and
// "<type> <id> unread" for one the reader never reads.
func refSet(refs ...string) string {
	var b strings.Builder
	for _, r := range refs {
		f := strings.Fields(r)
		fmt.Fprintf(&b, "<item><type>%s</type><id>%s</id>", f[0], f[1])
		if len(f) > 2 {
			b.WriteString("<unread>true</unread>")
		}
		b.WriteString("</item>")
	}
	return "<refSet>" + b.String() + "</refSet>"
}

// putVpc is a PutVpc exchange loading the VPCs ids.
func putVpc(ids ...string) string {
	items := make([]string, len(ids))
	for i, id := range ids {
		items[i] = vpcItem(id)
	}
	return loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "", items...))
}

// putSubnet is a PutSubnet exchange loading subnet id in vpc.
func putSubnet(id, vpc string) string {
	return loadExchange("fakeaws-test", "PutSubnet",
		"<PutSubnetResponse><subnetSet><item><subnetId>"+id+"</subnetId><vpcId>"+vpc+"</vpcId></item></subnetSet></PutSubnetResponse>")
}

// sharedGroup is a DescribeSecurityGroups exchange filtered by filter,
// as the step-0 read's tag-key and vpc-id reads are, loading group
// sg-0shared, named name, in vpc-0shared.
func sharedGroup(filter, name string) string {
	return loadPage("fakeaws-test", "DescribeSecurityGroups", map[string]string{"Filter.1.Name": filter, "Filter.1.Value.1": "v"}, http.StatusOK,
		"<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-0shared</groupId><groupName>"+name+
			"</groupName><vpcId>vpc-0shared</vpcId></item></securityGroupInfo></DescribeSecurityGroupsResponse>")
}

// loadEnvelope is a recorded read of exchanges under account and region.
func loadEnvelope(account, region string, exchanges ...string) string {
	return fmt.Sprintf(`{"account":%q,"region":%q,"timestamp":"2026-10-11T09:30:00Z","duration_ms":842,"calls":%d,"exchanges":[%s]}`,
		account, region, len(exchanges), strings.Join(exchanges, ","))
}

// newLoadApp is newOptionsApp serving /mock/load at loadLimit behind
// adminToken, unless opts sets either.
func newLoadApp(t *testing.T, opts handlers.Options) (*handlers.Application, *httptest.Server) {
	t.Helper()
	if opts.AdminToken == "" {
		opts.AdminToken = adminToken
	}
	if opts.LoadMaxBytes == 0 {
		opts.LoadMaxBytes = loadLimit
	}
	return newOptionsApp(t, opts)
}

// mockRequest sends method path with header and body (none when empty).
func mockRequest(t *testing.T, srv *httptest.Server, method, path string, header http.Header, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header = header
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "%s %s", method, path)
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(got)
}

// mockCall is mockRequest with the admin token.
func mockCall(t *testing.T, srv *httptest.Server, method, path, body string) (int, string) {
	t.Helper()
	return mockRequest(t, srv, method, path, bearer(adminToken), body)
}

// mockOK is mockCall that must answer 200.
func mockOK(t *testing.T, srv *httptest.Server, method, path, body string) string {
	t.Helper()
	status, got := mockCall(t, srv, method, path, body)
	require.Equal(t, http.StatusOK, status, "%s %s: %s", method, path, got)
	return got
}

// postLoad POSTs body to /mock/load with the admin token.
func postLoad(t *testing.T, srv *httptest.Server, body string) (int, string) {
	t.Helper()
	return mockCall(t, srv, http.MethodPost, "/mock/load", body)
}

// loadRefusals decodes a 400's refusals.
func loadRefusals(t *testing.T, body string) []string {
	t.Helper()
	var got struct{ Refusals []string }
	require.NoError(t, json.Unmarshal([]byte(body), &got), "decode %s", body)
	return got.Refusals
}

// loadedState is everything a load may change, as one string: the
// /mock/state body and the identity row, loaded flag included.
func loadedState(t *testing.T, app *handlers.Application, srv *httptest.Server) string {
	t.Helper()
	state := mockOK(t, srv, http.MethodGet, "/mock/state", "")
	var account, region string
	var loaded bool
	err := app.Repository().DB().QueryRow(`SELECT account_id, region, loaded FROM identity`).Scan(&account, &region, &loaded)
	if err != nil {
		return state + "\nidentity: " + err.Error()
	}
	return fmt.Sprintf("%s\nidentity: %s %s loaded=%v", state, account, region, loaded)
}

// seedLoadRows creates a VPC, a role and an SSM parameter through the
// AWS surface and returns the VPC id.
func seedLoadRows(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	vpcID := seedVPC(t, srv)
	mustOK(t)(iamCall(t, srv, "CreateRole", url.Values{
		"RoleName": {"pre-load-role"}, "AssumeRolePolicyDocument": {`{"Version":"2012-10-17"}`},
	}))
	mustOK(t)(ssmCall(t, srv, "PutParameter", `{"Name":"/pre-load/param","Type":"String","Value":"v"}`))
	return vpcID
}

func TestMockLoad_UnroutedWithoutTheFlag(t *testing.T) {
	_, srv := newTestApp(t, ":memory:")
	unknown, unknownBody := doPost(t, srv, "/mock/no-such-path")
	status, body := mockRequest(t, srv, http.MethodPost, "/mock/load", nil, loadEnvelope(loadAccount, loadRegion))
	assert.Equal(t, unknown.StatusCode, status, "POST /mock/load answers as an unknown /mock path")
	assert.Equal(t, string(unknownBody), body)
}

func TestNewApplication_LoadNeedsAnAdminToken(t *testing.T) {
	_, err := handlers.NewApplication(handlers.Options{DBPath: ":memory:", LoadMaxBytes: loadLimit})
	require.ErrorIs(t, err, handlers.ErrLoadNeedsAdminToken)
	assert.ErrorContains(t, err, "Options.LoadMaxBytes")
	assert.ErrorContains(t, err, "AdminToken")
}

func TestMockLoad_GuardedAndCapped(t *testing.T) {
	envelope := loadEnvelope(loadAccount, loadRegion)
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:", LoadMaxBytes: int64(len(envelope))})
	seedLoadRows(t, srv)
	before := loadedState(t, app, srv)

	crossOrigin := bearer(adminToken)
	crossOrigin.Set("Origin", "https://attacker.example")
	for name, tc := range map[string]struct {
		header http.Header
		body   string
		want   int
	}{
		"no token":            {nil, envelope, http.StatusUnauthorized},
		"non-loopback Origin": {crossOrigin, envelope, http.StatusForbidden},
		"one byte over":       {bearer(adminToken), envelope + " ", http.StatusRequestEntityTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := mockRequest(t, srv, http.MethodPost, "/mock/load", tc.header, tc.body)
			assert.Equal(t, tc.want, status, body)
			assert.Equal(t, before, loadedState(t, app, srv), "changed something")
		})
	}

	status, body := postLoad(t, srv, envelope)
	assert.Equal(t, http.StatusOK, status, "a body at the limit loads: %s", body)
}

func TestMockLoad_EmptyLoadReplacesEveryRowAndKeepsTheSnapshot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "load.db")
	app, srv := newLoadApp(t, handlers.Options{DBPath: dbPath})
	vpcID := seedLoadRows(t, srv)
	mockOK(t, srv, http.MethodPost, "/mock/snapshot", "")

	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion))
	require.Equal(t, http.StatusOK, status, body)
	assert.JSONEq(t, `{"loaded":{},"absent":{},"unresolved":{}}`, body)

	db := app.Repository().DB()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT IN ('schema_version', 'sqlite_sequence')`)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rows.Close())
	require.NotEmpty(t, tables)
	for _, table := range tables {
		var n int
		require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM `+table).Scan(&n))
		if table == "identity" {
			assert.Equal(t, 1, n, "identity")
			continue
		}
		assert.Zero(t, n, "%s still holds rows", table)
	}
	assert.Equal(t, loadAccount, accountID(t, app))
	assert.Equal(t, loadRegion, storedIdentity(t, app).Region)
	loaded, err := app.Repository().Loaded()
	require.NoError(t, err)
	assert.True(t, loaded, "the load marks the db loaded")

	_, err = os.Stat(dbPath + ".snapshot")
	require.NoError(t, err, "the load removed the snapshot")
	mockOK(t, srv, http.MethodPost, "/mock/restore", "")
	state := mockOK(t, srv, http.MethodGet, "/mock/state", "")
	for _, row := range []string{vpcID, "pre-load-role", "/pre-load/param"} {
		assert.Contains(t, state, row, "restore did not bring back %s", row)
	}
	assert.Equal(t, awsproto.FakeAccountID, accountID(t, app), "restore brings back the identity it replaced")
}

func TestMockLoad_RefusalsChangeNothing(t *testing.T) {
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	mockOK(t, srv, http.MethodPost, "/mock/identity", `{"account_id":"`+otherAccount+`","region":"us-east-1"}`)
	seedLoadRows(t, srv)
	before := loadedState(t, app, srv)

	noExchanges := fmt.Sprintf(`{"account":%q,"region":%q,"timestamp":"2026-10-11T09:30:00Z","duration_ms":842,"calls":0}`, loadAccount, loadRegion)
	vpc := putVpc("vpc-0refused")
	pageOne := loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "<nextToken>page-2</nextToken>", vpcItem("vpc-0dup")))
	iamPage := func(tail string) string {
		return loadExchange("fakeaws-test", "ListVpcs", vpcBody("ListVpcs", tail, vpcItem("vpc-0iam")))
	}
	for name, tc := range map[string]struct {
		body string
		want []string
	}{
		"exchange no loader takes": {loadEnvelope(loadAccount, loadRegion, loadExchange("ec2", "DescribeFoo", "")),
			[]string{"exchange 0: no loader for ec2 DescribeFoo"}},
		"unknown envelope key": {strings.Replace(loadEnvelope(loadAccount, loadRegion), `"calls"`, `"kalls"`, 1),
			[]string{`invalid body: json: unknown field "kalls"`}},
		"unknown exchange key": {loadEnvelope(loadAccount, loadRegion, strings.Replace(vpc, `"body"`, `"bodyy"`, 1)),
			[]string{`invalid body: json: unknown field "bodyy"`}},
		"no exchanges key": {noExchanges,
			[]string{"exchanges is required: [] loads nothing"}},
		"null exchanges": {strings.Replace(noExchanges, `}`, `,"exchanges":null}`, 1),
			[]string{"exchanges is required: [] loads nothing"}},
		"every refusal listed": {loadEnvelope("12", "", loadExchange("ec2", "DescribeFoo", ""), vpc, loadExchange("iam", "ListBar", "")),
			[]string{"account must be 12 digits", "region must look like us-east-1",
				"exchange 0: no loader for ec2 DescribeFoo", "exchange 2: no loader for iam ListBar"}},
		"loaders' refusals roll back their writes": {loadEnvelope(loadAccount, loadRegion, vpc,
			textExchange("Refuse", "first"), textExchange("Refuse", "second")),
			[]string{"exchange 1: fakeaws-test Refuse: first", "exchange 2: fakeaws-test Refuse: second"}},
		"refusals before a failure, and where it stopped": {loadEnvelope(loadAccount, loadRegion,
			textExchange("Refuse", "vpc-0parent is refused"),
			textExchange("Fail", "")),
			[]string{"exchange 0: fakeaws-test Refuse: vpc-0parent is refused",
				"exchange 1: fakeaws-test Fail failed; the load stopped there and wrote nothing"}},
		"a parent read finds no row": {loadEnvelope(loadAccount, loadRegion, putSubnet("subnet-0orphan", "vpc-0absent")),
			[]string{"exchange 0: fakeaws-test PutSubnet: subnet subnet-0orphan names vpc vpc-0absent, which is not loaded"}},
		"a 500": {loadEnvelope(loadAccount, loadRegion, loadPage("fakeaws-test", "PutVpc", map[string]string{}, http.StatusInternalServerError, "")),
			[]string{"exchange 0: fakeaws-test PutVpc: answered 500, which is not a NotFound"}},
		"an error code that is not a NotFound": {loadEnvelope(loadAccount, loadRegion, loadPage("fakeaws-test", "PutVpc", map[string]string{}, http.StatusBadRequest,
			"<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors></Response>")),
			[]string{"exchange 0: fakeaws-test PutVpc: answered 400, which is not a NotFound"}},
		"a body that does not parse": {loadEnvelope(loadAccount, loadRegion,
			loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "", vpcItem("vpc-0a"))+"<trailer/>")),
			[]string{"exchange 0: fakeaws-test PutVpc: body is not XML: more than one root element"}},
		"an empty body": {loadEnvelope(loadAccount, loadRegion, loadExchange("fakeaws-test", "PutSubnet", "")),
			[]string{"exchange 0: fakeaws-test PutSubnet: body is not XML: no root element"}},
		"a JSON body where XML is answered": {loadEnvelope(loadAccount, loadRegion, loadExchange("fakeaws-test", "PutSubnet", "{}")),
			[]string{"exchange 0: fakeaws-test PutSubnet: body is not XML: text outside the root element"}},
		"two first pages answering one token": {loadEnvelope(loadAccount, loadRegion,
			loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "<nextToken>page-2</nextToken>", vpcItem("vpc-0a"))),
			loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "<nextToken>page-2</nextToken>", vpcItem("vpc-0b"))),
			loadPage("fakeaws-test", "PutVpc", map[string]string{"NextToken": "page-2"}, http.StatusOK, vpcBody("PutVpc", "", vpcItem("vpc-0c")))),
			[]string{"exchange 0: fakeaws-test PutVpc: truncated: it answers more pages, and no later page of its read carries its nextToken"}},
		"a page answering the token it carries": {loadEnvelope(loadAccount, loadRegion,
			loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "<nextToken>page-2</nextToken>", vpcItem("vpc-0a"))),
			loadPage("fakeaws-test", "PutVpc", map[string]string{"NextToken": "page-2"}, http.StatusOK, vpcBody("PutVpc", "<nextToken>page-2</nextToken>", vpcItem("vpc-0b")))),
			[]string{"exchange 1: fakeaws-test PutVpc: truncated: it answers more pages, and no later page of its read carries its nextToken"}},
		"a JSON NextToken no page carries": {loadEnvelope(loadAccount, loadRegion,
			jsonPage("GetVpcs", map[string]any{}, http.StatusOK, `{"Vpcs":[{"VpcId":"vpc-0json","CidrBlock":"10.0.0.0/16"}],"NextToken":"j-2"}`)),
			[]string{"exchange 0: fakeaws-test GetVpcs: truncated: it answers more pages, and no later page of its read carries its NextToken"}},
		"a nextToken no page carries": {loadEnvelope(loadAccount, loadRegion, pageOne),
			[]string{"exchange 0: fakeaws-test PutVpc: truncated: it answers more pages, and no later page of its read carries its nextToken"}},
		"an IAM Marker no page carries": {loadEnvelope(loadAccount, loadRegion, iamPage("<IsTruncated>true</IsTruncated><Marker>page-2</Marker>")),
			[]string{"exchange 0: fakeaws-test ListVpcs: truncated: it answers more pages, and no later page of its read carries its Marker"}},
		"an IAM IsTruncated with no Marker": {loadEnvelope(loadAccount, loadRegion, iamPage("<IsTruncated>true</IsTruncated>")),
			[]string{"exchange 0: fakeaws-test ListVpcs: truncated: it answers more pages, and no later page of its read carries its Marker"}},
		"an orphan page": {loadEnvelope(loadAccount, loadRegion,
			loadPage("fakeaws-test", "PutVpc", map[string]string{"NextToken": "page-9"}, http.StatusOK, vpcBody("PutVpc", "", vpcItem("vpc-0orphan")))),
			[]string{"exchange 0: fakeaws-test PutVpc: orphan page: no earlier page of its read answered the NextToken it carries"}},
		"an id in two pages of one chain": {loadEnvelope(loadAccount, loadRegion, pageOne,
			loadPage("fakeaws-test", "PutVpc", map[string]string{"NextToken": "page-2"}, http.StatusOK, vpcBody("PutVpc", "", vpcItem("vpc-0dup")))),
			[]string{"exchange 1: fakeaws-test PutVpc: vpc vpc-0dup repeats in its page chain, first at exchange 0"}},
		"an IsTruncated that is not false": {loadEnvelope(loadAccount, loadRegion, iamPage("<IsTruncated>TRUE</IsTruncated>")),
			[]string{"exchange 0: fakeaws-test ListVpcs: truncated: it answers more pages, and no later page of its read carries its Marker"}},
		"an id twice in a second read's chain": {loadEnvelope(loadAccount, loadRegion,
			loadPage("fakeaws-test", "PutVpc", map[string]string{"Filter.1.Name": "tag-key"}, http.StatusOK, vpcBody("PutVpc", "", vpcItem("vpc-0dup"))),
			loadPage("fakeaws-test", "PutVpc", map[string]string{"Filter.1.Name": "vpc-id"}, http.StatusOK, vpcBody("PutVpc", "", vpcItem("vpc-0dup"), vpcItem("vpc-0dup")))),
			[]string{"exchange 1: fakeaws-test PutVpc: vpc vpc-0dup repeats in its page chain, first at exchange 1"}},
		"one item recorded differently by two actions": {loadEnvelope(loadAccount, loadRegion,
			loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "", vpcItem("vpc-0both"))),
			loadExchange("fakeaws-test", "ListVpcs", vpcBody("ListVpcs", "", "<item><vpcId>vpc-0both</vpcId><cidrBlock>10.9.0.0/16</cidrBlock></item>"))),
			[]string{"exchange 1: fakeaws-test ListVpcs: vpc vpc-0both differs from exchange 0's (fakeaws-test PutVpc)"}},
		"one item recorded differently by two reads": {loadEnvelope(loadAccount, loadRegion,
			putVpc("vpc-0shared"), sharedGroup("tag-key", "web"), sharedGroup("vpc-id", "web-renamed")),
			[]string{"exchange 2: fakeaws-test DescribeSecurityGroups: security-group sg-0shared differs from exchange 1's (fakeaws-test DescribeSecurityGroups)"}},
		"a reference to a row no exchange loaded": {loadEnvelope(loadAccount, loadRegion,
			loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "", vpcItem("vpc-0a", refSet("vpc vpc-0absent"))))),
			[]string{"exchange 0: fakeaws-test PutVpc: vpc vpc-0a references vpc vpc-0absent, which no exchange loaded"}},
		"a recorded field the write drops": {loadEnvelope(loadAccount, loadRegion,
			loadExchange("fakeaws-test", "DropField", vpcBody("DropField", "", vpcItem("vpc-0a")))),
			[]string{"exchange 0: fakeaws-test DropField: vpc vpc-0a: the model cannot hold recorded vpcSet/item[0]/cidrBlock"}},
		"a field the render adds": {loadEnvelope(loadAccount, loadRegion,
			loadExchange("fakeaws-test", "RenderExtra", vpcBody("RenderExtra", "", vpcItem("vpc-0a"), vpcItem("vpc-0b")))),
			[]string{"exchange 0: fakeaws-test RenderExtra: vpc vpc-0a: fakeaws would answer vpcSet/item[0]/extra, which the recording does not hold",
				"exchange 0: fakeaws-test RenderExtra: vpc vpc-0b: fakeaws would answer vpcSet/item[1]/extra, which the recording does not hold"}},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := postLoad(t, srv, tc.body)
			require.Equal(t, http.StatusBadRequest, status, body)
			assert.Equal(t, tc.want, loadRefusals(t, body))
			assert.Equal(t, before, loadedState(t, app, srv), "a refused load changed something")
		})
	}
}

// TestMockLoad_LoaderErrorAbortsWith500: Fail ends the transaction, as
// SQLite does itself on SQLITE_FULL or IOERR, and returns a plain error.
// PutVpc, which runs after it, must never run: its write would commit
// on its own.
func TestMockLoad_LoaderErrorAbortsWith500(t *testing.T) {
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	seedLoadRows(t, srv)
	before := loadedState(t, app, srv)

	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion,
		putVpc("vpc-0late"), textExchange("Fail", "")))
	assert.Equal(t, http.StatusInternalServerError, status, body)
	var late int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_vpcs WHERE id = 'vpc-0late'`).Scan(&late))
	assert.Zero(t, late, "a loader ran after the failure and its write committed")
	assert.Equal(t, before, loadedState(t, app, srv), "a failed load changed something")
}

// TestMockLoad_FailedStatementAbortsEvenAsARefusal: QuoteFailure ends
// the transaction, runs a statement that fails (an Exec, a QueryRow's
// Scan, a Query, a Query row's Scan), and returns that as a refusal,
// quoted or wrapped. The load aborts all the same, and PutVpc, which
// runs after it, never writes.
func TestMockLoad_FailedStatementAbortsEvenAsARefusal(t *testing.T) {
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	seedLoadRows(t, srv)
	before := loadedState(t, app, srv)
	for _, form := range []string{"quote", "wrap", "queryrow", "query", "scan"} {
		t.Run(form, func(t *testing.T) {
			status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion,
				putVpc("vpc-0late"), textExchange("QuoteFailure", form)))
			assert.Equal(t, http.StatusInternalServerError, status, body)
			var late int
			require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_vpcs WHERE id = 'vpc-0late'`).Scan(&late))
			assert.Zero(t, late, "a loader ran after the failed statement and its write committed")
			assert.Equal(t, before, loadedState(t, app, srv), "a failed load changed something")
		})
	}
}

// lockedBuffer is a log destination the server's goroutines write while
// the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestMockLoad_FailureLogsOnlyTheExchange: a failed load's log line, and
// its answer, name the exchange's index and loader and nothing of the
// failure, which can quote the recorded body, whether the loader
// returned it (Fail) or panicked with it, decoding (Panic) or rendering
// a row (RenderPanic); a failure of the
// transaction itself says only that. A panic that reached
// middleware.Recoverer would answer an empty 500 and print its value to
// the stderr Recoverer bound at init, so the abort's answer is what
// shows it was caught first.
func TestMockLoad_FailureLogsOnlyTheExchange(t *testing.T) {
	logged := &lockedBuffer{}
	log.SetOutput(logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	const marker = "marker-4f7c-real-account-value"

	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	seedLoadRows(t, srv)
	before := loadedState(t, app, srv)
	for action, recorded := range map[string]string{
		"Fail": textBody(marker), "Panic": textBody(marker), "RenderPanic": vpcBody("RenderPanic", "", vpcItem(marker)),
	} {
		t.Run(action, func(t *testing.T) {
			status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion, loadExchange("fakeaws-test", action, recorded)))
			assert.Equal(t, http.StatusInternalServerError, status, body)
			want := "exchange 0: fakeaws-test " + action + " failed; the load stopped there and wrote nothing"
			assert.JSONEq(t, `{"status":"error","message":"`+want+`"}`, body)
			assert.Contains(t, logged.String(), "POST /mock/load: "+want+"\n")
			assert.NotContains(t, logged.String(), marker)
			assert.Equal(t, before, loadedState(t, app, srv), "a failed load changed something")
		})
	}

	_, err := app.Repository().DB().Exec(`DROP TABLE audit`)
	require.NoError(t, err)
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion))
	assert.Equal(t, http.StatusInternalServerError, status, body)
	assert.Contains(t, logged.String(), "POST /mock/load: the load's transaction failed and wrote nothing\n")
	assert.NotContains(t, logged.String(), "no such table")
	assert.NotContains(t, body, "no such table")
}

func TestMockLoad_SecondLoadReplacesTheFirst(t *testing.T) {
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion,
		putVpc("vpc-0first"), putSubnet("subnet-0first", "vpc-0first")))
	require.Equal(t, http.StatusOK, status, body)

	status, body = postLoad(t, srv, loadEnvelope(otherAccount, "us-west-2", putVpc("vpc-0second")))
	require.Equal(t, http.StatusOK, status, body)
	assert.JSONEq(t, `{"loaded":{"vpc":1},"absent":{},"unresolved":{}}`, body)

	db := app.Repository().DB()
	var vpcs, subnets int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM ec2_vpcs WHERE NOT (account_id = ? AND region = ? AND id = 'vpc-0second')`, otherAccount, "us-west-2").Scan(&vpcs))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM ec2_subnets`).Scan(&subnets))
	assert.Zero(t, vpcs, "a VPC other than the second load's remains")
	assert.Zero(t, subnets, "the first load's subnet remains")
	assert.Equal(t, otherAccount, accountID(t, app))
	assert.Equal(t, "us-west-2", storedIdentity(t, app).Region)
}

// TestMockLoad_RunsParentTablesFirst: PutSubnet is registered, and its
// exchange recorded, before PutVpc, yet the VPC its FK needs is stored
// first: loaders run by the table they write.
func TestMockLoad_RunsParentTablesFirst(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion,
		putSubnet("subnet-0ordered", "vpc-0ordered"), putVpc("vpc-0ordered")))
	require.Equal(t, http.StatusOK, status, body)
	assert.JSONEq(t, `{"loaded":{"vpc":1,"subnet":1},"absent":{},"unresolved":{}}`, body)
}

// TestMockLoad_NotFoundIsAbsent: a non-2xx answering one of its
// loader's NotFound codes loads nothing and counts under absent: an XML
// Code, or a JSON __type with or without its namespace and suffix.
func TestMockLoad_NotFoundIsAbsent(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion, putVpc("vpc-0found"),
		loadPage("fakeaws-test", "PutVpc", map[string]string{"VpcId.1": "vpc-0gone"}, http.StatusBadRequest,
			"<Response><Errors><Error><Code>InvalidVpcID.NotFound</Code><Message>gone</Message></Error></Errors><RequestID>r</RequestID></Response>"),
		jsonPage("GetVpcs", map[string]any{"VpcId": "vpc-0gone"}, http.StatusBadRequest, `{"__type":"com.amazonaws.ec2#InvalidVpcID.NotFound","message":"gone"}`),
		jsonPage("GetVpcs", map[string]any{"VpcId": "vpc-0gone2"}, http.StatusBadRequest, `{"__type":"InvalidVpcID.NotFound:http://internal.amazon.com/coral/com.amazon.coral.service/"}`)))
	require.Equal(t, http.StatusOK, status, body)
	assert.JSONEq(t, `{"loaded":{"vpc":1},"absent":{"vpc":3},"unresolved":{}}`, body)
}

// TestMockLoad_LoadsEveryPageOfAChain: each next page carries the token
// the page before it answered, as EC2, IAM and SSM's JSON page.
func TestMockLoad_LoadsEveryPageOfAChain(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	page := func(action, carried, tail, id string) string {
		params := map[string]string{"Filter.1.Name": "tag-key"}
		if carried != "" {
			params[map[string]string{"PutVpc": "NextToken", "ListVpcs": "Marker"}[action]] = carried
		}
		return loadPage("fakeaws-test", action, params, http.StatusOK, vpcBody(action, tail, vpcItem(id)))
	}
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion,
		page("PutVpc", "", "<nextToken>page-2</nextToken>", "vpc-0page1"),
		page("ListVpcs", "", "<IsTruncated>true</IsTruncated><Marker>m-2</Marker>", "vpc-0iam1"),
		page("PutVpc", "page-2", "<nextToken>page-3</nextToken>", "vpc-0page2"),
		page("ListVpcs", "m-2", "<IsTruncated>false</IsTruncated>", "vpc-0iam2"),
		page("PutVpc", "page-3", "", "vpc-0page3"),
		jsonPage("GetVpcs", map[string]any{}, http.StatusOK, `{"Vpcs":[{"VpcId":"vpc-0json1","CidrBlock":"10.0.0.0/16"}],"NextToken":"j-2"}`),
		jsonPage("GetVpcs", map[string]any{"NextToken": "j-2"}, http.StatusOK, `{"Vpcs":[{"VpcId":"vpc-0json2","CidrBlock":"10.0.0.0/16"}]}`)))
	require.Equal(t, http.StatusOK, status, body)
	assert.JSONEq(t, `{"loaded":{"vpc":7},"absent":{},"unresolved":{}}`, body)
}

// TestMockLoad_SameItemInTwoReadsLoadsOnce: the step-0 read answers its
// tagged group to a tag-key DescribeSecurityGroups and again to the
// vpc-id one; recorded equal, it loads once and counts once.
func TestMockLoad_SameItemInTwoReadsLoadsOnce(t *testing.T) {
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion,
		putVpc("vpc-0shared"), sharedGroup("tag-key", "web"), sharedGroup("vpc-id", "web")))
	require.Equal(t, http.StatusOK, status, body)
	assert.JSONEq(t, `{"loaded":{"vpc":1,"security-group":1},"absent":{},"unresolved":{}}`, body)
	var groups int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_security_groups`).Scan(&groups))
	assert.Equal(t, 1, groups)
}

// TestMockLoad_SameItemFromTwoActionsLoadsOnce: one item two actions
// answer under different roots, names and paths (as GetRole's Role and
// ListRoles' member are) compares by its fields: equal, it loads once,
// and a field either action's ignore entry names is not compared.
func TestMockLoad_SameItemFromTwoActionsLoadsOnce(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	vpc := func(cidr string) string { return `{"VpcId":"vpc-0both","CidrBlock":"` + cidr + `"}` }
	jsonBoth := func(getCidr string) string {
		return loadEnvelope(loadAccount, loadRegion,
			jsonPage("GetVpcs", map[string]any{}, http.StatusOK, `{"Vpcs":[`+vpc("10.0.0.0/16")+`]}`),
			jsonPage("GetVpc", map[string]any{"VpcId": "vpc-0both"}, http.StatusOK, `{"Vpc":`+vpc(getCidr)+`}`))
	}
	for name, envelope := range map[string]string{
		"XML roots": loadEnvelope(loadAccount, loadRegion,
			loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "", vpcItem("vpc-0both"))),
			loadExchange("fakeaws-test", "ListVpcs", vpcBody("ListVpcs", "", vpcItem("vpc-0both")))),
		"JSON paths": jsonBoth("10.0.0.0/16"),
	} {
		t.Run(name, func(t *testing.T) {
			status, body := postLoad(t, srv, envelope)
			require.Equal(t, http.StatusOK, status, body)
			assert.JSONEq(t, `{"loaded":{"vpc":1},"absent":{},"unresolved":{}}`, body)
		})
	}

	status, body := postLoad(t, srv, jsonBoth("10.9.0.0/16"))
	require.Equal(t, http.StatusBadRequest, status, body)
	assert.Equal(t, []string{"exchange 1: fakeaws-test GetVpc: vpc vpc-0both differs from exchange 0's (fakeaws-test GetVpcs)"}, loadRefusals(t, body))
	for action, path := range map[string]string{"GetVpcs": "Vpcs/CidrBlock", "GetVpc": "Vpc/CidrBlock"} {
		t.Run("ignored by "+action, func(t *testing.T) {
			handlers.WithLoadIgnores(t, handlers.IgnoreEntry{Key: handlers.LoadKey{Service: "fakeaws-test", Action: action},
				Path: path, Cite: "terraform-provider-aws@v5.100.0/internal/service/ec2/vpc_.go"})
			status, body := postLoad(t, srv, jsonBoth("10.9.0.0/16"))
			require.Equal(t, http.StatusOK, status, body)
			assert.JSONEq(t, `{"loaded":{"vpc":1},"absent":{},"unresolved":{}}`, body)
		})
	}
}

// TestMockLoad_NullOrEmptyTokenIsNone: a request token sent null or
// empty, as an SSM client may on a first page, carries nothing.
func TestMockLoad_NullOrEmptyTokenIsNone(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	for name, token := range map[string]any{"null": nil, "empty": ""} {
		t.Run(name, func(t *testing.T) {
			status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion,
				jsonPage("GetVpcs", map[string]any{"NextToken": token}, http.StatusOK, `{"Vpcs":[{"VpcId":"vpc-0first","CidrBlock":"10.0.0.0/16"}]}`)))
			require.Equal(t, http.StatusOK, status, body)
			assert.JSONEq(t, `{"loaded":{"vpc":1},"absent":{},"unresolved":{}}`, body)
		})
	}
}

// TestMockLoad_UnreadReferenceIsUnresolved: a reference the reader never
// reads, which no exchange loaded, is answered under unresolved, once
// however many rows name it; one naming a loaded row resolves.
func TestMockLoad_UnreadReferenceIsUnresolved(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion, loadExchange("fakeaws-test", "PutVpc", vpcBody("PutVpc", "",
		vpcItem("vpc-0a", refSet("dhcp-options dopt-0b unread", "dhcp-options dopt-0a unread", "vpc vpc-0b unread")),
		vpcItem("vpc-0b", refSet("dhcp-options dopt-0a unread", "vpc vpc-0a"))))))
	require.Equal(t, http.StatusOK, status, body)
	assert.JSONEq(t, `{"loaded":{"vpc":2},"absent":{},"unresolved":{"dhcp-options":["dopt-0a","dopt-0b"]}}`, body)
}

// TestMockLoad_ClearsTheRequestLog: a load clears the -record-requests
// log, as /mock/reset does; one its loaders refuse, or one that fails,
// changes nothing, the log included.
func TestMockLoad_ClearsTheRequestLog(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:", RecordRequests: true})
	seedVPC(t, srv)
	logged := func() int {
		var got struct{ Requests []json.RawMessage }
		require.NoError(t, json.Unmarshal([]byte(mockOK(t, srv, http.MethodGet, "/mock/requests", "")), &got))
		return len(got.Requests)
	}
	require.Equal(t, 1, logged(), "CreateVpc is logged")

	for _, refused := range []struct {
		exchange string
		status   int
	}{
		{textExchange("Refuse", "kept"), http.StatusBadRequest},
		{textExchange("Fail", ""), http.StatusInternalServerError},
	} {
		status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion, refused.exchange))
		require.Equal(t, refused.status, status, body)
		assert.Equal(t, 1, logged(), "a load answered %d cleared the log", refused.status)
	}

	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion))
	require.Equal(t, http.StatusOK, status, body)
	assert.Zero(t, logged(), "the load left pre-load traffic in the log")
}

type answer struct {
	status int
	body   string
	err    error
}

// sendAsync sends req on a goroutine and sends its answer, or the error,
// on the returned channel, so a failure is asserted on the test goroutine.
func sendAsync(srv *httptest.Server, req *http.Request) <-chan answer {
	done := make(chan answer, 1)
	client := *srv.Client()
	client.Timeout = 30 * time.Second
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			done <- answer{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		done <- answer{resp.StatusCode, string(b), err}
	}()
	return done
}

// holdLoad starts a load of envelope that holds inside its transaction,
// after its PutVpc write, until release is called (or t ends), and
// returns once it holds.
func holdLoad(t *testing.T, srv *httptest.Server, envelope string) (release func(), done <-chan answer) {
	t.Helper()
	held, unblock := make(chan struct{}), make(chan struct{})
	handlers.HoldLoad(t, func() {
		close(held)
		<-unblock
	})
	var once sync.Once
	release = func() { once.Do(func() { close(unblock) }) }
	t.Cleanup(release)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mock/load", strings.NewReader(envelope))
	require.NoError(t, err)
	req.Header = bearer(adminToken)
	done = sendAsync(srv, req)
	select {
	case <-held:
	case a := <-done:
		t.Fatalf("the load answered before its hold: %d %s %v", a.status, a.body, a.err)
	case <-time.After(30 * time.Second):
		t.Fatal("the load never reached its hold")
	}
	return release, done
}

// notYet fails t if pending answers within 200ms.
func notYet(t *testing.T, pending <-chan answer, what string) {
	t.Helper()
	select {
	case a := <-pending:
		t.Fatalf("%s answered mid-load: %d %s %v", what, a.status, a.body, a.err)
	case <-time.After(200 * time.Millisecond):
	}
}

// awaitOK waits for pending's answer, which must be a 200.
func awaitOK(t *testing.T, pending <-chan answer, what string) string {
	t.Helper()
	select {
	case a := <-pending:
		require.NoError(t, a.err, what)
		require.Equal(t, http.StatusOK, a.status, "%s: %s", what, a.body)
		return a.body
	case <-time.After(30 * time.Second):
		t.Fatalf("%s never answered after the commit", what)
		return ""
	}
}

func TestMockLoad_RequestWaitsForCommit(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	release, loadDone := holdLoad(t, srv, loadEnvelope(loadAccount, loadRegion, putVpc("vpc-0held")))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/ec2/region/"+loadRegion,
		strings.NewReader(url.Values{"Action": {"DescribeVpcs"}, "Version": {ec2Version}}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	described := sendAsync(srv, req)
	notYet(t, described, "DescribeVpcs")

	release()
	awaitOK(t, loadDone, "the load")
	assert.Contains(t, awaitOK(t, described, "DescribeVpcs"), "<vpcId>vpc-0held</vpcId>", "DescribeVpcs answers the loaded rows")
}

// TestMockLoad_RestoreWaitsForTheLoad: a restore sent mid-load runs after
// the commit, never on the db handle the load's transaction holds.
func TestMockLoad_RestoreWaitsForTheLoad(t *testing.T) {
	app, srv := newLoadApp(t, handlers.Options{DBPath: filepath.Join(t.TempDir(), "load.db")})
	vpcID := seedVPC(t, srv)
	mockOK(t, srv, http.MethodPost, "/mock/snapshot", "")
	release, loadDone := holdLoad(t, srv, loadEnvelope(loadAccount, loadRegion, putVpc("vpc-0held")))

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mock/restore", nil)
	require.NoError(t, err)
	req.Header = bearer(adminToken)
	restored := sendAsync(srv, req)
	notYet(t, restored, "/mock/restore")

	release()
	awaitOK(t, loadDone, "the load")
	awaitOK(t, restored, "/mock/restore")
	state := mockOK(t, srv, http.MethodGet, "/mock/state/ec2", "")
	assert.Contains(t, state, vpcID, "the restore ran after the load")
	assert.NotContains(t, state, "vpc-0held")
	assert.Equal(t, awsproto.FakeAccountID, accountID(t, app))
}

// TestMockLoad_SourceNeverReachesTheDBHandle: inside a load's
// transaction the db's one connection is taken, so a loader that reads
// the account or reaches the repository's handle waits forever. In the
// load files only LoadTx's constructor, Repository.Load, reaches it.
func TestMockLoad_SourceNeverReachesTheDBHandle(t *testing.T) {
	reach := regexp.MustCompile(`AccountID\(\)|r\.db`)
	var files []string
	for _, pattern := range []string{"load*.go", filepath.Join("..", "repository", "load*.go")} {
		matched, err := filepath.Glob(pattern)
		require.NoError(t, err)
		files = append(files, matched...)
	}
	require.Contains(t, files, "load.go")
	var hits []string
	for _, path := range files {
		src, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, line := range strings.Split(string(src), "\n") {
			if reach.MatchString(line) {
				hits = append(hits, filepath.ToSlash(path)+": "+strings.TrimSpace(line))
			}
		}
	}
	// Split, so this file is not a hit itself.
	assert.Equal(t, []string{"../repository/load.go: tx, err := r" + ".db.Begin()"}, hits)
}
