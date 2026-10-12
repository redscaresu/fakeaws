package handlers_test

import (
	"encoding/json"
	"fmt"
	"io"
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

// loadExchange is one exchange of a recorded read, as JSON.
func loadExchange(service, action, body string) string {
	b, _ := json.Marshal(map[string]any{
		"service": service, "protocol": "query", "action": action, "params": map[string]string{},
		"status": http.StatusOK, "body": body,
	})
	return string(b)
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
	vpc := loadExchange("fakeaws-test", "PutVpc", "vpc-0refused")
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
			loadExchange("fakeaws-test", "Refuse", "first"), loadExchange("fakeaws-test", "Refuse", "second")),
			[]string{"exchange 1: fakeaws-test Refuse: first", "exchange 2: fakeaws-test Refuse: second"}},
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
		loadExchange("fakeaws-test", "PutVpc", "vpc-0late"), loadExchange("fakeaws-test", "Fail", "")))
	assert.Equal(t, http.StatusInternalServerError, status, body)
	var late int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_vpcs WHERE id = 'vpc-0late'`).Scan(&late))
	assert.Zero(t, late, "a loader ran after the failure and its write committed")
	assert.Equal(t, before, loadedState(t, app, srv), "a failed load changed something")
}

func TestMockLoad_SecondLoadReplacesTheFirst(t *testing.T) {
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, loadRegion,
		loadExchange("fakeaws-test", "PutVpc", "vpc-0first"),
		loadExchange("fakeaws-test", "PutSubnet", "subnet-0first vpc-0first")))
	require.Equal(t, http.StatusOK, status, body)

	status, body = postLoad(t, srv, loadEnvelope(otherAccount, "us-west-2",
		loadExchange("fakeaws-test", "PutVpc", "vpc-0second")))
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
		loadExchange("fakeaws-test", "PutSubnet", "subnet-0ordered vpc-0ordered"),
		loadExchange("fakeaws-test", "PutVpc", "vpc-0ordered")))
	require.Equal(t, http.StatusOK, status, body)
	assert.JSONEq(t, `{"loaded":{"vpc":1,"subnet":1},"absent":{},"unresolved":{}}`, body)
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
		{loadExchange("fakeaws-test", "Refuse", "kept"), http.StatusBadRequest},
		{loadExchange("fakeaws-test", "Fail", ""), http.StatusInternalServerError},
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
	release, loadDone := holdLoad(t, srv, loadEnvelope(loadAccount, loadRegion, loadExchange("fakeaws-test", "PutVpc", "vpc-0held")))

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
	release, loadDone := holdLoad(t, srv, loadEnvelope(loadAccount, loadRegion, loadExchange("fakeaws-test", "PutVpc", "vpc-0held")))

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
