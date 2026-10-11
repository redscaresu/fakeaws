package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

const requestDeadline = 10 * time.Second

type loggedRequest struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	Classification string `json:"classification"`
}

// newRecordingApp is newOptionsApp with RecordRequests and the admin
// token it needs, and a deadline on every request the server's client
// sends.
func newRecordingApp(t *testing.T, opts handlers.Options) (*handlers.Application, *httptest.Server) {
	t.Helper()
	opts.RecordRequests, opts.AdminToken = true, adminToken
	app, srv := newOptionsApp(t, opts)
	srv.Client().Timeout = requestDeadline
	return app, srv
}

func loggedRequests(t *testing.T, srv *httptest.Server) []loggedRequest {
	t.Helper()
	status, body := doAdmin(t, srv, http.MethodGet, "/mock/requests", bearer(adminToken))
	require.Equal(t, http.StatusOK, status, body)
	var got struct {
		Requests []loggedRequest `json:"requests"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &got), body)
	require.NotNil(t, got.Requests, "requests is [], never null: %s", body)
	return got.Requests
}

// stateAudit is /mock/state's audit block, read with header.
func stateAudit(t *testing.T, srv *httptest.Server, header http.Header) []map[string]any {
	t.Helper()
	status, body := doAdmin(t, srv, http.MethodGet, "/mock/state", header)
	require.Equal(t, http.StatusOK, status, body)
	var state struct {
		Audit []map[string]any `json:"audit"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &state), body)
	require.NotNil(t, state.Audit, "audit is [], never null: %s", body)
	return state.Audit
}

// testRoutes adds /test routes to app's router: one that panics, one
// that writes 200 and then panics, one that answers 503 unmarked, one that marks unimplemented-501 and
// answers 200, and one that marks unimplemented-501 then filter-refused.
func testRoutes(app *handlers.Application) *chi.Mux {
	mux := app.Router().(*chi.Mux)
	mux.Get("/test/panic", func(http.ResponseWriter, *http.Request) { panic("test route") })
	mux.Get("/test/panic-after-200", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic("test route after 200")
	})
	mux.Get("/test/503", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	mux.Get("/test/marked-200", func(w http.ResponseWriter, _ *http.Request) {
		handlers.MarkClass(w, handlers.ClassUnimplemented)
		w.WriteHeader(http.StatusOK)
	})
	mux.Get("/test/remarked", func(w http.ResponseWriter, _ *http.Request) {
		handlers.MarkClass(w, handlers.ClassUnimplemented)
		handlers.MarkClass(w, handlers.RequestClass("filter-refused"))
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// providerTraffic sends an STS request answered from rows, an
// unmodelled STS action and a path no service owns.
func providerTraffic(t *testing.T, srv *httptest.Server) {
	t.Helper()
	resp, body := stsCall(t, srv, "GetCallerIdentity")
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	resp, body = stsCall(t, srv, "AssumeRole")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
	resp, body = doGet(t, srv, "/secret-bucket-name/key")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
}

func TestContract_request_log_off_by_default(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	providerTraffic(t, srv)

	wantStatus, wantBody := doAdmin(t, srv, http.MethodGet, "/mock/x", http.Header{})
	require.Equal(t, http.StatusNotImplemented, wantStatus, "the router's 501")
	for _, rt := range []adminRoute{{http.MethodGet, "/mock/requests"}, {http.MethodPost, "/mock/requests/clear"}} {
		status, body := doAdmin(t, srv, rt.method, rt.path, http.Header{})
		assert.Equal(t, wantStatus, status, "%s %s", rt.method, rt.path)
		assert.Equal(t, wantBody, body, "%s %s", rt.method, rt.path)
	}
	assert.Empty(t, stateAudit(t, srv, http.Header{}), "nothing is recorded")
}

func TestContract_request_log_needs_admin_token(t *testing.T) {
	app, err := handlers.NewApplication(handlers.Options{DBPath: ":memory:", RecordRequests: true})
	assert.ErrorIs(t, err, handlers.ErrRecordRequestsNeedsAdminToken)
	assert.ErrorContains(t, err, "admin token")
	assert.Nil(t, app)
}

func TestRequestLog_CompletionOrderSkipsAdminAndHealthz(t *testing.T) {
	app, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	entered, release := make(chan struct{}), make(chan struct{})
	testRoutes(app).Get("/test/slow", func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusAccepted)
	})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock) // runs before srv.Close, which waits on /test/slow

	slow := make(chan int, 1)
	go func() {
		status := 0
		if resp, err := srv.Client().Get(srv.URL + "/test/slow"); err == nil {
			resp.Body.Close()
			status = resp.StatusCode
		}
		slow <- status
	}()
	select {
	case <-entered:
	case <-time.After(requestDeadline):
		t.Fatal("/test/slow never reached its handler")
	}

	resp, body := stsCall(t, srv, "GetCallerIdentity")
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	for _, rt := range []adminRoute{{http.MethodGet, "/healthz"}, {http.MethodGet, "/mock/state"}, {http.MethodGet, "/mock/x"}, {http.MethodGet, "/mock"}} {
		doAdmin(t, srv, rt.method, rt.path, http.Header{})
	}
	unblock()
	select {
	case status := <-slow:
		require.Equal(t, http.StatusAccepted, status)
	case <-time.After(requestDeadline):
		t.Fatal("/test/slow never answered")
	}

	assert.Equal(t, []loggedRequest{
		{http.MethodPost, "/sts/", http.StatusOK, "answered-from-rows"},
		{http.MethodGet, "/test/slow", http.StatusAccepted, "answered-from-rows"},
	}, loggedRequests(t, srv), "completion order; /mock and /healthz are not recorded")
}

func TestRequestLog_ClearResetSnapshotRestoreRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fakeaws.db")
	app, srv := newRecordingApp(t, handlers.Options{DBPath: dbPath})
	sts := loggedRequest{http.MethodPost, "/sts/", http.StatusOK, "answered-from-rows"}
	getCallerIdentity := func() {
		resp, body := stsCall(t, srv, "GetCallerIdentity")
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	}
	admin := func(path string) {
		status, body := doAdmin(t, srv, http.MethodPost, path, bearer(adminToken))
		require.Equal(t, http.StatusOK, status, "%s: %s", path, body)
	}

	getCallerIdentity()
	admin("/mock/requests/clear")
	assert.Empty(t, loggedRequests(t, srv), "clear empties the log")

	getCallerIdentity()
	admin("/mock/reset")
	assert.Empty(t, loggedRequests(t, srv), "/mock/reset empties the log")

	getCallerIdentity()
	admin("/mock/snapshot")
	assert.Equal(t, []loggedRequest{sts}, loggedRequests(t, srv), "snapshot leaves the log")
	getCallerIdentity()
	admin("/mock/restore")
	assert.Equal(t, []loggedRequest{sts, sts}, loggedRequests(t, srv), "restore leaves the log")

	require.NoError(t, app.Close())
	_, restarted := newRecordingApp(t, handlers.Options{DBPath: dbPath})
	assert.Empty(t, loggedRequests(t, restarted), "a restart on the same db starts empty")
}

func TestContract_request_log_unimplemented_501(t *testing.T) {
	app, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	testRoutes(app)

	resp, body := doGet(t, srv, "/no/such/path")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "NotFound: %s", body)
	resp, body = doGet(t, srv, "/ec2/region/us-east-1")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "MethodNotAllowed: %s", body)
	resp, body = stsCall(t, srv, "AssumeRole")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
	resp, body = ssmCall(t, srv, "GetParametersByPath", `{"Path":"/app"}`)
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
	resp, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"missing"}})
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "%s", body)
	for _, path := range []string{"/test/503", "/test/marked-200", "/test/remarked"} {
		doGet(t, srv, path)
	}

	assert.Equal(t, []loggedRequest{
		{http.MethodGet, "/no/such/path", http.StatusNotImplemented, "unimplemented-501"},
		{http.MethodGet, "/ec2/region/us-east-1", http.StatusNotImplemented, "unimplemented-501"},
		{http.MethodPost, "/sts/", http.StatusNotImplemented, "unimplemented-501"},
		{http.MethodPost, "/ssm/region/us-east-1", http.StatusNotImplemented, "unimplemented-501"},
		{http.MethodPost, "/iam", http.StatusNotFound, "answered-from-rows"},
		{http.MethodGet, "/test/503", http.StatusServiceUnavailable, "unimplemented-501"},
		{http.MethodGet, "/test/marked-200", http.StatusOK, "unimplemented-501"},
		{http.MethodGet, "/test/remarked", http.StatusOK, "filter-refused"},
	}, loggedRequests(t, srv))
}

func TestContract_request_log_panic_recorded(t *testing.T) {
	app, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	testRoutes(app)

	resp, body := doGet(t, srv, "/test/panic")
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode, "%s", body)
	resp, body = doGet(t, srv, "/test/panic-after-200")
	require.Equal(t, http.StatusOK, resp.StatusCode, "the 200 went out before the panic: %s", body)
	assert.Equal(t, []loggedRequest{
		{http.MethodGet, "/test/panic", http.StatusInternalServerError, "unimplemented-501"},
		{http.MethodGet, "/test/panic-after-200", http.StatusInternalServerError, "unimplemented-501"},
	}, loggedRequests(t, srv))
}

func TestContract_state_audit_no_values(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	providerTraffic(t, srv)

	_, state := doAdmin(t, srv, http.MethodGet, "/mock/state", bearer(adminToken))
	assert.NotContains(t, state, "secret-bucket-name", "no path reaches /mock/state")
	audit := stateAudit(t, srv, bearer(adminToken))
	for _, e := range audit {
		var keys []string
		for k := range e {
			keys = append(keys, k)
		}
		assert.ElementsMatch(t, []string{"service", "protocol", "action", "status", "class"}, keys, "%v", e)
	}
	assert.Equal(t, []map[string]any{
		{"service": "sts", "protocol": "", "action": "", "status": float64(http.StatusOK), "class": "answered-from-rows"},
		{"service": "sts", "protocol": "", "action": "", "status": float64(http.StatusNotImplemented), "class": "unimplemented-501"},
		{"service": "", "protocol": "", "action": "", "status": float64(http.StatusNotImplemented), "class": "unimplemented-501"},
	}, audit)
}

func TestRequestLog_ConcurrentRequestsAllRecorded(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	const n = 50
	ctx, cancel := context.WithTimeout(context.Background(), requestDeadline)
	defer cancel()

	statuses := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			form := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}.Encode()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/sts/", strings.NewReader(form))
			if err != nil {
				statuses <- 0
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := srv.Client().Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			resp.Body.Close()
			statuses <- resp.StatusCode
		})
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		require.Equal(t, http.StatusOK, status)
	}

	got := loggedRequests(t, srv)
	assert.Len(t, got, n)
	for _, e := range got {
		assert.Equal(t, loggedRequest{http.MethodPost, "/sts/", http.StatusOK, "answered-from-rows"}, e)
	}
}

func TestRequestLog_AdminTokenGatesIt(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	providerTraffic(t, srv)

	for _, rt := range []adminRoute{{http.MethodGet, "/mock/requests"}, {http.MethodPost, "/mock/requests/clear"}} {
		status, body := doAdmin(t, srv, rt.method, rt.path, http.Header{})
		assert.Equal(t, http.StatusUnauthorized, status, "%s %s: %s", rt.method, rt.path, body)
		assert.NotContains(t, body, "secret-bucket-name", "%s %s", rt.method, rt.path)
	}
	status, body := doAdmin(t, srv, http.MethodGet, "/mock/requests", bearer(adminToken))
	assert.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "secret-bucket-name", "the bearer reads the log")
}
