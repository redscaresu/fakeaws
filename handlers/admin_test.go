package handlers_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdminMockState_ReturnsDocumentedShape pins the /mock/state
// contract topology_derive_aws will key off. The shape is documented
// inline in admin.go § stateSchemaVersion; this test asserts the keys
// the audit will look for.
func TestAdminMockState_ReturnsDocumentedShape(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/state")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var state map[string]any
	require.NoError(t, json.Unmarshal(body, &state), "decode")
	for _, want := range []string{"schema_version", "operations", "audit", "iam", "s3"} {
		assert.Contains(t, state, want, "missing key %q in /mock/state response: %s", want, body)
	}
	v, _ := state["schema_version"].(float64)
	assert.Equal(t, float64(1), v, "schema_version: got %v want 1", state["schema_version"])
}

func TestAdminMockState_PerServiceFiltersToBlock(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/state/iam")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var state map[string]any
	require.NoError(t, json.Unmarshal(body, &state), "decode")
	assert.Contains(t, state, "iam", "expected iam block in per-service response: %s", body)
	assert.NotContains(t, state, "s3", "per-service /state/iam should NOT include s3 block: %s", body)
}

func TestAdminMockState_UnknownServiceReturnsEmptyBlock(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/state/notreal")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), `"notreal":{}`, "expected empty block for unknown service: %s", body)
}

func TestAdminMockReset_OK(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doPost(t, srv, "/mock/reset")
	require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
}

func TestAdminMockSnapshot_MemoryConflict(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusConflict, resp.StatusCode, "snapshot meaningless on :memory:; body: %s", body)
}

func TestAdminMockRestore_NoBaselineIs404(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	srv := newTestServer(t, dbPath)

	resp, body := doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "no snapshot baseline; body: %s", body)
}

func TestAdminMockSnapshotRestore_FileBackedRoundTrips(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	srv := newTestServer(t, dbPath)

	// Snapshot the empty state.
	r, b := doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusOK, r.StatusCode, "snapshot body %s", b)

	// Restore — the snapshot file exists, so this should 200.
	r, b = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, r.StatusCode, "restore body %s", b)
}

func TestAdminMockRestore_MemoryConflict(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusConflict, resp.StatusCode, "restore meaningless on :memory:; body: %s", body)
	assert.NoFileExists(t, ":memory:", ":memory: must not create a file")
}

// assertOwnerOnly checks each path is a file with mode exactly 0600.
func assertOwnerOnly(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		fi, err := os.Stat(p)
		if assert.NoError(t, err) {
			assert.Equal(t, os.FileMode(0o600).String(), fi.Mode().Perm().String(), filepath.Base(p))
		}
	}
}

func TestContract_file_backed_db_owner_only(t *testing.T) {
	// Under umask 022 a file created without an explicit mode is 0644.
	umask := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(umask) })
	dbPath := filepath.Join(t.TempDir(), "test.db")
	live := []string{dbPath, dbPath + "-wal", dbPath + "-shm"}
	srv := newTestServer(t, dbPath)

	resp, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"owner-only"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateQueue: %s", body)
	assertOwnerOnly(t, live...)

	// Left by a snapshot killed mid-VACUUM.
	require.NoError(t, os.WriteFile(dbPath+".snapshot.tmp", []byte("partial"), 0o644))
	resp, body = doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusOK, resp.StatusCode, "snapshot: %s", body)
	assertOwnerOnly(t, dbPath+".snapshot")
	assert.NoFileExists(t, dbPath+".snapshot.tmp")

	resp, body = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, resp.StatusCode, "restore: %s", body)
	assertOwnerOnly(t, live...)

	require.NoError(t, os.Remove(dbPath))
	resp, body = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, resp.StatusCode, "restore over a removed db: %s", body)
	assertOwnerOnly(t, live...)
}

// A failed VACUUM INTO leaves no .snapshot, so the next restore is 404
// instead of copying an empty file over the live db. Nor is there one
// while VACUUM runs, so a kill then leaves none either.
func TestAdminMockSnapshot_FailedVacuumLeavesNoSnapshot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	srv := newTestServer(t, dbPath)
	resp, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"survives"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateQueue: %s", body)

	var statDuringVacuum error
	vacuum := repository.VacuumInto
	repository.VacuumInto = func(*sql.DB, string) error {
		_, statDuringVacuum = os.Stat(dbPath + ".snapshot")
		return errors.New("forced vacuum failure")
	}
	t.Cleanup(func() { repository.VacuumInto = vacuum })

	resp, body = doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode, "snapshot: %s", body)
	assert.ErrorIs(t, statDuringVacuum, os.ErrNotExist, ".snapshot exists while VACUUM runs")
	assert.NoFileExists(t, dbPath+".snapshot")
	assert.NoFileExists(t, dbPath+".snapshot.tmp")

	resp, body = doPost(t, srv, "/mock/restore")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "restore after a failed snapshot: %s", body)
	resp, body = sqsCall(t, srv, "GetQueueUrl", `{"QueueName":"survives"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "live db intact: %s", body)
}

func TestAdminMockImages_SeededImageLaunches(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	const ami = "ami-0123456789abcdef0"

	seed := `{"ami_id":"` + ami + `","name":"al2023-ami-real","region":"us-east-1","root_device_name":"/dev/sdz","account_id":"000000000000"}`
	resp, body := doPostJSON(t, srv, "/mock/images", seed)
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed: %s", body)
	resp, body = doPostJSON(t, srv, "/mock/images", seed)
	require.Equal(t, http.StatusOK, resp.StatusCode, "identical re-seed: %s", body)

	resp, body = ec2Call(t, srv, region, "DescribeImages", url.Values{"ImageId.1": {ami}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
	assert.Contains(t, string(body), ami)
	assert.Contains(t, string(body), "<rootDeviceName>/dev/sdz</rootDeviceName>", "seeded root device: %s", body)
	assert.Contains(t, string(body), "<imageOwnerId>amazon</imageOwnerId>", "owner defaults to the AL2023 fixture's: %s", body)

	subnetID := adminTestSubnet(t, srv, region)
	resp, body = runImage(t, srv, region, subnetID, ami)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "RunInstances seeded: %s", body)
	resp, body = runImage(t, srv, region, subnetID, "ami-0fedcba9876543210")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "InvalidAMIID.NotFound", "unseeded id still refused")

	resp, body = doPost(t, srv, "/mock/reset")
	require.Equal(t, http.StatusOK, resp.StatusCode, "reset: %s", body)
	subnetID = adminTestSubnet(t, srv, region)
	resp, body = runImage(t, srv, region, subnetID, ami)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "InvalidAMIID.NotFound", "reset drops the seeded image")
}

// TestAdminMockImages_ReseedConflicts pins that a re-seed never
// changes a stored image: identical fields are 200 with the stored row,
// any differing field is 409 naming it. Fixture ids count as stored,
// in a region touched before or not.
func TestAdminMockImages_ReseedConflicts(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	const ami = "ami-0123456789abcdef0"

	seed := `{"ami_id":"` + ami + `","name":"al2023-ami-real","region":"us-east-1","root_device_name":"/dev/sdz"}`
	resp, body := doPostJSON(t, srv, "/mock/images", seed)
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed: %s", body)

	for name, tc := range map[string]struct{ body, wantMessage, region, ami, wantRootDevice string }{
		"differing re-seed": {
			body:        `{"ami_id":"` + ami + `","name":"al2023-ami-other","region":"us-east-1","root_device_name":"/dev/xvda"}`,
			wantMessage: ami + " already exists in us-east-1 with a different name, root_device_name",
			region:      "us-east-1", ami: ami, wantRootDevice: "/dev/sdz",
		},
		"differing AL2023 fixture": {
			body:        `{"ami_id":"` + handlers.AL2023AMIID + `","name":"al2023-ami-real","region":"us-east-1","root_device_name":"/dev/xvda","owner_id":"137112412989"}`,
			wantMessage: handlers.AL2023AMIID + " already exists in us-east-1 with a different name, owner_id",
			region:      "us-east-1", ami: handlers.AL2023AMIID, wantRootDevice: "/dev/xvda",
		},
		"differing fixture in an untouched region": {
			body:        `{"ami_id":"ami-0abcd1234","name":"amzn2-ami-hvm-2.0","region":"eu-west-3","root_device_name":"/dev/sdz","virtualization_type":"paravirtual"}`,
			wantMessage: "ami-0abcd1234 already exists in eu-west-3 with a different virtualization_type, root_device_name",
			region:      "eu-west-3", ami: "ami-0abcd1234", wantRootDevice: "/dev/xvda",
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := amiRowCount(t, app)
			resp, body := doPostJSON(t, srv, "/mock/images", tc.body)
			assert.Equal(t, http.StatusConflict, resp.StatusCode, "body: %s", body)
			assert.Equal(t, tc.wantMessage, adminErrorMessage(t, body))
			assert.Equal(t, before, amiRowCount(t, app), "conflict wrote an image row")

			resp, body = ec2Call(t, srv, tc.region, "DescribeImages", url.Values{"ImageId.1": {tc.ami}})
			require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
			assert.Contains(t, string(body), "<rootDeviceName>"+tc.wantRootDevice+"</rootDeviceName>", "stored row unchanged: %s", body)
		})
	}

	for name, tc := range map[string]struct{ body, wantName string }{
		"identical re-seed":        {seed, "al2023-ami-real"},
		"identical AL2023 fixture": {`{"ami_id":"` + handlers.AL2023AMIID + `","name":"al2023-ami-2023.6.20241010.0-kernel-6.1-x86_64","region":"us-east-1","root_device_name":"/dev/xvda"}`, "al2023-ami-2023.6.20241010.0-kernel-6.1-x86_64"},
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := doPostJSON(t, srv, "/mock/images", tc.body)
			require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)
			var got struct {
				Image map[string]string `json:"image"`
			}
			require.NoError(t, json.Unmarshal(body, &got), "decode %s", body)
			assert.Equal(t, tc.wantName, got.Image["name"], "returns the stored row")
		})
	}
}

func TestAdminMockImages_InvalidBodyWritesNothing(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	bigName := strings.Repeat("x", 64<<10)

	for name, tc := range map[string]struct{ body, wantMessage string }{
		"malformed id in an untouched region": {`{"ami_id":"ami-NOTHEX","name":"x","region":"ap-south-2","root_device_name":"/dev/xvda"}`,
			"ami_id must be ami- followed by 8 or 17 lowercase hex digits"},
		"id of another length": {`{"ami_id":"ami-0123456789","name":"x","region":"us-east-1","root_device_name":"/dev/xvda"}`,
			"ami_id must be ami- followed by 8 or 17 lowercase hex digits"},
		"no region": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa1","name":"x","root_device_name":"/dev/xvda"}`,
			"region must look like us-east-1"},
		"upper-case region": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa6","name":"x","region":"US-East-1","root_device_name":"/dev/xvda"}`,
			"region must look like us-east-1"},
		"region with trailing space": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa7","name":"x","region":"us-east-1 ","root_device_name":"/dev/xvda"}`,
			"region must look like us-east-1"},
		"no name": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa9","region":"us-east-1","root_device_name":"/dev/xvda"}`,
			"name is required"},
		"no root device name": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa2","name":"x","region":"us-east-1"}`,
			"root_device_name is required"},
		"other account": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa5","name":"x","region":"us-east-1","root_device_name":"/dev/xvda","account_id":"111122223333"}`,
			"account_id must be 000000000000"},
		"trailing data": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa4","name":"x","region":"us-east-1","root_device_name":"/dev/xvda"} junk`,
			"invalid body: one JSON object expected"},
		"unknown field (typo)": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa3","name":"x","region":"us-east-1","root_device":"/dev/xvda"}`,
			`invalid body: json: unknown field "root_device"`},
		"oversized body": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa8","region":"us-east-1","root_device_name":"/dev/xvda","name":"` + bigName + `"}`,
			"invalid body: http: request body too large"},
	} {
		t.Run(name, func(t *testing.T) {
			before := amiRowCount(t, app)
			resp, body := doPostJSON(t, srv, "/mock/images", tc.body)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", body)
			assert.Equal(t, tc.wantMessage, adminErrorMessage(t, body))
			assert.Equal(t, before, amiRowCount(t, app), "rejected request wrote an image row in some region or account")
		})
	}
}

// ----- helpers -----

// amiRowCount counts image rows across every account and region.
func amiRowCount(t *testing.T, app *handlers.Application) int {
	t.Helper()
	var n int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_amis`).Scan(&n))
	return n
}

func adminErrorMessage(t *testing.T, body []byte) string {
	t.Helper()
	var got struct {
		Status, Message string
	}
	require.NoError(t, json.Unmarshal(body, &got), "decode %s", body)
	assert.Equal(t, "error", got.Status)
	return got.Message
}

func adminTestSubnet(t *testing.T, srv *httptest.Server, region string) string {
	t.Helper()
	resp, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateVpc: %s", body)
	resp, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {extractEC2Tag(body, "vpcId")}, "CidrBlock": {"10.0.1.0/24"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateSubnet: %s", body)
	return extractEC2Tag(body, "subnetId")
}

func runImage(t *testing.T, srv *httptest.Server, region, subnetID, ami string) (*http.Response, []byte) {
	t.Helper()
	return ec2Call(t, srv, region, "RunInstances", url.Values{
		"SubnetId": {subnetID}, "ImageId": {ami}, "InstanceType": {"t3.micro"},
	})
}

func doPostJSON(t *testing.T, srv *httptest.Server, path, payload string) (*http.Response, []byte) {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader(payload))
	require.NoError(t, err, "POST %s", path)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// newTestApp is newTestServer that also hands back the Application,
// for tests that read the repository directly.
func newTestApp(t *testing.T, dbPath string) (*handlers.Application, *httptest.Server) {
	t.Helper()
	return newOptionsApp(t, handlers.Options{DBPath: dbPath})
}

// newOptionsApp is newTestApp for an Application built from opts.
func newOptionsApp(t *testing.T, opts handlers.Options) (*handlers.Application, *httptest.Server) {
	t.Helper()
	app, err := handlers.NewApplication(opts)
	require.NoError(t, err, "NewApplication")
	srv := httptest.NewServer(app.Router())
	t.Cleanup(func() {
		srv.Close()
		_ = app.Close()
	})
	return app, srv
}

func newTestServer(t *testing.T, dbPath string) *httptest.Server {
	t.Helper()
	_, srv := newTestApp(t, dbPath)
	return srv
}

func doGet(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	require.NoError(t, err, "GET %s", path)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func doPost(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+path, "application/json", nil)
	require.NoError(t, err, "POST %s", path)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

const adminToken = "s3cr3t-admin-token"

// doAdmin sends method path with header and returns the status and body.
func doAdmin(t *testing.T, srv *httptest.Server, method, path string, header http.Header) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	require.NoError(t, err)
	req.Header = header
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "%s %s", method, path)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

type adminRoute struct{ method, path string }

// mockRoutes walks app's router for its /mock routes, filling the
// {service} parameter, and adds an unknown /mock path.
func mockRoutes(t *testing.T, app *handlers.Application) []adminRoute {
	t.Helper()
	var routes []adminRoute
	err := chi.Walk(app.Router().(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, "/mock/") {
			routes = append(routes, adminRoute{method, strings.ReplaceAll(route, "{service}", "iam")})
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, routes, "no /mock routes found")
	return append(routes, adminRoute{http.MethodGet, "/mock/x"})
}

func bearer(token string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}}
}

func TestContract_listen_addr_default_all_interfaces(t *testing.T) {
	assert.Equal(t, ":8082", handlers.Options{Port: 8082}.ListenAddr())
	assert.Equal(t, "[::1]:8082", handlers.Options{Bind: "::1", Port: 8082}.ListenAddr())

	ln, err := net.Listen("tcp", handlers.Options{Bind: "127.0.0.1"}.ListenAddr())
	require.NoError(t, err)
	defer ln.Close()
	assert.Equal(t, "127.0.0.1", ln.Addr().(*net.TCPAddr).IP.String())
}

func TestContract_mock_admin_token_required(t *testing.T) {
	app, guarded := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AdminToken: adminToken})
	plain := newTestServer(t, ":memory:")

	for _, rt := range mockRoutes(t, app) {
		for name, h := range map[string]http.Header{
			"no Authorization": {},
			"wrong token":      bearer("wrong"),
			"non-Bearer":       {"Authorization": {"Basic " + adminToken}},
		} {
			status, body := doAdmin(t, guarded, rt.method, rt.path, h)
			assert.Equal(t, http.StatusUnauthorized, status, "%s %s, %s: %s", rt.method, rt.path, name, body)
			assert.NotContains(t, body, adminToken, "%s %s, %s", rt.method, rt.path, name)
		}

		wantStatus, wantBody := doAdmin(t, plain, rt.method, rt.path, http.Header{})
		status, body := doAdmin(t, guarded, rt.method, rt.path, bearer(adminToken))
		assert.Equal(t, wantStatus, status, "%s %s with the token", rt.method, rt.path)
		assert.Equal(t, wantBody, body, "%s %s with the token", rt.method, rt.path)
	}

	status, _ := doAdmin(t, guarded, http.MethodGet, "/healthz", http.Header{})
	assert.Equal(t, http.StatusOK, status, "/healthz is not gated")
	resp, body := stsCall(t, guarded, "GetCallerIdentity")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "provider routes are not gated: %s", body)
}

func TestContract_mock_admin_origin_loopback_only(t *testing.T) {
	app, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AdminToken: adminToken})

	for _, origin := range []string{"https://evil.example", "null", "http://localhost.evil", "http://127.0.0.1.evil"} {
		for _, rt := range mockRoutes(t, app) {
			h := bearer(adminToken)
			h.Set("Origin", origin)
			status, body := doAdmin(t, srv, rt.method, rt.path, h)
			assert.Equal(t, http.StatusForbidden, status, "%s %s, Origin %s: %s", rt.method, rt.path, origin, body)
			assert.NotContains(t, body, adminToken)
		}
	}

	for _, origin := range []string{"", "http://127.0.0.1:4173", "http://localhost:4173", "http://[::1]:4173"} {
		h := bearer(adminToken)
		if origin != "" {
			h.Set("Origin", origin)
		}
		status, body := doAdmin(t, srv, http.MethodGet, "/mock/state", h)
		assert.Equal(t, http.StatusOK, status, "Origin %q: %s", origin, body)
	}
}

// Without an admin token /mock is as open as it always was: a
// non-loopback Origin and no Authorization change nothing.
func TestAdminMock_NoTokenIsUngated(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	evil := http.Header{"Origin": {"https://evil.example"}}

	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/mock/state", http.StatusOK},
		{"/mock/x", http.StatusNotImplemented},
	} {
		wantStatus, wantBody := doAdmin(t, srv, http.MethodGet, tc.path, http.Header{})
		status, body := doAdmin(t, srv, http.MethodGet, tc.path, evil)
		assert.Equal(t, tc.status, wantStatus, tc.path)
		assert.Equal(t, wantStatus, status, tc.path)
		assert.Equal(t, wantBody, body, tc.path)
	}
}

const (
	otherAccount = "123456789012"
	thirdAccount = "210987654321"
	refusedMsg   = "resource conflict: account " + otherAccount + " refused: the database is not empty and holds account 000000000000"
)

func accountID(t *testing.T, app *handlers.Application) string {
	t.Helper()
	id, err := app.AccountID()
	require.NoError(t, err)
	return id
}

func storedIdentity(t *testing.T, app *handlers.Application) repository.Identity {
	t.Helper()
	id, err := app.Repository().GetIdentity()
	require.NoError(t, err)
	return id
}

func TestContract_identity_change_refused_on_non_empty_db(t *testing.T) {
	setOther := `{"account_id":"` + otherAccount + `","region":"eu-west-1"}`
	for name, create := range map[string]func(*testing.T, *httptest.Server){
		"role": func(t *testing.T, srv *httptest.Server) { createRole(t, srv, "identity-role") },
		"vpc": func(t *testing.T, srv *httptest.Server) {
			resp, body := ec2Call(t, srv, "us-east-1", "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
			require.Equal(t, http.StatusOK, resp.StatusCode, "CreateVpc: %s", body)
		},
	} {
		t.Run(name, func(t *testing.T) {
			app, srv := newTestApp(t, ":memory:")
			create(t, srv)
			resp, body := doPostJSON(t, srv, "/mock/identity", setOther)
			assert.Equal(t, http.StatusConflict, resp.StatusCode, "body: %s", body)
			assert.Equal(t, refusedMsg, adminErrorMessage(t, body))
			assert.Equal(t, awsproto.FakeAccountID, accountID(t, app))
		})
	}

	app, srv := newTestApp(t, ":memory:")
	resp, body := doPostJSON(t, srv, "/mock/identity", setOther)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "empty database: %s", body)
	assert.Equal(t, otherAccount, accountID(t, app))

	dbPath := filepath.Join(t.TempDir(), "test.db")
	app, srv = newTestApp(t, dbPath)
	createRole(t, srv, "identity-role")
	require.NoError(t, app.Close())
	_, err := handlers.NewApplication(handlers.Options{DBPath: dbPath, AccountID: otherAccount})
	require.Error(t, err, "boot with another account on a non-empty file database")
	assert.Equal(t, refusedMsg, err.Error())
}

func TestContract_identity_stored_in_database(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	app, srv := newTestApp(t, dbPath)
	want := repository.Identity{AccountID: otherAccount, Region: "eu-west-1"}

	resp, body := doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`","region":"eu-west-1"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "set: %s", body)
	resp, body = doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusOK, resp.StatusCode, "snapshot: %s", body)
	resp, body = doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+thirdAccount+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "set again: %s", body)
	require.Equal(t, thirdAccount, accountID(t, app))

	resp, body = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, resp.StatusCode, "restore: %s", body)
	assert.Equal(t, otherAccount, accountID(t, app), "restore")
	assert.Equal(t, want, storedIdentity(t, app), "restore")

	require.NoError(t, app.Close())
	app, srv = newTestApp(t, dbPath)
	assert.Equal(t, want, storedIdentity(t, app), "reopened with no AccountID")

	createRole(t, srv, "identity-role")
	require.NoError(t, app.Close())
	app, srv = newOptionsApp(t, handlers.Options{DBPath: dbPath, AccountID: otherAccount})
	assert.Equal(t, want, storedIdentity(t, app), "reopened non-empty with the same account and no region")

	resp, body = doPost(t, srv, "/mock/reset")
	require.Equal(t, http.StatusOK, resp.StatusCode, "reset: %s", body)
	assert.Equal(t, awsproto.FakeAccountID, accountID(t, app), "reset")
}

func TestAdminMockIdentity_UnreadableIdentityIs500(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	_, err := app.Repository().DB().Exec(`DROP TABLE identity`)
	require.NoError(t, err)

	_, err = app.AccountID()
	assert.Error(t, err)
	resp, body := doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`"}`)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "POST /mock/identity: %s", body)
	resp, body = doPostJSON(t, srv, "/mock/images", `{"ami_id":"ami-0123456789abcdef0","name":"x","region":"us-east-1","root_device_name":"/dev/xvda"}`)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "POST /mock/images: %s", body)
	for _, path := range []string{"/mock/state", "/mock/state/iam"} {
		resp, body := doGet(t, srv, path)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "GET %s: %s", path, body)
	}
}

// A new table seeded at boot that does not join repository's
// emptyExclusions makes every fresh database read as non-empty, which
// fails this test.
func TestAdminMockIdentity_FixturesCountAsEmpty(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	resp, body := ec2Call(t, srv, "ap-south-2", "DescribeImages", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
	var n int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_amis WHERE region = 'ap-south-2'`).Scan(&n))
	require.Positive(t, n, "DescribeImages lazily seeds the fixtures into an unseeded region")

	resp, body = doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)
}

// Until EC2 reads the stored account, these rows are invisible to
// RunInstances under any account but the default.
func TestAdminMockIdentity_SeedsGoUnderStoredAccount(t *testing.T) {
	app, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AccountID: otherAccount})
	amis := func(account string) int {
		var n int
		require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_amis WHERE account_id = ?`, account).Scan(&n))
		return n
	}
	assert.Positive(t, amis(otherAccount), "boot fixtures under the stored account")
	assert.Zero(t, amis(awsproto.FakeAccountID), "boot fixtures under the default")

	before := amis(otherAccount)
	seed := `{"ami_id":"ami-0123456789abcdef0","name":"x","region":"us-east-1","root_device_name":"/dev/xvda"`
	resp, body := doPostJSON(t, srv, "/mock/images", seed+`,"account_id":"000000000000"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", body)
	assert.Equal(t, "account_id must be "+otherAccount, adminErrorMessage(t, body))
	resp, body = doPostJSON(t, srv, "/mock/images", seed+`}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)
	assert.Equal(t, before+1, amis(otherAccount), "seeded image under the stored account")

	resp, body = doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+thirdAccount+`"}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "a seeded image is not empty: %s", body)
}

func TestAdminMockIdentity_InvalidBodyWritesNothing(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	for name, tc := range map[string]struct{ body, wantMessage string }{
		"two digits":       {`{"account_id":"12"}`, "account_id must be 12 digits"},
		"thirteen digits":  {`{"account_id":"1234567890123"}`, "account_id must be 12 digits"},
		"not digits":       {`{"account_id":"12345678901a"}`, "account_id must be 12 digits"},
		"no account":       {`{"region":"eu-west-1"}`, "account_id must be 12 digits"},
		"malformed region": {`{"account_id":"` + otherAccount + `","region":"eu-west"}`, "region must look like us-east-1"},
		"unknown field":    {`{"account_id":"` + otherAccount + `","acount":"x"}`, `invalid body: json: unknown field "acount"`},
		"trailing data":    {`{"account_id":"` + otherAccount + `"} junk`, "invalid body: one JSON object expected"},
		"two objects":      {`{"account_id":"` + otherAccount + `"}{}`, "invalid body: one JSON object expected"},
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := doPostJSON(t, srv, "/mock/identity", tc.body)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", body)
			assert.Equal(t, tc.wantMessage, adminErrorMessage(t, body))
			_, err := app.Repository().GetIdentity()
			assert.ErrorIs(t, err, sql.ErrNoRows, "rejected request stored an identity")
		})
	}

	_, guarded := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AdminToken: adminToken})
	resp, body := doPostJSON(t, guarded, "/mock/identity", `{"account_id":"`+otherAccount+`"}`)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "no bearer: %s", body)
}
