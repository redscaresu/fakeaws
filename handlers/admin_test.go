package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redscaresu/fakeaws/handlers"
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

func TestAdminMockImages_SeededImageLaunches(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	const ami = "ami-0123456789abcdef0"

	resp, body := doPostJSON(t, srv, "/mock/images", `{"ami_id":"`+ami+`","name":"al2023-ami-real","region":"us-east-1","root_device_name":"/dev/sdz","account_id":"000000000000"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed: %s", body)
	resp, body = doPostJSON(t, srv, "/mock/images", `{"ami_id":"`+ami+`","region":"us-east-1","root_device_name":"/dev/xvda"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "re-seed is idempotent: %s", body)

	resp, body = ec2Call(t, srv, region, "DescribeImages", url.Values{"ImageId.1": {ami}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
	assert.Contains(t, string(body), ami)
	assert.Contains(t, string(body), "<rootDeviceName>/dev/sdz</rootDeviceName>", "first seed wins: %s", body)
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

func TestAdminMockImages_InvalidBodyWritesNothing(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	for name, tc := range map[string]struct{ ami, body string }{
		"malformed id":         {"ami-NOTHEX", `{"ami_id":"ami-NOTHEX","region":"us-east-1","root_device_name":"/dev/xvda"}`},
		"no region":            {"ami-0aaaaaaaaaaaaaaa1", `{"ami_id":"ami-0aaaaaaaaaaaaaaa1","root_device_name":"/dev/xvda"}`},
		"no root device name":  {"ami-0aaaaaaaaaaaaaaa2", `{"ami_id":"ami-0aaaaaaaaaaaaaaa2","region":"us-east-1"}`},
		"other account":        {"ami-0aaaaaaaaaaaaaaa5", `{"ami_id":"ami-0aaaaaaaaaaaaaaa5","region":"us-east-1","root_device_name":"/dev/xvda","account_id":"111122223333"}`},
		"trailing data":        {"ami-0aaaaaaaaaaaaaaa4", `{"ami_id":"ami-0aaaaaaaaaaaaaaa4","region":"us-east-1","root_device_name":"/dev/xvda"} junk`},
		"unknown field (typo)": {"ami-0aaaaaaaaaaaaaaa3", `{"ami_id":"ami-0aaaaaaaaaaaaaaa3","region":"us-east-1","root_device":"/dev/xvda"}`},
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := doPostJSON(t, srv, "/mock/images", tc.body)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", body)

			resp, body = ec2Call(t, srv, "us-east-1", "DescribeImages", nil)
			require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
			assert.NotContains(t, string(body), tc.ami, "rejected image was written")
		})
	}
}

// ----- helpers -----

func adminTestSubnet(t *testing.T, srv *httptest.Server, region string) string {
	t.Helper()
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {extractEC2Tag(body, "vpcId")}, "CidrBlock": {"10.0.1.0/24"},
	})
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

func newTestServer(t *testing.T, dbPath string) *httptest.Server {
	t.Helper()
	app, err := handlers.NewApplication(dbPath, false)
	require.NoError(t, err, "NewApplication")
	srv := httptest.NewServer(app.Router())
	t.Cleanup(func() {
		srv.Close()
		_ = app.Close()
	})
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
