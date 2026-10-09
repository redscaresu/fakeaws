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
	srv := newTestServer(t, ":memory:")
	const ami = "ami-0123456789abcdef0"

	seed := `{"ami_id":"` + ami + `","name":"al2023-ami-real","region":"us-east-1","root_device_name":"/dev/sdz"}`
	resp, body := doPostJSON(t, srv, "/mock/images", seed)
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed: %s", body)

	for name, tc := range map[string]struct{ body, wantMessage, region, ami, wantRootDevice string }{
		"differing re-seed": {
			body:        `{"ami_id":"` + ami + `","region":"us-east-1","root_device_name":"/dev/xvda"}`,
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
			resp, body := doPostJSON(t, srv, "/mock/images", tc.body)
			assert.Equal(t, http.StatusConflict, resp.StatusCode, "body: %s", body)
			assert.Equal(t, tc.wantMessage, adminErrorMessage(t, body))

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

	for name, tc := range map[string]struct{ ami, body, wantMessage string }{
		"malformed id": {"ami-NOTHEX", `{"ami_id":"ami-NOTHEX","region":"us-east-1","root_device_name":"/dev/xvda"}`,
			"ami_id must be ami- followed by 8 or 17 lowercase hex digits"},
		"id of another length": {"ami-0123456789", `{"ami_id":"ami-0123456789","region":"us-east-1","root_device_name":"/dev/xvda"}`,
			"ami_id must be ami- followed by 8 or 17 lowercase hex digits"},
		"no region": {"ami-0aaaaaaaaaaaaaaa1", `{"ami_id":"ami-0aaaaaaaaaaaaaaa1","root_device_name":"/dev/xvda"}`,
			"region must look like us-east-1"},
		"upper-case region": {"ami-0aaaaaaaaaaaaaaa6", `{"ami_id":"ami-0aaaaaaaaaaaaaaa6","region":"US-East-1","root_device_name":"/dev/xvda"}`,
			"region must look like us-east-1"},
		"region with trailing space": {"ami-0aaaaaaaaaaaaaaa7", `{"ami_id":"ami-0aaaaaaaaaaaaaaa7","region":"us-east-1 ","root_device_name":"/dev/xvda"}`,
			"region must look like us-east-1"},
		"no root device name": {"ami-0aaaaaaaaaaaaaaa2", `{"ami_id":"ami-0aaaaaaaaaaaaaaa2","region":"us-east-1"}`,
			"root_device_name is required"},
		"other account": {"ami-0aaaaaaaaaaaaaaa5", `{"ami_id":"ami-0aaaaaaaaaaaaaaa5","region":"us-east-1","root_device_name":"/dev/xvda","account_id":"111122223333"}`,
			"account_id must be 000000000000"},
		"trailing data": {"ami-0aaaaaaaaaaaaaaa4", `{"ami_id":"ami-0aaaaaaaaaaaaaaa4","region":"us-east-1","root_device_name":"/dev/xvda"} junk`,
			"invalid body: one JSON object expected"},
		"unknown field (typo)": {"ami-0aaaaaaaaaaaaaaa3", `{"ami_id":"ami-0aaaaaaaaaaaaaaa3","region":"us-east-1","root_device":"/dev/xvda"}`,
			`invalid body: json: unknown field "root_device"`},
		"oversized body": {"ami-0aaaaaaaaaaaaaaa8", `{"ami_id":"ami-0aaaaaaaaaaaaaaa8","region":"us-east-1","root_device_name":"/dev/xvda","name":"` + bigName + `"}`,
			"invalid body: http: request body too large"},
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := doPostJSON(t, srv, "/mock/images", tc.body)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", body)
			assert.Equal(t, tc.wantMessage, adminErrorMessage(t, body))

			var n int
			require.NoError(t, app.Repository().DB().QueryRow(
				`SELECT COUNT(*) FROM ec2_amis WHERE id = ?`, tc.ami).Scan(&n))
			assert.Zero(t, n, "rejected image written in some region or account")
		})
	}
}

// ----- helpers -----

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
	app, err := handlers.NewApplication(dbPath, false)
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
