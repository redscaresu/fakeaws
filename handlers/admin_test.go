package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// ----- helpers -----

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
