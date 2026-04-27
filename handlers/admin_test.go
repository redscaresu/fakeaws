package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redscaresu/fakeaws/handlers"
)

// TestAdminMockState_ReturnsDocumentedShape pins the /mock/state
// contract topology_derive_aws will key off. The shape is documented
// inline in admin.go § stateSchemaVersion; this test asserts the keys
// the audit will look for.
func TestAdminMockState_ReturnsDocumentedShape(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/state")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	var state map[string]any
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, want := range []string{"schema_version", "operations", "audit", "iam", "s3"} {
		if _, ok := state[want]; !ok {
			t.Errorf("missing key %q in /mock/state response: %s", want, body)
		}
	}
	if v, _ := state["schema_version"].(float64); v != 1 {
		t.Errorf("schema_version: got %v want 1", state["schema_version"])
	}
}

func TestAdminMockState_PerServiceFiltersToBlock(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/state/iam")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	var state map[string]any
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := state["iam"]; !ok {
		t.Errorf("expected iam block in per-service response: %s", body)
	}
	if _, ok := state["s3"]; ok {
		t.Errorf("per-service /state/iam should NOT include s3 block: %s", body)
	}
}

func TestAdminMockState_UnknownServiceReturnsEmptyBlock(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/state/notreal")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"notreal":{}`) {
		t.Errorf("expected empty block for unknown service: %s", body)
	}
}

func TestAdminMockReset_OK(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doPost(t, srv, "/mock/reset")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d body %s", resp.StatusCode, body)
	}
}

func TestAdminMockSnapshot_MemoryConflict(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := doPost(t, srv, "/mock/snapshot")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status: got %d want 409 (snapshot meaningless on :memory:); body: %s", resp.StatusCode, body)
	}
}

func TestAdminMockRestore_NoBaselineIs404(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	srv := newTestServer(t, dbPath)

	resp, body := doPost(t, srv, "/mock/restore")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (no snapshot baseline); body: %s", resp.StatusCode, body)
	}
}

func TestAdminMockSnapshotRestore_FileBackedRoundTrips(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	srv := newTestServer(t, dbPath)

	// Snapshot the empty state.
	if r, b := doPost(t, srv, "/mock/snapshot"); r.StatusCode != http.StatusOK {
		t.Fatalf("snapshot: got %d body %s", r.StatusCode, b)
	}

	// Restore — the snapshot file exists, so this should 200.
	if r, b := doPost(t, srv, "/mock/restore"); r.StatusCode != http.StatusOK {
		t.Fatalf("restore: got %d body %s", r.StatusCode, b)
	}
}

// ----- helpers -----

func newTestServer(t *testing.T, dbPath string) *httptest.Server {
	t.Helper()
	app, err := handlers.NewApplication(dbPath, false)
	if err != nil {
		t.Fatalf("NewApplication: %v", err)
	}
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
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func doPost(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+path, "application/json", nil)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}
