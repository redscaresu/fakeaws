// Package testutil is the test-side helper layer.
//
// fakegcp's testutil exposes a single JSON-shaped Do* surface because
// every fakegcp endpoint speaks JSON. fakeaws speaks five distinct wire
// shapes (XML, Query-RPC, JSON 1.0 with x-amz-target, JSON 1.1 with
// x-amz-target, JSON-REST), so this package exposes a low-level DoRaw
// helper plus per-protocol convenience wrappers (DoQueryRPC, DoXAmzTarget,
// DoXMLREST, DoJSONREST). See concepts.md § "testutil API contract".
//
// The full per-protocol surface lands progressively as services arrive:
//   - S43-T1 ships DoRaw + NewTestServer (this file).
//   - S43-T6 (IAM) requires DoQueryRPC.
//   - S43-T8 (S3) requires DoXMLREST + S3Path.
//   - S45-T5 (DynamoDB) requires DoXAmzTarget.
//   - S46-T3 (EKS) requires DoJSONREST.
//
// Path/endpoint builders live next to their helpers when each service ships.
package testutil

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redscaresu/fakeaws/handlers"
)

// NewTestServer boots an in-memory fakeaws on a random local port and
// returns the httptest.Server plus a cleanup func. t.Cleanup is also
// wired so callers don't have to remember to defer cleanup() — both
// patterns work, mirroring fakegcp/testutil.
func NewTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	app, err := handlers.NewApplication(":memory:", false)
	if err != nil {
		t.Fatalf("testutil: NewTestServer: %v", err)
	}
	srv := httptest.NewServer(app.Router())
	cleanup := func() {
		srv.Close()
		_ = app.Close()
	}
	t.Cleanup(cleanup)
	return srv, cleanup
}

// DoRaw is the foundation every per-protocol wrapper builds on. It
// fires the request and returns the response plus the body bytes —
// callers parse per-protocol (encoding/xml, encoding/json, etc.).
//
// Per concepts.md § "testutil API contract": tests pass *http.Request
// because each protocol wants different headers; the helpers above
// (DoQueryRPC, DoXMLREST, ...) construct the right Request shape.
func DoRaw(t *testing.T, srv *httptest.Server, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	if req.URL.Scheme == "" {
		// Caller passed a path-only URL; rewrite against the test server.
		u := srv.URL + req.URL.String()
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, u, req.Body)
		if err != nil {
			t.Fatalf("testutil.DoRaw: rewrite URL: %v", err)
		}
		for k, vs := range req.Header {
			newReq.Header[k] = vs
		}
		req = newReq
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("testutil.DoRaw: %s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testutil.DoRaw: read body: %v", err)
	}
	return resp, body
}
