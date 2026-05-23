package handlers_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/redscaresu/fakeaws/handlers"
)

// TestFaults_DefaultZeroBeforePostingConfig pins the fault-free
// default — pre-S49 fakeaws callers see no behavior change unless
// they explicitly POST /mock/faults.
func TestFaults_DefaultZeroBeforePostingConfig(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/faults/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", resp.StatusCode, body)
	}
	var cfg handlers.FaultConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if cfg.IAMAttachLatencyMS != 0 {
		t.Fatalf("expected zero default latency, got %d", cfg.IAMAttachLatencyMS)
	}
}

// TestFaults_RoundTripPersistsConfig: POST then GET surfaces the
// previously-set value, proving the package-level state holds across
// requests on the same Application.
func TestFaults_RoundTripPersistsConfig(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	postFaults(t, srv, handlers.FaultConfig{IAMAttachLatencyMS: 250})

	resp, body := doGet(t, srv, "/mock/faults/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", resp.StatusCode, body)
	}
	var cfg handlers.FaultConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if cfg.IAMAttachLatencyMS != 250 {
		t.Fatalf("expected 250 after roundtrip, got %d", cfg.IAMAttachLatencyMS)
	}
}

// TestFaults_NegativeLatencyRejected guards against silently inverting
// a sleep into a poll-loop or otherwise weird behavior — explicit 400.
func TestFaults_NegativeLatencyRejected(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	body, _ := json.Marshal(handlers.FaultConfig{IAMAttachLatencyMS: -1})
	resp, _ := srv.Client().Post(srv.URL+"/mock/faults/", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on negative latency, got %d", resp.StatusCode)
	}
}

// TestFaults_ResetClearsConfig: a test that pokes latency to a high
// value must not leak that value into the next test in a shared
// server, so /mock/reset must drop the fault config alongside table
// state.
func TestFaults_ResetClearsConfig(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	postFaults(t, srv, handlers.FaultConfig{IAMAttachLatencyMS: 1000})
	doPost(t, srv, "/mock/reset")

	_, body := doGet(t, srv, "/mock/faults/")
	var cfg handlers.FaultConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if cfg.IAMAttachLatencyMS != 0 {
		t.Fatalf("expected reset to zero latency, got %d", cfg.IAMAttachLatencyMS)
	}
}

// TestFaults_IAMAttachLatencyAppliesToHandler pins the load-bearing
// behavior: when iam_attach_latency_ms is set, AttachRolePolicy takes
// at least that long to respond. Uses a small but reliable knob
// (50ms) so the test is fast but immune to scheduler noise.
func TestFaults_IAMAttachLatencyAppliesToHandler(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	createIAMRoleAndPolicyForFaultTest(t, srv)

	const latencyMS = 50
	postFaults(t, srv, handlers.FaultConfig{IAMAttachLatencyMS: latencyMS})

	attachForm := strings.NewReader(
		"Action=AttachRolePolicy&Version=2010-05-08" +
			"&RoleName=fault-test-role" +
			"&PolicyArn=arn:aws:iam::000000000000:policy/fault-test-policy",
	)
	start := time.Now()
	resp, err := srv.Client().Post(srv.URL+"/iam", "application/x-www-form-urlencoded", attachForm)
	if err != nil {
		t.Fatalf("attach POST: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	elapsed := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attach status: got %d want 200", resp.StatusCode)
	}
	if elapsed < latencyMS*time.Millisecond {
		t.Fatalf("expected at least %dms latency, got %s", latencyMS, elapsed)
	}
}

// postFaults is a small helper that posts a FaultConfig and fails the
// test on a non-200 response.
func postFaults(t *testing.T, srv *httptest.Server, cfg handlers.FaultConfig) {
	t.Helper()
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal fault config: %v", err)
	}
	resp, err := srv.Client().Post(srv.URL+"/mock/faults/", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /mock/faults: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /mock/faults: got %d want 200, body=%s", resp.StatusCode, raw)
	}
}

// createIAMRoleAndPolicyForFaultTest seeds a role + policy so the
// AttachRolePolicy call in TestFaults_IAMAttachLatencyAppliesToHandler
// actually succeeds (the FK enforcement layer rejects attach against
// nonexistent parents). Names are unique to this test so it doesn't
// collide with iam_test.go fixtures.
func createIAMRoleAndPolicyForFaultTest(t *testing.T, srv *httptest.Server) {
	t.Helper()
	roleForm := strings.NewReader(
		"Action=CreateRole&Version=2010-05-08" +
			"&RoleName=fault-test-role" +
			"&AssumeRolePolicyDocument=" + `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D`,
	)
	resp, err := srv.Client().Post(srv.URL+"/iam", "application/x-www-form-urlencoded", roleForm)
	if err != nil {
		t.Fatalf("create role POST: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create role: got %d", resp.StatusCode)
	}

	policyForm := strings.NewReader(
		"Action=CreatePolicy&Version=2010-05-08" +
			"&PolicyName=fault-test-policy" +
			"&PolicyDocument=" + `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D`,
	)
	resp, err = srv.Client().Post(srv.URL+"/iam", "application/x-www-form-urlencoded", policyForm)
	if err != nil {
		t.Fatalf("create policy POST: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create policy: got %d", resp.StatusCode)
	}
}
