package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func smCall(t *testing.T, srv *httptest.Server, op, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/secretsmanager/region/us-east-1",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager."+op)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /secretsmanager %s: %v", op, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func TestSecretsManager_CreateGetSecret(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := smCall(t, srv, "CreateSecret", `{
		"Name": "db-creds",
		"Description": "test secret",
		"SecretString": "supersecret"
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateSecret: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"Name":"db-creds"`) {
		t.Errorf("CreateSecret body: %s", body)
	}

	// GetSecretValue.
	resp, body = smCall(t, srv, "GetSecretValue", `{"SecretId":"db-creds"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetSecretValue: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"SecretString":"supersecret"`) {
		t.Errorf("GetSecretValue: %s", body)
	}
}

func TestSecretsManager_TerminalStateRefusesRestore(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	smCall(t, srv, "CreateSecret", `{"Name":"x","SecretString":"s"}`)

	// Force-delete (window=0) → Destroyed.
	resp, _ := smCall(t, srv, "DeleteSecret", `{"SecretId":"x","ForceDeleteWithoutRecovery":true}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteSecret force: %d", resp.StatusCode)
	}

	// RestoreSecret on Destroyed → 409 InvalidRequestException
	// (concepts.md "Standing patterns" item 9 — terminal-state).
	resp, body := smCall(t, srv, "RestoreSecret", `{"SecretId":"x"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("RestoreSecret on Destroyed: got %d, want 409; body=%s", resp.StatusCode, body)
	}
}

func TestContract_secretsmanager_soft_delete_state_pending_deletion(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	smCall(t, srv, "CreateSecret", `{"Name":"x","SecretString":"s"}`)

	// Schedule with 30-day window → PendingDeletion.
	resp, _ := smCall(t, srv, "DeleteSecret", `{"SecretId":"x","RecoveryWindowInDays":30}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteSecret")

	// Restore.
	resp, _ = smCall(t, srv, "RestoreSecret", `{"SecretId":"x"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "RestoreSecret on PendingDeletion")

	// Re-Get works after restore.
	resp, body := smCall(t, srv, "GetSecretValue", `{"SecretId":"x"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetSecretValue after restore: %s", body)
	assert.Contains(t, string(body), `"s"`, "GetSecretValue body should contain restored secret")
}

// TestSecretsManager_DestroyedNotFoundContract pins the Codex pass 2
// BLOCKING #2 fix: a force-deleted (Destroyed) secret must behave as
// not-found across all read paths, not just RestoreSecret.
func TestSecretsManager_DestroyedNotFoundContract(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	smCall(t, srv, "CreateSecret", `{"Name":"d","SecretString":"s"}`)
	smCall(t, srv, "DeleteSecret", `{"SecretId":"d","ForceDeleteWithoutRecovery":true}`)

	// DescribeSecret on Destroyed → 404.
	resp, _ := smCall(t, srv, "DescribeSecret", `{"SecretId":"d"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DescribeSecret on Destroyed: got %d, want 404", resp.StatusCode)
	}

	// GetSecretValue on Destroyed → 404.
	resp, _ = smCall(t, srv, "GetSecretValue", `{"SecretId":"d"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetSecretValue on Destroyed: got %d, want 404", resp.StatusCode)
	}

	// ListSecrets does NOT include the destroyed secret.
	_, body := smCall(t, srv, "ListSecrets", `{}`)
	if strings.Contains(string(body), `"d"`) {
		t.Errorf("ListSecrets must skip Destroyed secrets; body=%s", body)
	}
}

// TestSecretsManager_MockStateFiltersDeleted pins S89's fix for the
// aws-full-stack LLMSoftDelete orphan_check failure. terraform-
// provider-aws's default DeleteSecret call sets a 30-day recovery
// window, which leaves the row in PendingDeletion. The orphan_check
// reads /mock/state.secretsmanager.secrets and treated any non-empty
// entry as a leftover, so the scenario stalled even though the
// secret IS gone from the user's perspective (DescribeSecret returns
// 404 on Destroyed; PendingDeletion is post-delete).
//
// Filter: PendingDeletion + Destroyed are excluded from
// gatherSecretsManagerStateReal. Active stays.
func TestSecretsManager_MockStateFiltersDeleted(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// Active secret should appear in /mock/state.
	smCall(t, srv, "CreateSecret", `{"Name":"keep","SecretString":"s"}`)
	resp, err := http.Get(srv.URL + "/mock/state")
	if err != nil {
		t.Fatalf("GET /mock/state: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), `"name":"keep"`) {
		t.Errorf("expected Active secret in /mock/state, got: %s", body)
	}

	// PendingDeletion (default 30-day recovery window) must NOT appear.
	smCall(t, srv, "CreateSecret", `{"Name":"pending","SecretString":"s"}`)
	smCall(t, srv, "DeleteSecret", `{"SecretId":"pending","RecoveryWindowInDays":30}`)
	resp, err = http.Get(srv.URL + "/mock/state")
	if err != nil {
		t.Fatalf("GET /mock/state: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), `"name":"pending"`) {
		t.Errorf("expected PendingDeletion secret filtered from /mock/state, got: %s", body)
	}

	// Destroyed (ForceDeleteWithoutRecovery) must NOT appear either.
	smCall(t, srv, "CreateSecret", `{"Name":"destroyed","SecretString":"s"}`)
	smCall(t, srv, "DeleteSecret", `{"SecretId":"destroyed","ForceDeleteWithoutRecovery":true}`)
	resp, err = http.Get(srv.URL + "/mock/state")
	if err != nil {
		t.Fatalf("GET /mock/state: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), `"name":"destroyed"`) {
		t.Errorf("expected Destroyed secret filtered from /mock/state, got: %s", body)
	}

	// Active "keep" should still be there after the other operations.
	if !strings.Contains(string(body), `"name":"keep"`) {
		t.Errorf("expected Active secret to survive, got: %s", body)
	}
}

func TestSecretsManager_VersionStages(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	smCall(t, srv, "CreateSecret", `{"Name":"x","SecretString":"v1"}`)
	smCall(t, srv, "PutSecretValue", `{"SecretId":"x","SecretString":"v2"}`)

	// Default (AWSCURRENT) is v2.
	_, body := smCall(t, srv, "GetSecretValue", `{"SecretId":"x"}`)
	if !strings.Contains(string(body), `"v2"`) {
		t.Errorf("AWSCURRENT: %s", body)
	}

	// AWSPREVIOUS is v1.
	_, body = smCall(t, srv, "GetSecretValue", `{"SecretId":"x","VersionStage":"AWSPREVIOUS"}`)
	if !strings.Contains(string(body), `"v1"`) {
		t.Errorf("AWSPREVIOUS: %s", body)
	}
}
