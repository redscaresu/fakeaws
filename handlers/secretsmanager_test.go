package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestSecretsManager_PendingDeletionRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	smCall(t, srv, "CreateSecret", `{"Name":"x","SecretString":"s"}`)

	// Schedule with 30-day window → PendingDeletion.
	resp, _ := smCall(t, srv, "DeleteSecret", `{"SecretId":"x","RecoveryWindowInDays":30}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteSecret: %d", resp.StatusCode)
	}

	// Restore.
	resp, _ = smCall(t, srv, "RestoreSecret", `{"SecretId":"x"}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("RestoreSecret on PendingDeletion: %d", resp.StatusCode)
	}

	// Re-Get works after restore.
	resp, body := smCall(t, srv, "GetSecretValue", `{"SecretId":"x"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"s"`) {
		t.Errorf("GetSecretValue after restore: %d %s", resp.StatusCode, body)
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
