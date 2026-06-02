package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func kmsCall(t *testing.T, srv *httptest.Server, region, op string, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/kms/region/"+region, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+op)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /kms %s: %v", op, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// TestKMS_KeyRotationPersistence pins the fix for the
// mock-gaps.md aws_kms_key rotation timeout. Before this fix,
// GetKeyRotationStatus always returned {KeyRotationEnabled: false}.
// EnableKeyRotation succeeded but didn't persist. The
// terraform-provider-aws Update wait-loop polled GetKeyRotationStatus
// for 10m waiting for the value to flip to true, then timed out.
//
// With the fix: CreateKey → EnableKeyRotation → GetKeyRotationStatus
// returns true.
func TestKMS_KeyRotationPersistence(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Create a key.
	resp, body := kmsCall(t, srv, region, "CreateKey", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateKey: %d %s", resp.StatusCode, body)
	}
	var created struct {
		KeyMetadata struct {
			KeyId string
		}
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode CreateKey: %v\nbody=%s", err, body)
	}
	if created.KeyMetadata.KeyId == "" {
		t.Fatalf("empty KeyId in CreateKey response: %s", body)
	}
	keyID := created.KeyMetadata.KeyId

	// Pre-Enable: rotation should be false (default).
	resp, body = kmsCall(t, srv, region, "GetKeyRotationStatus", `{"KeyId":"`+keyID+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-Enable GetKeyRotationStatus: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"KeyRotationEnabled":false`) {
		t.Errorf("pre-Enable expected false, got: %s", body)
	}

	// Enable rotation.
	resp, body = kmsCall(t, srv, region, "EnableKeyRotation", `{"KeyId":"`+keyID+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("EnableKeyRotation: %d %s", resp.StatusCode, body)
	}

	// Post-Enable: rotation should be true.
	resp, body = kmsCall(t, srv, region, "GetKeyRotationStatus", `{"KeyId":"`+keyID+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-Enable GetKeyRotationStatus: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"KeyRotationEnabled":true`) {
		t.Errorf("post-Enable expected true, got: %s", body)
	}

	// Disable rotation.
	resp, body = kmsCall(t, srv, region, "DisableKeyRotation", `{"KeyId":"`+keyID+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DisableKeyRotation: %d %s", resp.StatusCode, body)
	}

	// Post-Disable: rotation should be false again.
	resp, body = kmsCall(t, srv, region, "GetKeyRotationStatus", `{"KeyId":"`+keyID+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-Disable GetKeyRotationStatus: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"KeyRotationEnabled":false`) {
		t.Errorf("post-Disable expected false, got: %s", body)
	}
}

// TestKMS_KeyRotation_UnknownKeyReturns404 guards the not-found
// path. Real KMS returns NotFoundException for unknown key ids; our
// rotation handlers must do the same.
func TestKMS_KeyRotation_UnknownKeyReturns404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	resp, _ := kmsCall(t, srv, region, "GetKeyRotationStatus", `{"KeyId":"nonexistent-key-id"}`)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("GetKeyRotationStatus on missing key should not return 200, got %d", resp.StatusCode)
	}

	resp, _ = kmsCall(t, srv, region, "EnableKeyRotation", `{"KeyId":"nonexistent-key-id"}`)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("EnableKeyRotation on missing key should not return 200, got %d", resp.StatusCode)
	}
}
