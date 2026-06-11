package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func kmsCall(t *testing.T, srv *httptest.Server, region, op string, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/kms/region/"+region, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+op)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "POST /kms %s", op)
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
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateKey: %s", body)
	var created struct {
		KeyMetadata struct {
			KeyId string
		}
	}
	require.NoError(t, json.Unmarshal(body, &created), "decode CreateKey: body=%s", body)
	require.NotEmpty(t, created.KeyMetadata.KeyId, "empty KeyId in CreateKey response: %s", body)
	keyID := created.KeyMetadata.KeyId

	// Pre-Enable: rotation should be false (default).
	resp, body = kmsCall(t, srv, region, "GetKeyRotationStatus", `{"KeyId":"`+keyID+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "pre-Enable GetKeyRotationStatus: %s", body)
	assert.Contains(t, string(body), `"KeyRotationEnabled":false`, "pre-Enable expected false, got: %s", body)

	// Enable rotation.
	resp, body = kmsCall(t, srv, region, "EnableKeyRotation", `{"KeyId":"`+keyID+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "EnableKeyRotation: %s", body)

	// Post-Enable: rotation should be true.
	resp, body = kmsCall(t, srv, region, "GetKeyRotationStatus", `{"KeyId":"`+keyID+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "post-Enable GetKeyRotationStatus: %s", body)
	assert.Contains(t, string(body), `"KeyRotationEnabled":true`, "post-Enable expected true, got: %s", body)

	// Disable rotation.
	resp, body = kmsCall(t, srv, region, "DisableKeyRotation", `{"KeyId":"`+keyID+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DisableKeyRotation: %s", body)

	// Post-Disable: rotation should be false again.
	resp, body = kmsCall(t, srv, region, "GetKeyRotationStatus", `{"KeyId":"`+keyID+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "post-Disable GetKeyRotationStatus: %s", body)
	assert.Contains(t, string(body), `"KeyRotationEnabled":false`, "post-Disable expected false, got: %s", body)
}

// TestKMS_KeyRotation_UnknownKeyReturns404 guards the not-found
// path. Real KMS returns NotFoundException for unknown key ids; our
// rotation handlers must do the same.
func TestKMS_KeyRotation_UnknownKeyReturns404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	resp, _ := kmsCall(t, srv, region, "GetKeyRotationStatus", `{"KeyId":"nonexistent-key-id"}`)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "GetKeyRotationStatus on missing key should not return 200, got %d", resp.StatusCode)

	resp, _ = kmsCall(t, srv, region, "EnableKeyRotation", `{"KeyId":"nonexistent-key-id"}`)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "EnableKeyRotation on missing key should not return 200, got %d", resp.StatusCode)
}

// TestKMS_TagPersistence pins S79's fix for the aws_kms_key tags
// update timeout. Before this fix, ListResourceTags always returned
// {Tags: []} and TagResource / UntagResource were no-ops. The
// terraform-provider-aws Update wait-loop polled ListResourceTags
// waiting for the tag set to converge to the configured value, then
// timed out.
//
// With the fix: CreateKey-with-tags → ListResourceTags returns
// initial set → TagResource adds → UntagResource removes → all
// changes visible in subsequent List calls.
func TestKMS_TagPersistence(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Create a key with initial tags.
	resp, body := kmsCall(t, srv, region, "CreateKey",
		`{"Tags":[{"TagKey":"env","TagValue":"prod"},{"TagKey":"team","TagValue":"platform"}]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateKey: %s", body)
	var created struct {
		KeyMetadata struct {
			KeyId string
		}
	}
	require.NoError(t, json.Unmarshal(body, &created), "decode CreateKey: body=%s", body)
	keyID := created.KeyMetadata.KeyId

	// ListResourceTags should return both initial tags.
	resp, body = kmsCall(t, srv, region, "ListResourceTags", `{"KeyId":"`+keyID+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "ListResourceTags: %s", body)
	assert.Contains(t, string(body), `"TagKey":"env"`, "expected env=prod tag in initial list, got: %s", body)
	assert.Contains(t, string(body), `"TagValue":"prod"`, "expected env=prod tag in initial list, got: %s", body)
	assert.Contains(t, string(body), `"TagKey":"team"`, "expected team=platform tag in initial list, got: %s", body)
	assert.Contains(t, string(body), `"TagValue":"platform"`, "expected team=platform tag in initial list, got: %s", body)

	// Add a third tag + overwrite env.
	resp, body = kmsCall(t, srv, region, "TagResource",
		`{"KeyId":"`+keyID+`","Tags":[{"TagKey":"env","TagValue":"staging"},{"TagKey":"owner","TagValue":"sre"}]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "TagResource: %s", body)

	resp, body = kmsCall(t, srv, region, "ListResourceTags", `{"KeyId":"`+keyID+`"}`)
	assert.Contains(t, string(body), `"TagValue":"staging"`, "expected env=staging after TagResource overwrite, got: %s", body)
	assert.Contains(t, string(body), `"TagKey":"owner"`, "expected owner tag after TagResource add, got: %s", body)
	assert.NotContains(t, string(body), `"TagValue":"prod"`, "expected old env=prod gone after overwrite, got: %s", body)

	// Remove env and owner; keep team.
	resp, body = kmsCall(t, srv, region, "UntagResource",
		`{"KeyId":"`+keyID+`","TagKeys":["env","owner"]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "UntagResource: %s", body)

	resp, body = kmsCall(t, srv, region, "ListResourceTags", `{"KeyId":"`+keyID+`"}`)
	assert.NotContains(t, string(body), `"TagKey":"env"`, "expected env removed after UntagResource, got: %s", body)
	assert.NotContains(t, string(body), `"TagKey":"owner"`, "expected owner removed after UntagResource, got: %s", body)
	assert.Contains(t, string(body), `"TagKey":"team"`, "expected team tag to survive UntagResource, got: %s", body)

	// UntagResource on an unknown key — real AWS silently ignores; we mirror.
	resp, body = kmsCall(t, srv, region, "UntagResource",
		`{"KeyId":"`+keyID+`","TagKeys":["does-not-exist"]}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "UntagResource of unknown key should silently 200, got %d %s", resp.StatusCode, body)
}

// TestKMS_Tag_UnknownKeyReturns404 guards the not-found path for
// the three tag handlers.
func TestKMS_Tag_UnknownKeyReturns404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	resp, _ := kmsCall(t, srv, region, "ListResourceTags", `{"KeyId":"nonexistent"}`)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "ListResourceTags on missing key should not return 200, got %d", resp.StatusCode)

	resp, _ = kmsCall(t, srv, region, "TagResource",
		`{"KeyId":"nonexistent","Tags":[{"TagKey":"a","TagValue":"b"}]}`)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "TagResource on missing key should not return 200, got %d", resp.StatusCode)

	resp, _ = kmsCall(t, srv, region, "UntagResource",
		`{"KeyId":"nonexistent","TagKeys":["a"]}`)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode, "UntagResource on missing key should not return 200, got %d", resp.StatusCode)
}

// TestKMS_ScheduleDeletion_SoftDelete pins the fix for the
// aws-secrets-manager destroy timeout surfaced by infrafactory S105.
// Before this fix, ScheduleKeyDeletion hard-deleted the key from the
// in-process store; the subsequent DescribeKey poll returned 404
// NotFoundException, and terraform-provider-aws's destroy wait-loop
// errored out.
//
// With the fix: ScheduleKeyDeletion sets KeyState=PendingDeletion,
// and DescribeKey returns 200 with that state — matching real AWS,
// where keys remain visible for 7-30 days post-schedule.
func TestContract_kms_soft_delete_state_pending_deletion(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Create a key.
	resp, body := kmsCall(t, srv, region, "CreateKey", `{}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateKey: %s", body)
	var created struct {
		KeyMetadata struct {
			KeyId string
		}
	}
	require.NoError(t, json.Unmarshal(body, &created), "decode CreateKey: %s", body)
	keyID := created.KeyMetadata.KeyId

	// Schedule deletion.
	resp, body = kmsCall(t, srv, region, "ScheduleKeyDeletion",
		`{"KeyId":"`+keyID+`","PendingWindowInDays":7}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "ScheduleKeyDeletion: %s", body)

	// DescribeKey must still return 200 with KeyState=PendingDeletion
	// (mirrors real AWS; the provider's destroy wait-loop polls this).
	resp, body = kmsCall(t, srv, region, "DescribeKey",
		`{"KeyId":"`+keyID+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"DescribeKey after ScheduleKeyDeletion (expected 200 with PendingDeletion): %s", body)
	var described struct {
		KeyMetadata struct {
			KeyId        string
			KeyState     string
			Enabled      bool
			DeletionDate float64
		}
	}
	require.NoError(t, json.Unmarshal(body, &described), "decode DescribeKey: %s", body)
	assert.Equal(t, "PendingDeletion", described.KeyMetadata.KeyState)
	assert.False(t, described.KeyMetadata.Enabled, "Enabled=true after ScheduleKeyDeletion, want false")
	assert.NotZero(t, described.KeyMetadata.DeletionDate, "DeletionDate not set in DescribeKey response after ScheduleKeyDeletion")
}
