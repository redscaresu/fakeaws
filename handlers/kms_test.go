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

// TestKMS_KeyDescriptionRoundTrip pins that DescribeKey returns the
// description CreateKey stored and UpdateKeyDescription replaced;
// a hard-coded "" made every described aws_kms_key drift on plan.
func TestKMS_KeyDescriptionRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	describe := func(keyID string) string {
		resp, body := kmsCall(t, srv, region, "DescribeKey", `{"KeyId":"`+keyID+`"}`)
		require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeKey: %s", body)
		var out struct{ KeyMetadata struct{ Description string } }
		require.NoError(t, json.Unmarshal(body, &out), "decode DescribeKey: body=%s", body)
		return out.KeyMetadata.Description
	}

	resp, body := kmsCall(t, srv, region, "CreateKey", `{"Description":"app key"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateKey: %s", body)
	var created struct {
		KeyMetadata struct{ KeyId, Description string }
	}
	require.NoError(t, json.Unmarshal(body, &created), "decode CreateKey: body=%s", body)
	keyID := created.KeyMetadata.KeyId
	assert.Equal(t, "app key", created.KeyMetadata.Description)
	assert.Equal(t, "app key", describe(keyID))

	resp, body = kmsCall(t, srv, region, "UpdateKeyDescription", `{"KeyId":"`+keyID+`","Description":"rotated key"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "UpdateKeyDescription: %s", body)
	assert.Equal(t, "rotated key", describe(keyID))

	resp, body = kmsCall(t, srv, region, "UpdateKeyDescription", `{"KeyId":"missing","Description":"x"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "UpdateKeyDescription on unknown key: %s", body)
}

// kmsCreateKey creates a key with description in us-east-1 and returns
// its id.
func kmsCreateKey(t *testing.T, srv *httptest.Server, description string) string {
	t.Helper()
	var key struct{ KeyMetadata struct{ KeyId string } }
	require.NoError(t, json.Unmarshal(mustOK(t)(kmsCall(t, srv, "us-east-1", "CreateKey", `{"Description":"`+description+`"}`)), &key))
	return key.KeyMetadata.KeyId
}

// kmsListKeyIDs returns ListKeys' key ids in us-east-1.
func kmsListKeyIDs(t *testing.T, srv *httptest.Server) []string {
	t.Helper()
	var out struct {
		Keys      []struct{ KeyId, KeyArn string }
		Truncated bool
	}
	require.NoError(t, json.Unmarshal(mustOK(t)(kmsCall(t, srv, "us-east-1", "ListKeys", `{}`)), &out))
	assert.False(t, out.Truncated)
	ids := []string{}
	for _, k := range out.Keys {
		assert.Contains(t, k.KeyArn, ":key/"+k.KeyId)
		ids = append(ids, k.KeyId)
	}
	return ids
}

// TestKMS_ResetDeletesKeys: /mock/reset deletes every key, so an
// identity change after it is accepted and no key answers under either
// account.
func TestKMS_ResetDeletesKeys(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	keyID := kmsCreateKey(t, srv, "reset")
	require.Equal(t, []string{keyID}, kmsListKeyIDs(t, srv))

	mustOK(t)(doPost(t, srv, "/mock/reset"))
	assert.Empty(t, kmsListKeyIDs(t, srv), "after reset")
	mustOK(t)(doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`"}`))
	assert.Empty(t, kmsListKeyIDs(t, srv), "under the new account")
	resp, body := kmsCall(t, srv, "us-east-1", "DescribeKey", `{"KeyId":"`+keyID+`"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeKey after reset: %s", body)
	var rows int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM kms_keys`).Scan(&rows))
	assert.Zero(t, rows, "kms_keys rows under any account")
}

// TestKMS_SnapshotRestoreCarriesKeys: a key created before a snapshot
// comes back from a restore as it was; one created after is gone.
func TestKMS_SnapshotRestoreCarriesKeys(t *testing.T) {
	srv := newTestServer(t, filepath.Join(t.TempDir(), "kms.db"))
	before := kmsCreateKey(t, srv, "before")
	described := mustOK(t)(kmsCall(t, srv, "us-east-1", "DescribeKey", `{"KeyId":"`+before+`"}`))
	mustOK(t)(doPost(t, srv, "/mock/snapshot"))
	after := kmsCreateKey(t, srv, "after")
	require.ElementsMatch(t, []string{before, after}, kmsListKeyIDs(t, srv))

	mustOK(t)(doPost(t, srv, "/mock/restore"))
	assert.Equal(t, []string{before}, kmsListKeyIDs(t, srv))
	assert.JSONEq(t, string(described), string(mustOK(t)(kmsCall(t, srv, "us-east-1", "DescribeKey", `{"KeyId":"`+before+`"}`))))
	resp, body := kmsCall(t, srv, "us-east-1", "DescribeKey", `{"KeyId":"`+after+`"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeKey of the key created after the snapshot: %s", body)
}

// TestKMS_ApplicationsKeepSeparateKeys: two Applications in one process
// never see each other's keys.
func TestKMS_ApplicationsKeepSeparateKeys(t *testing.T) {
	srvA, srvB := newTestServer(t, ":memory:"), newTestServer(t, ":memory:")
	keyA := kmsCreateKey(t, srvA, "a")
	keyB := kmsCreateKey(t, srvB, "b")
	assert.Equal(t, []string{keyA}, kmsListKeyIDs(t, srvA))
	assert.Equal(t, []string{keyB}, kmsListKeyIDs(t, srvB))
	resp, body := kmsCall(t, srvB, "us-east-1", "DescribeKey", `{"KeyId":"`+keyA+`"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "A's key on B: %s", body)
}

// TestKMS_KeysAreRegional: a key answers only in the region it was
// created in, as in AWS.
func TestKMS_KeysAreRegional(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	keyID := kmsCreateKey(t, srv, "regional")
	var listed struct{ Keys []any }
	require.NoError(t, json.Unmarshal(mustOK(t)(kmsCall(t, srv, "eu-west-1", "ListKeys", `{}`)), &listed))
	assert.Empty(t, listed.Keys)
	resp, body := kmsCall(t, srv, "eu-west-1", "DescribeKey", `{"KeyId":"`+keyID+`"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeKey in another region: %s", body)
}

// kmsNotFound asserts resp is AWS KMS's 404 NotFoundException, the code
// terraform-provider-aws reads as a key that is gone.
func kmsNotFound(t *testing.T, call string, resp *http.Response, body []byte) {
	t.Helper()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "%s: %s", call, body)
	assert.Contains(t, string(body), `"__type":"NotFoundException"`, call)
}

// TestKMS_StateListsKeys: /mock/state lists every key under the stored
// account, in every region, with its state, PendingDeletion included.
func TestKMS_StateListsKeys(t *testing.T) {
	_, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AccountID: otherAccount})
	east := kmsCreateKey(t, srv, "east")
	var created struct{ KeyMetadata struct{ KeyId string } }
	require.NoError(t, json.Unmarshal(mustOK(t)(kmsCall(t, srv, "eu-west-1", "CreateKey", `{}`)), &created))
	west := created.KeyMetadata.KeyId
	mustOK(t)(kmsCall(t, srv, "eu-west-1", "ScheduleKeyDeletion", `{"KeyId":"`+west+`","PendingWindowInDays":7}`))

	var state struct {
		KMS struct{ Keys []map[string]string } `json:"kms"`
	}
	require.NoError(t, json.Unmarshal(mustOK(t)(doGet(t, srv, "/mock/state/kms")), &state))
	assert.Equal(t, []map[string]string{
		{"key_id": west, "arn": "arn:aws:kms:eu-west-1:" + otherAccount + ":key/" + west, "state": "PendingDeletion", "region": "eu-west-1", "account": otherAccount},
		{"key_id": east, "arn": "arn:aws:kms:us-east-1:" + otherAccount + ":key/" + east, "state": "Enabled", "region": "us-east-1", "account": otherAccount},
	}, state.KMS.Keys)
}

// TestKMS_DestroyLeavesIdentityFree replays the requests
// terraform-provider-aws 5.100.0 sends to apply and then destroy
// examples/working/kms_key, recorded with -record-requests. Destroy
// only schedules deletion, so the key stays, PendingDeletion, in
// /mock/state; the identity guard does not count it, as AWS no longer
// serves it, so POST /mock/identity is accepted.
func TestKMS_DestroyLeavesIdentityFree(t *testing.T) {
	_, srv := newTestApp(t, ":memory:")
	const region = "us-east-1"
	var created struct{ KeyMetadata struct{ KeyId string } }
	require.NoError(t, json.Unmarshal(mustOK(t)(kmsCall(t, srv, region, "CreateKey",
		`{"CustomerMasterKeySpec":"SYMMETRIC_DEFAULT","Description":"fakeaws example key","KeyUsage":"ENCRYPT_DECRYPT"}`)), &created))
	key := `{"KeyId":"` + created.KeyMetadata.KeyId + `"}`
	refresh := func() {
		mustOK(t)(kmsCall(t, srv, region, "DescribeKey", key))
		mustOK(t)(kmsCall(t, srv, region, "GetKeyPolicy", `{"KeyId":"`+created.KeyMetadata.KeyId+`","PolicyName":"default"}`))
		mustOK(t)(kmsCall(t, srv, region, "GetKeyRotationStatus", key))
		mustOK(t)(kmsCall(t, srv, region, "ListResourceTags", key))
	}
	refresh() // apply's read after create
	resp, body := doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`"}`)
	require.Equal(t, http.StatusConflict, resp.StatusCode, "an applied key counts: %s", body)

	refresh() // destroy's refresh
	mustOK(t)(kmsCall(t, srv, region, "ScheduleKeyDeletion", `{"KeyId":"`+created.KeyMetadata.KeyId+`","PendingWindowInDays":7}`))
	mustOK(t)(kmsCall(t, srv, region, "DescribeKey", key))

	var state struct {
		KMS struct {
			Keys []struct{ KeyId, State string }
		} `json:"kms"`
	}
	stateBody := mustOK(t)(doGet(t, srv, "/mock/state/kms"))
	require.NoError(t, json.Unmarshal(stateBody, &state))
	require.Len(t, state.KMS.Keys, 1, "%s", stateBody)
	assert.Equal(t, "PendingDeletion", state.KMS.Keys[0].State)
	resp, body = doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "after destroy: %s", body)
}

// TestKMS_GetKeyPolicyNeedsTheKey: GetKeyPolicy answers only a stored
// key, as every other key operation does.
func TestKMS_GetKeyPolicyNeedsTheKey(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	keyID := kmsCreateKey(t, srv, "policy")
	policy := `{"KeyId":"` + keyID + `","PolicyName":"default"}`
	mustOK(t)(kmsCall(t, srv, "us-east-1", "GetKeyPolicy", policy))

	resp, body := kmsCall(t, srv, "us-east-1", "GetKeyPolicy", `{"KeyId":"1234abcd-12ab-34cd-56ef-1234567890ab","PolicyName":"default"}`)
	kmsNotFound(t, "unknown key", resp, body)
	resp, body = kmsCall(t, srv, "eu-west-1", "GetKeyPolicy", policy)
	kmsNotFound(t, "another region", resp, body)
	mustOK(t)(doPost(t, srv, "/mock/reset"))
	resp, body = kmsCall(t, srv, "us-east-1", "GetKeyPolicy", policy)
	kmsNotFound(t, "after reset", resp, body)
}

// TestKMS_KeyArnAccepted: every key operation takes the KeyArn ListKeys
// answers as well as the key id; an ARN in another region matches no
// key. Aliases are not stored, so DescribeKey refuses an alias name or
// ARN as not modelled, and an operation AWS gives only a key id or ARN
// answers one NotFoundException.
func TestKMS_KeyArnAccepted(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	const region = "us-east-1"
	keyID := kmsCreateKey(t, srv, "arn")
	var listed struct {
		Keys []struct{ KeyId, KeyArn string }
	}
	require.NoError(t, json.Unmarshal(mustOK(t)(kmsCall(t, srv, region, "ListKeys", `{}`)), &listed))
	require.Len(t, listed.Keys, 1)
	arn := listed.Keys[0].KeyArn

	var described struct{ KeyMetadata struct{ KeyId, Arn string } }
	require.NoError(t, json.Unmarshal(mustOK(t)(kmsCall(t, srv, region, "DescribeKey", `{"KeyId":"`+arn+`"}`)), &described))
	assert.Equal(t, keyID, described.KeyMetadata.KeyId)
	assert.Equal(t, arn, described.KeyMetadata.Arn)
	for _, op := range []struct{ name, body string }{
		{"GetKeyPolicy", `{"KeyId":"` + arn + `","PolicyName":"default"}`},
		{"GetKeyRotationStatus", `{"KeyId":"` + arn + `"}`},
		{"EnableKeyRotation", `{"KeyId":"` + arn + `"}`},
		{"UpdateKeyDescription", `{"KeyId":"` + arn + `","Description":"by arn"}`},
		{"TagResource", `{"KeyId":"` + arn + `","Tags":[{"TagKey":"k","TagValue":"v"}]}`},
		{"ListResourceTags", `{"KeyId":"` + arn + `"}`},
		{"UntagResource", `{"KeyId":"` + arn + `","TagKeys":["k"]}`},
		{"ScheduleKeyDeletion", `{"KeyId":"` + arn + `","PendingWindowInDays":7}`},
	} {
		resp, body := kmsCall(t, srv, region, op.name, op.body)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "%s by ARN: %s", op.name, body)
	}
	var after struct {
		KeyMetadata struct{ Description, KeyState string }
	}
	require.NoError(t, json.Unmarshal(mustOK(t)(kmsCall(t, srv, region, "DescribeKey", `{"KeyId":"`+keyID+`"}`)), &after))
	assert.Equal(t, "by arn", after.KeyMetadata.Description)
	assert.Equal(t, "PendingDeletion", after.KeyMetadata.KeyState)

	resp, body := kmsCall(t, srv, region, "DescribeKey", `{"KeyId":"arn:aws:kms:eu-west-1:000000000000:key/`+keyID+`"}`)
	kmsNotFound(t, "an ARN in another region", resp, body)

	for _, alias := range []string{"alias/app", "arn:aws:kms:us-east-1:000000000000:alias/app"} {
		resp, body := kmsCall(t, srv, region, "DescribeKey", `{"KeyId":"`+alias+`"}`)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "DescribeKey %s: %s", alias, body)
		assert.Equal(t, "filter-refused", lastClass(t, srv), alias)
	}
	resp, body = kmsCall(t, srv, region, "GetKeyPolicy", `{"KeyId":"alias/app","PolicyName":"default"}`)
	kmsNotFound(t, "GetKeyPolicy by alias", resp, body)
	assert.Equal(t, "answered-from-rows", lastClass(t, srv))
}
