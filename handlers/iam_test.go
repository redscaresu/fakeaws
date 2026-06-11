package handlers_test

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IAM handler tests. Each in-scope endpoint has at least one
// success-path test plus a 404 / FK-violation test where applicable
// per concepts.md "Coverage requirements" rule 1.
//
// Wire format: Query-RPC POST /iam with form body
// Action=<op>&Version=2010-05-08&<params>; XML response.

const iamVersion = "2010-05-08"

// iamCall is the common test helper — POSTs a Query-RPC body and
// returns the response + body bytes so tests can encoding/xml decode.
func iamCall(t *testing.T, srv *httptest.Server, action string, params url.Values) (*http.Response, []byte) {
	t.Helper()
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", iamVersion)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/iam", strings.NewReader(params.Encode()))
	require.NoError(t, err, "new request")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "POST /iam %s", action)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// ----- Roles -----

func TestIAM_CreateGetListUpdateDeleteRole(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// Create.
	resp, body := iamCall(t, srv, "CreateRole", url.Values{
		"RoleName":                 {"admin"},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17"}`},
		"Description":              {"the admin role"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateRole: body=%s", body)
	assert.Contains(t, string(body), "<RoleName>admin</RoleName>", "CreateRole body missing <RoleName>admin</RoleName>: %s", body)
	assert.Contains(t, string(body), "arn:aws:iam::000000000000:role/admin", "CreateRole body missing ARN: %s", body)

	// Get.
	resp, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"admin"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "GetRole: body=%s", body)
	assert.Contains(t, string(body), "<RoleName>admin</RoleName>", "GetRole missing role: %s", body)

	// List.
	resp, body = iamCall(t, srv, "ListRoles", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "ListRoles")
	assert.Contains(t, string(body), "<RoleName>admin</RoleName>", "ListRoles missing role: %s", body)

	// Update.
	resp, _ = iamCall(t, srv, "UpdateRole", url.Values{
		"RoleName":    {"admin"},
		"Description": {"updated"},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "UpdateRole")
	_, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"admin"}})
	assert.Contains(t, string(body), "<Description>updated</Description>", "UpdateRole did not persist: %s", body)

	// Delete.
	resp, _ = iamCall(t, srv, "DeleteRole", url.Values{"RoleName": {"admin"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteRole")
	resp, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"admin"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "after delete, GetRole body=%s", body)
}

func TestIAM_CreateRoleMissingNameIs409(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := iamCall(t, srv, "CreateRole", url.Values{})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateRole with no RoleName")
}

func TestIAM_CreateRoleDuplicateIs409(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})
	resp, body := iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "duplicate CreateRole body=%s", body)
}

func TestIAM_GetRoleMissingIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "GetRole", url.Values{"RoleName": {"ghost"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetRole on missing body=%s", body)
	assert.Contains(t, string(body), "ResourceNotFoundException", "body missing AWS error code: %s", body)
}

// ----- Policies -----

func TestIAM_PolicyCRUD(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := iamCall(t, srv, "CreatePolicy", url.Values{
		"PolicyName":     {"p1"},
		"PolicyDocument": {`{"Version":"2012-10-17"}`},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreatePolicy body=%s", body)
	assert.Contains(t, string(body), "<PolicyName>p1</PolicyName>", "CreatePolicy body: %s", body)

	resp, _ = iamCall(t, srv, "ListPolicies", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListPolicies")

	// GetPolicy via PolicyArn.
	resp, body = iamCall(t, srv, "GetPolicy", url.Values{
		"PolicyArn": {"arn:aws:iam::000000000000:policy/p1"},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetPolicy by ARN: body=%s", body)

	// Delete.
	resp, _ = iamCall(t, srv, "DeletePolicy", url.Values{"PolicyName": {"p1"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeletePolicy")
}

// FK contract: DeletePolicy must refuse if attached. Real IAM
// returns a DeleteConflict error.
func TestIAM_DeletePolicyAttachedReturns409(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})
	_, _ = iamCall(t, srv, "CreatePolicy", url.Values{"PolicyName": {"p"}})
	_, _ = iamCall(t, srv, "AttachRolePolicy", url.Values{
		"RoleName":  {"r"},
		"PolicyArn": {"arn:aws:iam::000000000000:policy/p"},
	})

	resp, body := iamCall(t, srv, "DeletePolicy", url.Values{"PolicyName": {"p"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "DeletePolicy on attached body=%s", body)
	assert.Contains(t, string(body), "ResourceInUseException", "body missing ResourceInUseException: %s", body)
}

// ----- InstanceProfile + role attach -----

func TestIAM_InstanceProfileAddRemoveRole(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})
	_, _ = iamCall(t, srv, "CreateInstanceProfile", url.Values{"InstanceProfileName": {"p"}})

	resp, _ := iamCall(t, srv, "AddRoleToInstanceProfile", url.Values{
		"InstanceProfileName": {"p"},
		"RoleName":            {"r"},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "AddRoleToInstanceProfile")

	_, body := iamCall(t, srv, "GetInstanceProfile", url.Values{"InstanceProfileName": {"p"}})
	assert.Contains(t, string(body), "<RoleName>r</RoleName>", "GetInstanceProfile should embed role: %s", body)

	resp, _ = iamCall(t, srv, "RemoveRoleFromInstanceProfile", url.Values{
		"InstanceProfileName": {"p"},
		"RoleName":            {"r"},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "RemoveRoleFromInstanceProfile")
}

// FK contract: AddRoleToInstanceProfile with missing parent → 404.
func TestIAM_AddRoleToInstanceProfileMissingProfile(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})

	resp, _ := iamCall(t, srv, "AddRoleToInstanceProfile", url.Values{
		"InstanceProfileName": {"missing"},
		"RoleName":            {"r"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "AddRoleToInstanceProfile missing profile")
}

// ----- Users + AccessKeys -----

func TestIAM_UserCRUDPlusAccessKeyCascade(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "CreateUser", url.Values{"UserName": {"alice"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateUser body=%s", body)

	resp, body = iamCall(t, srv, "CreateAccessKey", url.Values{"UserName": {"alice"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateAccessKey body=%s", body)
	assert.Contains(t, string(body), "<AccessKey>", "CreateAccessKey body: %s", body)

	resp, body = iamCall(t, srv, "ListAccessKeys", url.Values{"UserName": {"alice"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListAccessKeys")
	assert.Contains(t, string(body), "<AccessKeyId>", "ListAccessKeys missing keys: %s", body)

	// CASCADE: deleting user wipes keys.
	resp, _ = iamCall(t, srv, "DeleteUser", url.Values{"UserName": {"alice"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteUser")
	resp, body = iamCall(t, srv, "ListAccessKeys", url.Values{"UserName": {"alice"}})
	// Empty list is acceptable (200 with no <member>) — the user is gone.
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListAccessKeys after delete")
	assert.NotContains(t, string(body), "<AccessKeyId>", "after CASCADE delete, ListAccessKeys should be empty: %s", body)
}

func TestIAM_CreateAccessKeyForMissingUserIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "CreateAccessKey", url.Values{"UserName": {"ghost"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "CreateAccessKey for missing user body=%s", body)
}

// ----- Role/Policy attach + detach round-trip -----

func TestIAM_AttachDetachRolePolicy(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})
	_, _ = iamCall(t, srv, "CreatePolicy", url.Values{"PolicyName": {"p"}})
	policyArn := "arn:aws:iam::000000000000:policy/p"

	resp, _ := iamCall(t, srv, "AttachRolePolicy", url.Values{
		"RoleName": {"r"}, "PolicyArn": {policyArn},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "AttachRolePolicy")

	resp, body := iamCall(t, srv, "ListAttachedRolePolicies", url.Values{"RoleName": {"r"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListAttachedRolePolicies")
	assert.Contains(t, string(body), policyArn, "ListAttachedRolePolicies missing %q: %s", policyArn, body)

	resp, _ = iamCall(t, srv, "DetachRolePolicy", url.Values{
		"RoleName": {"r"}, "PolicyArn": {policyArn},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DetachRolePolicy")
}

// TestIAM_AttachDetachUserPolicy pins the Ticket 1 closeout: user
// policy attachments persist into user_policy_attachments, so the
// provider's aws_iam_user_policy_attachment Read enumerates them
// instead of the pre-fix empty list (which made every refresh report
// drift on aws-full-stack).
func TestIAM_AttachDetachUserPolicy(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateUser", url.Values{"UserName": {"alice"}})
	_, _ = iamCall(t, srv, "CreatePolicy", url.Values{"PolicyName": {"p"}})
	policyArn := "arn:aws:iam::000000000000:policy/p"

	resp, _ := iamCall(t, srv, "AttachUserPolicy", url.Values{
		"UserName": {"alice"}, "PolicyArn": {policyArn},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "AttachUserPolicy")

	resp, body := iamCall(t, srv, "ListAttachedUserPolicies", url.Values{"UserName": {"alice"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListAttachedUserPolicies")
	assert.Contains(t, string(body), policyArn, "ListAttachedUserPolicies missing %q: %s", policyArn, body)

	resp, _ = iamCall(t, srv, "DetachUserPolicy", url.Values{
		"UserName": {"alice"}, "PolicyArn": {policyArn},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DetachUserPolicy")

	resp, body = iamCall(t, srv, "ListAttachedUserPolicies", url.Values{"UserName": {"alice"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListAttachedUserPolicies post-detach")
	assert.NotContains(t, string(body), policyArn, "post-detach still contains ARN: %s", body)
}

// TestIAM_PutGetDeleteUserPolicy pins the inline-policy round-trip:
// PutUserPolicy → GetUserPolicy returns the verbatim document; provider
// hashes match so no diff on plan.
func TestIAM_PutGetDeleteUserPolicy(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateUser", url.Values{"UserName": {"alice"}})
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`

	resp, _ := iamCall(t, srv, "PutUserPolicy", url.Values{
		"UserName":       {"alice"},
		"PolicyName":     {"all-s3"},
		"PolicyDocument": {doc},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "PutUserPolicy")

	resp, body := iamCall(t, srv, "GetUserPolicy", url.Values{
		"UserName":   {"alice"},
		"PolicyName": {"all-s3"},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetUserPolicy")
	assert.Contains(t, string(body), "s3:*", "GetUserPolicy missing document: %s", body)

	resp, body = iamCall(t, srv, "ListUserPolicies", url.Values{"UserName": {"alice"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListUserPolicies")
	assert.Contains(t, string(body), "all-s3", "ListUserPolicies missing name: %s", body)

	resp, _ = iamCall(t, srv, "DeleteUserPolicy", url.Values{
		"UserName":   {"alice"},
		"PolicyName": {"all-s3"},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteUserPolicy")

	resp, _ = iamCall(t, srv, "GetUserPolicy", url.Values{
		"UserName":   {"alice"},
		"PolicyName": {"all-s3"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetUserPolicy post-delete")
}

func TestIAM_AttachRolePolicyMissingPolicyIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})

	resp, body := iamCall(t, srv, "AttachRolePolicy", url.Values{
		"RoleName":  {"r"},
		"PolicyArn": {"arn:aws:iam::000000000000:policy/ghost"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "AttachRolePolicy missing policy body=%s", body)
}

// TestIAM_UserDestroyPreflightListsReturn200Empty pins the Ticket A
// closeout: the aws_iam_user destroy preflight walks four list
// endpoints (SSH public keys, service-specific credentials, MFA
// devices, signing certificates) before DeleteUser. Pre-T-A, each
// returned 404 and broke destroy mid-flight; now each returns 200
// with an empty list so destroy can proceed even on users with
// none of those resources attached.
func TestIAM_UserDestroyPreflightListsReturn200Empty(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateUser", url.Values{"UserName": {"u"}})

	cases := []struct {
		action     string
		wantMarker string
	}{
		{"ListSSHPublicKeys", "<SSHPublicKeys"},
		{"ListServiceSpecificCredentials", "<ServiceSpecificCredentials"},
		{"ListMFADevices", "<MFADevices"},
		{"ListSigningCertificates", "<Certificates"},
		{"ListVirtualMFADevices", "<VirtualMFADevices"},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			resp, raw := iamCall(t, srv, tc.action, url.Values{"UserName": {"u"}})
			body := string(raw)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "%s: body=%s", tc.action, body)
			// Tight: assert no marshal-error comment AND that the
			// result wrapper is present. The marshal-error comment
			// would appear if awsproto.WriteQueryRPCResponse falls
			// back when it can't serialize the result type (anonymous
			// multi-field structs trip this — see iamGetUserPolicyResult
			// inline comment).
			assert.NotContains(t, body, "marshal error", "%s: marshal error in body, body=%s", tc.action, body)
			assert.Contains(t, body, "<"+tc.action+"Result>", "%s: response missing <%sResult> wrapper, body=%s", tc.action, tc.action, body)
		})
	}
}

// TestIAM_DeleteLoginProfileReturnsNoSuchEntity pins the
// Ticket A follow-up: fakeaws doesn't model console login
// profiles. The provider's aws_iam_user destroy calls
// DeleteLoginProfile unconditionally and treats NoSuchEntity (404)
// as "already gone" — making destroy idempotent. Any other status
// breaks destroy.
func TestIAM_DeleteLoginProfileReturnsNoSuchEntity(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateUser", url.Values{"UserName": {"u"}})

	resp, raw := iamCall(t, srv, "DeleteLoginProfile", url.Values{"UserName": {"u"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteLoginProfile body=%s", raw)
	assert.Contains(t, string(raw), "NoSuchEntity", "DeleteLoginProfile: missing NoSuchEntity code, body=%s", raw)
}

// TestIAM_MockStateExcludesAutoSeededManagedPolicies pins the
// Ticket B closeout: SeedManagedPolicy lazy-inserts AWS-managed
// policy stubs (arn:aws:iam::aws:policy/*) when AttachRolePolicy
// or AttachUserPolicy references one. They aren't tenant resources
// and shouldn't surface in /mock/state's per-account view —
// otherwise infrafactory's countOrphans gate fires on them after
// destroy.
func TestIAM_MockStateExcludesAutoSeededManagedPolicies(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateUser", url.Values{"UserName": {"u"}})
	_, _ = iamCall(t, srv, "AttachUserPolicy", url.Values{
		"UserName":  {"u"},
		"PolicyArn": {"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
	})

	resp, raw := doGet(t, srv, "/mock/state/iam")
	body := string(raw)
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state/iam")
	assert.NotContains(t, body, "arn:aws:iam::aws:policy/", "auto-seeded managed policy ARN leaked into /mock/state: %s", body)

	// Also create a tenant policy and confirm it STAYS visible —
	// the filter must only drop arn:aws:iam::aws:policy/* prefix.
	_, _ = iamCall(t, srv, "CreatePolicy", url.Values{"PolicyName": {"mine"}})
	resp, raw = doGet(t, srv, "/mock/state/iam")
	body = string(raw)
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state/iam")
	assert.Contains(t, body, `"mine"`, "tenant policy missing from /mock/state after filter: %s", body)
}

// ----- Unknown action -----

func TestIAM_UnknownActionIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "DescribeUnicorns", nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "unknown action body=%s", body)
}

// ----- /mock/state IAM block -----

func TestIAM_MockStateReflectsCreatedResources(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"admin"}})
	_, _ = iamCall(t, srv, "CreatePolicy", url.Values{"PolicyName": {"p1"}})

	resp, body := doGet(t, srv, "/mock/state/iam")
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state/iam")
	for _, want := range []string{`"admin"`, `"p1"`} {
		assert.Contains(t, string(body), want, "/mock/state/iam missing %s: %s", want, body)
	}
}

// TestIAM_MockStateAccessKeysSurfaced pins Codex pass 10 BLOCKING #1:
// /mock/state.iam.access_keys must list every access key for the
// account so terraform-provider-aws's aws_iam_access_key drift checks
// are visible to topology_derive_aws.
func TestIAM_MockStateAccessKeysSurfaced(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	r, b := iamCall(t, srv, "CreateUser", url.Values{"UserName": {"alice"}})
	require.Equal(t, http.StatusOK, r.StatusCode, "CreateUser: %s", b)
	resp, body := iamCall(t, srv, "CreateAccessKey", url.Values{"UserName": {"alice"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateAccessKey: %s", body)
	// Pull the AccessKeyId out of the XML so we can assert on it.
	keyID := xmlExtract(body, "AccessKeyId")
	require.NotEmpty(t, keyID, "could not extract AccessKeyId from response: %s", body)

	resp, body = doGet(t, srv, "/mock/state/iam")
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state/iam")
	state := string(body)
	assert.Contains(t, state, `"access_keys"`, "/mock/state/iam missing access_keys collection: %s", state)
	assert.Contains(t, state, keyID, "/mock/state/iam.access_keys missing %s: %s", keyID, state)
	assert.Contains(t, state, `"alice"`, "/mock/state/iam.access_keys missing user_name=alice: %s", state)
}

// ----- Wire-shape sanity: response decodes as XML -----

func TestIAM_CreateRoleResponseIsValidXML(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, body := iamCall(t, srv, "CreateRole", url.Values{
		"RoleName":                 {"x"},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17"}`},
	})
	// Use a permissive struct — just confirm xml.Unmarshal succeeds
	// against the response envelope shape.
	var v struct {
		XMLName xml.Name
	}
	assert.NoError(t, xml.Unmarshal(body, &v), "response not valid XML: %s", body)
	assert.Contains(t, string(body), "<CreateRoleResponse>", "response missing <CreateRoleResponse> envelope: %s", body)
}
