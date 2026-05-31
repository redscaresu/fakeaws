package handlers_test

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /iam %s: %v", action, err)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole: got %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "<RoleName>admin</RoleName>") {
		t.Errorf("CreateRole body missing <RoleName>admin</RoleName>: %s", body)
	}
	if !strings.Contains(string(body), "arn:aws:iam::000000000000:role/admin") {
		t.Errorf("CreateRole body missing ARN: %s", body)
	}

	// Get.
	resp, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"admin"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetRole: got %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "<RoleName>admin</RoleName>") {
		t.Errorf("GetRole missing role: %s", body)
	}

	// List.
	resp, body = iamCall(t, srv, "ListRoles", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListRoles: got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "<RoleName>admin</RoleName>") {
		t.Errorf("ListRoles missing role: %s", body)
	}

	// Update.
	resp, _ = iamCall(t, srv, "UpdateRole", url.Values{
		"RoleName":    {"admin"},
		"Description": {"updated"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("UpdateRole: got %d", resp.StatusCode)
	}
	_, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"admin"}})
	if !strings.Contains(string(body), "<Description>updated</Description>") {
		t.Errorf("UpdateRole did not persist: %s", body)
	}

	// Delete.
	resp, _ = iamCall(t, srv, "DeleteRole", url.Values{"RoleName": {"admin"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteRole: got %d", resp.StatusCode)
	}
	resp, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"admin"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("after delete, GetRole: got %d want 404, body=%s", resp.StatusCode, body)
	}
}

func TestIAM_CreateRoleMissingNameIs409(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := iamCall(t, srv, "CreateRole", url.Values{})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateRole with no RoleName: got %d want 409", resp.StatusCode)
	}
}

func TestIAM_CreateRoleDuplicateIs409(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})
	resp, body := iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate CreateRole: got %d want 409 body=%s", resp.StatusCode, body)
	}
}

func TestIAM_GetRoleMissingIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "GetRole", url.Values{"RoleName": {"ghost"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetRole on missing: got %d want 404, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "ResourceNotFoundException") {
		t.Errorf("body missing AWS error code: %s", body)
	}
}

// ----- Policies -----

func TestIAM_PolicyCRUD(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := iamCall(t, srv, "CreatePolicy", url.Values{
		"PolicyName":     {"p1"},
		"PolicyDocument": {`{"Version":"2012-10-17"}`},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreatePolicy: %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "<PolicyName>p1</PolicyName>") {
		t.Errorf("CreatePolicy body: %s", body)
	}

	resp, _ = iamCall(t, srv, "ListPolicies", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListPolicies: %d", resp.StatusCode)
	}

	// GetPolicy via PolicyArn.
	resp, body = iamCall(t, srv, "GetPolicy", url.Values{
		"PolicyArn": {"arn:aws:iam::000000000000:policy/p1"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetPolicy by ARN: %d body=%s", resp.StatusCode, body)
	}

	// Delete.
	resp, _ = iamCall(t, srv, "DeletePolicy", url.Values{"PolicyName": {"p1"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeletePolicy: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("DeletePolicy on attached: got %d want 409, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "ResourceInUseException") {
		t.Errorf("body missing ResourceInUseException: %s", body)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("AddRoleToInstanceProfile: %d", resp.StatusCode)
	}

	_, body := iamCall(t, srv, "GetInstanceProfile", url.Values{"InstanceProfileName": {"p"}})
	if !strings.Contains(string(body), "<RoleName>r</RoleName>") {
		t.Errorf("GetInstanceProfile should embed role: %s", body)
	}

	resp, _ = iamCall(t, srv, "RemoveRoleFromInstanceProfile", url.Values{
		"InstanceProfileName": {"p"},
		"RoleName":            {"r"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("RemoveRoleFromInstanceProfile: %d", resp.StatusCode)
	}
}

// FK contract: AddRoleToInstanceProfile with missing parent → 404.
func TestIAM_AddRoleToInstanceProfileMissingProfile(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})

	resp, _ := iamCall(t, srv, "AddRoleToInstanceProfile", url.Values{
		"InstanceProfileName": {"missing"},
		"RoleName":            {"r"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("AddRoleToInstanceProfile missing profile: %d want 404", resp.StatusCode)
	}
}

// ----- Users + AccessKeys -----

func TestIAM_UserCRUDPlusAccessKeyCascade(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "CreateUser", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser: %d body=%s", resp.StatusCode, body)
	}

	resp, body = iamCall(t, srv, "CreateAccessKey", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateAccessKey: %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "<AccessKey>") {
		t.Errorf("CreateAccessKey body: %s", body)
	}

	resp, body = iamCall(t, srv, "ListAccessKeys", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListAccessKeys: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "<AccessKeyId>") {
		t.Errorf("ListAccessKeys missing keys: %s", body)
	}

	// CASCADE: deleting user wipes keys.
	resp, _ = iamCall(t, srv, "DeleteUser", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteUser: %d", resp.StatusCode)
	}
	resp, body = iamCall(t, srv, "ListAccessKeys", url.Values{"UserName": {"alice"}})
	// Empty list is acceptable (200 with no <member>) — the user is gone.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListAccessKeys after delete: %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "<AccessKeyId>") {
		t.Errorf("after CASCADE delete, ListAccessKeys should be empty: %s", body)
	}
}

func TestIAM_CreateAccessKeyForMissingUserIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "CreateAccessKey", url.Values{"UserName": {"ghost"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("CreateAccessKey for missing user: %d want 404, body=%s", resp.StatusCode, body)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("AttachRolePolicy: %d", resp.StatusCode)
	}

	resp, body := iamCall(t, srv, "ListAttachedRolePolicies", url.Values{"RoleName": {"r"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListAttachedRolePolicies: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), policyArn) {
		t.Errorf("ListAttachedRolePolicies missing %q: %s", policyArn, body)
	}

	resp, _ = iamCall(t, srv, "DetachRolePolicy", url.Values{
		"RoleName": {"r"}, "PolicyArn": {policyArn},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DetachRolePolicy: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("AttachUserPolicy: %d", resp.StatusCode)
	}

	resp, body := iamCall(t, srv, "ListAttachedUserPolicies", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListAttachedUserPolicies: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), policyArn) {
		t.Errorf("ListAttachedUserPolicies missing %q: %s", policyArn, body)
	}

	resp, _ = iamCall(t, srv, "DetachUserPolicy", url.Values{
		"UserName": {"alice"}, "PolicyArn": {policyArn},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DetachUserPolicy: %d", resp.StatusCode)
	}

	resp, body = iamCall(t, srv, "ListAttachedUserPolicies", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListAttachedUserPolicies post-detach: %d", resp.StatusCode)
	}
	if strings.Contains(string(body), policyArn) {
		t.Errorf("post-detach still contains ARN: %s", body)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PutUserPolicy: %d", resp.StatusCode)
	}

	resp, body := iamCall(t, srv, "GetUserPolicy", url.Values{
		"UserName":   {"alice"},
		"PolicyName": {"all-s3"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetUserPolicy: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "s3:*") {
		t.Errorf("GetUserPolicy missing document: %s", body)
	}

	resp, body = iamCall(t, srv, "ListUserPolicies", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListUserPolicies: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "all-s3") {
		t.Errorf("ListUserPolicies missing name: %s", body)
	}

	resp, _ = iamCall(t, srv, "DeleteUserPolicy", url.Values{
		"UserName":   {"alice"},
		"PolicyName": {"all-s3"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteUserPolicy: %d", resp.StatusCode)
	}

	resp, _ = iamCall(t, srv, "GetUserPolicy", url.Values{
		"UserName":   {"alice"},
		"PolicyName": {"all-s3"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetUserPolicy post-delete: %d want 404", resp.StatusCode)
	}
}

func TestIAM_AttachRolePolicyMissingPolicyIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}})

	resp, body := iamCall(t, srv, "AttachRolePolicy", url.Values{
		"RoleName":  {"r"},
		"PolicyArn": {"arn:aws:iam::000000000000:policy/ghost"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("AttachRolePolicy missing policy: %d want 404, body=%s", resp.StatusCode, body)
	}
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
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			resp, raw := iamCall(t, srv, tc.action, url.Values{"UserName": {"u"}})
			body := string(raw)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s: %d want 200, body=%s", tc.action, resp.StatusCode, body)
			}
			if !strings.Contains(body, tc.wantMarker) && !strings.Contains(body, tc.action+"Result") {
				t.Errorf("%s: response missing wrapper, body=%s", tc.action, body)
			}
		})
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /mock/state/iam: %d", resp.StatusCode)
	}
	if strings.Contains(body, "arn:aws:iam::aws:policy/") {
		t.Errorf("auto-seeded managed policy ARN leaked into /mock/state: %s", body)
	}

	// Also create a tenant policy and confirm it STAYS visible —
	// the filter must only drop arn:aws:iam::aws:policy/* prefix.
	_, _ = iamCall(t, srv, "CreatePolicy", url.Values{"PolicyName": {"mine"}})
	resp, raw = doGet(t, srv, "/mock/state/iam")
	body = string(raw)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /mock/state/iam: %d", resp.StatusCode)
	}
	if !strings.Contains(body, `"mine"`) {
		t.Errorf("tenant policy missing from /mock/state after filter: %s", body)
	}
}

// ----- Unknown action -----

func TestIAM_UnknownActionIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "DescribeUnicorns", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown action: %d want 404, body=%s", resp.StatusCode, body)
	}
}

// ----- /mock/state IAM block -----

func TestIAM_MockStateReflectsCreatedResources(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"admin"}})
	_, _ = iamCall(t, srv, "CreatePolicy", url.Values{"PolicyName": {"p1"}})

	resp, body := doGet(t, srv, "/mock/state/iam")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /mock/state/iam: %d", resp.StatusCode)
	}
	for _, want := range []string{`"admin"`, `"p1"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("/mock/state/iam missing %s: %s", want, body)
		}
	}
}

// TestIAM_MockStateAccessKeysSurfaced pins Codex pass 10 BLOCKING #1:
// /mock/state.iam.access_keys must list every access key for the
// account so terraform-provider-aws's aws_iam_access_key drift checks
// are visible to topology_derive_aws.
func TestIAM_MockStateAccessKeysSurfaced(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	if resp, body := iamCall(t, srv, "CreateUser", url.Values{"UserName": {"alice"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser: %d %s", resp.StatusCode, body)
	}
	resp, body := iamCall(t, srv, "CreateAccessKey", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateAccessKey: %d %s", resp.StatusCode, body)
	}
	// Pull the AccessKeyId out of the XML so we can assert on it.
	keyID := xmlExtract(body, "AccessKeyId")
	if keyID == "" {
		t.Fatalf("could not extract AccessKeyId from response: %s", body)
	}

	resp, body = doGet(t, srv, "/mock/state/iam")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /mock/state/iam: %d", resp.StatusCode)
	}
	state := string(body)
	if !strings.Contains(state, `"access_keys"`) {
		t.Errorf("/mock/state/iam missing access_keys collection: %s", state)
	}
	if !strings.Contains(state, keyID) {
		t.Errorf("/mock/state/iam.access_keys missing %s: %s", keyID, state)
	}
	if !strings.Contains(state, `"alice"`) {
		t.Errorf("/mock/state/iam.access_keys missing user_name=alice: %s", state)
	}
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
	if err := xml.Unmarshal(body, &v); err != nil {
		t.Errorf("response not valid XML: %v\n%s", err, body)
	}
	if !strings.Contains(string(body), "<CreateRoleResponse>") {
		t.Errorf("response missing <CreateRoleResponse> envelope: %s", body)
	}
}
