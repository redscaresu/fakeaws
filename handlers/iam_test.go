package handlers_test

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
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

func TestIAM_CreateRoleMissingNameIsValidationError(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "CreateRole", url.Values{})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "CreateRole with no RoleName")
	assert.Contains(t, string(body), "<Code>ValidationError</Code>")
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
	assert.Contains(t, string(body), "<Code>NoSuchEntity</Code>", "body missing AWS error code: %s", body)
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

// FK contract: DeletePolicy must refuse if attached, with IAM's
// DeleteConflict.
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
	assert.Contains(t, string(body), "<Code>DeleteConflict</Code>", "body missing DeleteConflict: %s", body)
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

// listInstanceProfilesForRole returns the profile names
// ListInstanceProfilesForRole answers for a role.
func listInstanceProfilesForRole(t *testing.T, srv *httptest.Server, role string) []string {
	t.Helper()
	resp, body := iamCall(t, srv, "ListInstanceProfilesForRole", url.Values{"RoleName": {role}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "ListInstanceProfilesForRole: %s", body)
	var out struct {
		Names []string `xml:"ListInstanceProfilesForRoleResult>InstanceProfiles>member>InstanceProfileName"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "ListInstanceProfilesForRole body: %s", body)
	return out.Names
}

// TestIAM_DeleteRoleHeldByInstanceProfile pins the aws_iam_role delete
// flow: ListInstanceProfilesForRole names the profiles holding the
// role, so the provider can remove it from each; while one still holds
// it DeleteRole is DeleteConflict.
func TestIAM_DeleteRoleHeldByInstanceProfile(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	for _, c := range []struct{ action, param, name string }{
		{"CreateRole", "RoleName", "r"},
		{"CreateRole", "RoleName", "other"},
		{"CreateInstanceProfile", "InstanceProfileName", "p1"},
		{"CreateInstanceProfile", "InstanceProfileName", "p2"},
		{"CreateInstanceProfile", "InstanceProfileName", "p3"},
	} {
		resp, body := iamCall(t, srv, c.action, url.Values{c.param: {c.name}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s %s: %s", c.action, c.name, body)
	}
	for profile, role := range map[string]string{"p1": "r", "p2": "r", "p3": "other"} {
		resp, body := iamCall(t, srv, "AddRoleToInstanceProfile", url.Values{"InstanceProfileName": {profile}, "RoleName": {role}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "AddRoleToInstanceProfile %s: %s", profile, body)
	}
	assert.Equal(t, []string{"p1", "p2"}, listInstanceProfilesForRole(t, srv, "r"))

	resp, body := iamCall(t, srv, "DeleteRole", url.Values{"RoleName": {"r"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "DeleteRole held by a profile: %s", body)
	assert.Contains(t, string(body), "<Code>DeleteConflict</Code>")

	for _, profile := range []string{"p1", "p2"} {
		resp, body = iamCall(t, srv, "RemoveRoleFromInstanceProfile", url.Values{"InstanceProfileName": {profile}, "RoleName": {"r"}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "RemoveRoleFromInstanceProfile %s: %s", profile, body)
	}
	assert.Empty(t, listInstanceProfilesForRole(t, srv, "r"))
	resp, body = iamCall(t, srv, "DeleteRole", url.Values{"RoleName": {"r"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteRole after the profiles let go: %s", body)
}

// TestIAM_GetRoleAssumeRolePolicyWireEncoding: GetRole sends
// AssumeRolePolicyDocument RFC 3986 encoded, as IAM does: a space is
// %20 and a '+' is %2B.
func TestIAM_GetRoleAssumeRolePolicyWireEncoding(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"a+b c"}]}`
	resp, body := iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}, "AssumeRolePolicyDocument": {doc}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateRole: %s", body)
	resp, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"r"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "GetRole: %s", body)
	var out struct {
		Doc string `xml:"GetRoleResult>Role>AssumeRolePolicyDocument"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "GetRole body: %s", body)
	assert.Contains(t, out.Doc, "a%2Bb%20c", "AssumeRolePolicyDocument on the wire")
	decoded, err := url.QueryUnescape(out.Doc)
	require.NoError(t, err)
	assert.Equal(t, doc, decoded)
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
// PutUserPolicy → GetUserPolicy returns the document, which
// TestIAM_PolicyDocumentsURLEncoded pins byte-exact.
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
	assert.Contains(t, string(body), "s3%3A%2A", "GetUserPolicy missing document: %s", body)

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

// TestIAM_PolicyDocumentsURLEncoded: GetUserPolicy and GetPolicyVersion
// send the document URL-encoded, as IAM does, so the provider's
// url.QueryUnescape gives back the bytes it sent. '%', '+', spaces and
// non-ASCII would not survive a decode of a document sent unencoded.
func TestIAM_PolicyDocumentsURLEncoded(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"a+b%20c d","Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::café/ü*"}]}`
	for _, c := range []struct{ action, param, name string }{
		{"CreateUser", "UserName", "alice"},
		{"PutUserPolicy", "UserName", "alice"},
		{"CreatePolicy", "PolicyName", "p"},
	} {
		resp, body := iamCall(t, srv, c.action, url.Values{c.param: {c.name}, "PolicyName": {"p"}, "PolicyDocument": {doc}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", c.action, body)
	}
	for action, params := range map[string]url.Values{
		"GetUserPolicy":    {"UserName": {"alice"}, "PolicyName": {"p"}},
		"GetPolicyVersion": {"PolicyArn": {"arn:aws:iam::000000000000:policy/p"}, "VersionId": {"v1"}},
	} {
		resp, body := iamCall(t, srv, action, params)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", action, body)
		var out struct { // one of the two is set
			User    string `xml:"GetUserPolicyResult>PolicyDocument"`
			Version string `xml:"GetPolicyVersionResult>PolicyVersion>Document"`
		}
		require.NoError(t, xml.Unmarshal(body, &out), "%s body: %s", action, body)
		wire := out.User + out.Version
		assert.Contains(t, wire, "a%2Bb%2520c%20d", "%s document on the wire", action)
		decoded, err := url.QueryUnescape(wire)
		require.NoError(t, err, action)
		assert.Equal(t, doc, decoded, action)
	}
}

// getRolePolicyDocument GetRolePolicy's a role's inline policy and
// returns its document URL-decoded, as the provider reads it.
func getRolePolicyDocument(t *testing.T, srv *httptest.Server, role, name string) string {
	t.Helper()
	doc, err := url.QueryUnescape(getRolePolicyWire(t, srv, role, name))
	require.NoError(t, err, "PolicyDocument is not URL-encoded")
	return doc
}

// getRolePolicyWire returns GetRolePolicy's PolicyDocument as sent,
// still URL-encoded.
func getRolePolicyWire(t *testing.T, srv *httptest.Server, role, name string) string {
	t.Helper()
	resp, body := iamCall(t, srv, "GetRolePolicy", url.Values{"RoleName": {role}, "PolicyName": {name}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "GetRolePolicy: %s", body)
	var out struct {
		PolicyDocument string `xml:"GetRolePolicyResult>PolicyDocument"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "GetRolePolicy body: %s", body)
	return out.PolicyDocument
}

// listRolePolicies returns the inline-policy names ListRolePolicies
// answers for a role.
func listRolePolicies(t *testing.T, srv *httptest.Server, role string) []string {
	t.Helper()
	resp, body := iamCall(t, srv, "ListRolePolicies", url.Values{"RoleName": {role}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "ListRolePolicies: %s", body)
	var out struct {
		Names []string `xml:"ListRolePoliciesResult>PolicyNames>member"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "ListRolePolicies body: %s", body)
	return out.Names
}

// TestContract_iam_role_inline_policies_stored pins aws_iam_role_policy's calls:
// Put then Get answers the document byte-exact once URL-decoded and
// RFC 3986 encoded on the wire, List names it, a second Put replaces
// it, Delete removes it, and Put or List on a missing role or Get or
// Delete of an absent name is NoSuchEntity, naming the missing one. A role holding an inline
// policy refuses DeleteRole with DeleteConflict and keeps both.
func TestContract_iam_role_inline_policies_stored(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "PutRolePolicy", url.Values{
		"RoleName": {"app"}, "PolicyName": {"s3"}, "PolicyDocument": {"{}"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "PutRolePolicy on a missing role: %s", body)
	assert.Contains(t, string(body), "<Code>NoSuchEntity</Code>", "PutRolePolicy on a missing role")
	assert.Contains(t, string(body), "<Message>The role with name app cannot be found.</Message>", "PutRolePolicy on a missing role")
	resp, body = iamCall(t, srv, "ListRolePolicies", url.Values{"RoleName": {"app"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "ListRolePolicies on a missing role: %s", body)
	assert.Contains(t, string(body), "<Code>NoSuchEntity</Code>", "ListRolePolicies on a missing role")
	assert.Contains(t, string(body), "<Message>The role with name app cannot be found.</Message>", "ListRolePolicies on a missing role")
	resp, body = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"app"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateRole: %s", body)
	put := func(doc string) {
		t.Helper()
		resp, body := iamCall(t, srv, "PutRolePolicy", url.Values{
			"RoleName": {"app"}, "PolicyName": {"s3"}, "PolicyDocument": {doc},
		})
		require.Equal(t, http.StatusOK, resp.StatusCode, "PutRolePolicy: %s", body)
	}
	// '+', '%', '&' and spaces would not survive a decode of a
	// document sent unencoded.
	v1 := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"arn:aws:s3:::a+b%20c&d e"}]}`
	v2 := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`

	put(v1)
	assert.Equal(t, v1, getRolePolicyDocument(t, srv, "app", "s3"))
	// IAM's RFC 3986 encoding: a space is %20, a '+' is %2B.
	assert.Contains(t, getRolePolicyWire(t, srv, "app", "s3"), "a%2Bb%2520c%26d%20e", "PolicyDocument on the wire")
	resp, body = iamCall(t, srv, "GetRolePolicy", url.Values{"RoleName": {"app"}, "PolicyName": {"absent"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetRolePolicy of an absent name: %s", body)
	assert.Contains(t, string(body), "<Message>The role policy with name absent cannot be found.</Message>")
	assert.Equal(t, []string{"s3"}, listRolePolicies(t, srv, "app"))

	put(v2)
	assert.Equal(t, v2, getRolePolicyDocument(t, srv, "app", "s3"), "a second Put replaces the document")

	resp, body = iamCall(t, srv, "DeleteRole", url.Values{"RoleName": {"app"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "DeleteRole holding an inline policy: %s", body)
	assert.Contains(t, string(body), "<Code>DeleteConflict</Code>")
	assert.Equal(t, v2, getRolePolicyDocument(t, srv, "app", "s3"), "the refused DeleteRole keeps the policy")
	resp, _ = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"app"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the refused DeleteRole keeps the role")

	resp, body = iamCall(t, srv, "DeleteRolePolicy", url.Values{"RoleName": {"app"}, "PolicyName": {"s3"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteRolePolicy: %s", body)
	for _, action := range []string{"GetRolePolicy", "DeleteRolePolicy"} {
		resp, body = iamCall(t, srv, action, url.Values{"RoleName": {"app"}, "PolicyName": {"s3"}})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "%s of an absent name: %s", action, body)
		assert.Contains(t, string(body), "<Code>NoSuchEntity</Code>", action)
	}
	assert.Empty(t, listRolePolicies(t, srv, "app"), "ListRolePolicies after delete")

	resp, body = iamCall(t, srv, "DeleteRole", url.Values{"RoleName": {"app"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteRole after DeleteRolePolicy: %s", body)
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

// TestIAM_RolesAreListMembers: a role in a list, an instance profile's
// Roles included, is a <member>. Nested as <Role>, the SDK reads the
// profile as roleless: aws_iam_instance_profile plans `+ role` and
// its next apply fails AddRoleToInstanceProfile.
func TestIAM_RolesAreListMembers(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"r"}, "AssumeRolePolicyDocument": {"{}"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateRole: %s", body)
	resp, body = iamCall(t, srv, "CreateInstanceProfile", url.Values{"InstanceProfileName": {"p"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateInstanceProfile: %s", body)
	resp, body = iamCall(t, srv, "AddRoleToInstanceProfile", url.Values{"InstanceProfileName": {"p"}, "RoleName": {"r"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "AddRoleToInstanceProfile: %s", body)

	var got struct {
		Roles []string `xml:"GetInstanceProfileResult>InstanceProfile>Roles>member>RoleName"`
		Name  string   `xml:"GetInstanceProfileResult>InstanceProfile>InstanceProfileName"`
	}
	_, body = iamCall(t, srv, "GetInstanceProfile", url.Values{"InstanceProfileName": {"p"}})
	require.NoError(t, xml.Unmarshal(body, &got), "%s", body)
	assert.Equal(t, "p", got.Name, "%s", body)
	assert.Equal(t, []string{"r"}, got.Roles, "%s", body)

	var listed struct {
		Profiles []string `xml:"ListInstanceProfilesResult>InstanceProfiles>member>InstanceProfileName"`
		Roles    []string `xml:"ListInstanceProfilesResult>InstanceProfiles>member>Roles>member>RoleName"`
	}
	_, body = iamCall(t, srv, "ListInstanceProfiles", nil)
	require.NoError(t, xml.Unmarshal(body, &listed), "%s", body)
	assert.Equal(t, []string{"p"}, listed.Profiles, "%s", body)
	assert.Equal(t, []string{"r"}, listed.Roles, "%s", body)

	var roles struct {
		Names []string `xml:"ListRolesResult>Roles>member>RoleName"`
	}
	_, body = iamCall(t, srv, "ListRoles", nil)
	require.NoError(t, xml.Unmarshal(body, &roles), "%s", body)
	assert.Equal(t, []string{"r"}, roles.Names, "%s", body)

	var role struct {
		Name string `xml:"GetRoleResult>Role>RoleName"`
	}
	_, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"r"}})
	require.NoError(t, xml.Unmarshal(body, &role), "%s", body)
	assert.Equal(t, "r", role.Name, "%s", body)
}

func TestIAM_ARNsCarryStoredAccount(t *testing.T) {
	_, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AccountID: otherAccount})
	cases := []struct {
		action, collection, name, arn string
		params                        url.Values
	}{
		{"CreateRole", "roles", "acct-role", "arn:aws:iam::123456789012:role/acct-role",
			url.Values{"RoleName": {"acct-role"}, "AssumeRolePolicyDocument": {`{"Version":"2012-10-17"}`}}},
		{"CreatePolicy", "policies", "acct-policy", "arn:aws:iam::123456789012:policy/acct-policy",
			url.Values{"PolicyName": {"acct-policy"}, "PolicyDocument": {`{"Version":"2012-10-17"}`}}},
		{"CreateInstanceProfile", "instance_profiles", "acct-profile", "arn:aws:iam::123456789012:instance-profile/acct-profile",
			url.Values{"InstanceProfileName": {"acct-profile"}}},
		{"CreateUser", "users", "acct-user", "arn:aws:iam::123456789012:user/acct-user",
			url.Values{"UserName": {"acct-user"}}},
	}
	for _, c := range cases {
		resp, body := iamCall(t, srv, c.action, c.params)
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", c.action, body)
		assert.Equal(t, c.arn, xmlExtract(body, "Arn"), c.action)
	}

	type row struct {
		Name string `json:"name"`
		ARN  string `json:"arn"`
	}
	var state struct {
		IAM map[string][]row `json:"iam"`
	}
	resp, body := doGet(t, srv, "/mock/state")
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state: %s", body)
	require.NoError(t, json.Unmarshal(body, &state), "body=%s", body)
	for _, c := range cases {
		assert.Equal(t, []row{{Name: c.name, ARN: c.arn}}, state.IAM[c.collection], c.collection)
	}
}

func TestIAM_UnreadableIdentityIs500(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	_, err := app.Repository().DB().Exec(`DROP TABLE identity`)
	require.NoError(t, err)

	resp, body := iamCall(t, srv, "CreateRole", url.Values{
		"RoleName":                 {"no-identity"},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17"}`},
	})
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "body=%s", body)
	assert.Contains(t, string(body), "<Code>InternalFailure</Code>")
	assert.Contains(t, string(body), "<Message>An internal error occurred.</Message>", "a 500 never carries the error's text")
	var n int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM iam_roles`).Scan(&n))
	assert.Zero(t, n, "role rows written")
}
