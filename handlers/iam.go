package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// registerIAMRoutes attaches the IAM Query-RPC dispatcher. Real IAM
// is a global service at iam.amazonaws.com, but terraform-provider-aws
// can be pointed at any host via `endpoints { iam = ... }`. fakeaws
// exposes the dispatcher at POST /iam — the infrafactory provider
// config (S43-T9 / S43-T11) will wire the endpoint override.
func (app *Application) registerIAMRoutes(r chi.Router) {
	r.Post("/iam", app.handleIAM)
}

// handleIAM parses the Query-RPC body, dispatches on Action, and
// writes the XML response (or AWS-shaped error). Per concepts.md
// § "testutil API contract": handler files focus on resource
// semantics; awsproto carries the wire-format burden.
func (app *Application) handleIAM(w http.ResponseWriter, r *http.Request) {
	req, err := awsproto.ParseQueryRPC(r)
	if err != nil {
		// Malformed request — treat as a bad-request error in the
		// Query-RPC shape so the SDK surfaces a useful message.
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}

	const account = awsproto.FakeAccountID

	switch req.Action {
	// ----- Roles -----
	case "CreateRole":
		app.iamCreateRole(w, account, req)
	case "GetRole":
		app.iamGetRole(w, account, req)
	case "ListRoles":
		app.iamListRoles(w, account, req)
	case "UpdateRole":
		app.iamUpdateRole(w, account, req)
	case "DeleteRole":
		app.iamDeleteRole(w, account, req)

	// ----- Policies -----
	case "CreatePolicy":
		app.iamCreatePolicy(w, account, req)
	case "GetPolicy":
		app.iamGetPolicy(w, account, req)
	case "GetPolicyVersion":
		app.iamGetPolicyVersion(w, account, req)
	case "ListPolicies":
		app.iamListPolicies(w, account, req)
	case "ListPolicyVersions":
		app.iamListPolicyVersions(w, account, req)
	case "DeletePolicy":
		app.iamDeletePolicy(w, account, req)

	// ----- Instance Profiles -----
	case "CreateInstanceProfile":
		app.iamCreateInstanceProfile(w, account, req)
	case "GetInstanceProfile":
		app.iamGetInstanceProfile(w, account, req)
	case "ListInstanceProfiles":
		app.iamListInstanceProfiles(w, account, req)
	case "DeleteInstanceProfile":
		app.iamDeleteInstanceProfile(w, account, req)
	case "AddRoleToInstanceProfile":
		app.iamAddRoleToInstanceProfile(w, account, req)
	case "RemoveRoleFromInstanceProfile":
		app.iamRemoveRoleFromInstanceProfile(w, account, req)

	// ----- Users -----
	case "CreateUser":
		app.iamCreateUser(w, account, req)
	case "GetUser":
		app.iamGetUser(w, account, req)
	case "ListUsers":
		app.iamListUsers(w, account, req)
	case "DeleteUser":
		app.iamDeleteUser(w, account, req)
	case "ListGroupsForUser":
		// terraform-provider-aws's aws_iam_user destroy enumerates
		// the user's group memberships so it can detach them before
		// deleting. fakeaws doesn't model IAM groups (no scenario
		// uses them); return an empty <Groups/> list rather than a
		// 404 so the destroy can proceed.
		app.iamListGroupsForUser(w, account, req)
	case "ListSSHPublicKeys":
		// Sibling of ListGroupsForUser in the aws_iam_user destroy
		// preflight: the provider walks SSH keys + service-specific
		// credentials before DeleteUser so it can remove them first.
		// fakeaws doesn't model either (no scenario uses them);
		// returning an empty list lets destroy proceed. Without
		// this, the 404 surfaces as "removing public SSH keys of
		// user X: ListSSHPublicKeys ResourceNotFoundException" and
		// blocks aws-full-stack destroy.
		app.iamListSSHPublicKeys(w, account, req)
	case "ListServiceSpecificCredentials":
		// Same destroy-preflight rationale as ListSSHPublicKeys.
		app.iamListServiceSpecificCredentials(w, account, req)
	case "ListMFADevices":
		// Same destroy-preflight rationale. The aws_iam_user destroy
		// flow walks MFA devices to deactivate them before DeleteUser;
		// fakeaws doesn't model MFA, so an empty list lets the destroy
		// proceed.
		app.iamListMFADevices(w, account, req)
	case "ListSigningCertificates":
		// Same destroy-preflight rationale. The destroy flow walks
		// signing certificates so it can delete them first.
		app.iamListSigningCertificates(w, account, req)
	case "AttachUserPolicy":
		// User-level analogue of AttachRolePolicy. Persisted now
		// (Ticket 1 closeout): aws_iam_user_policy_attachment Read
		// enumerates the user's attachments and the prior no-op
		// stub returned empty, causing apply to report drift on
		// every refresh and ultimately fail aws-full-stack.
		app.iamAttachUserPolicy(w, account, req)
	case "DetachUserPolicy":
		app.iamDetachUserPolicy(w, account, req)
	case "PutUserPolicy":
		app.iamPutUserPolicy(w, account, req)
	case "DeleteUserPolicy":
		app.iamDeleteUserPolicy(w, account, req)
	case "GetUserPolicy":
		app.iamGetUserPolicy(w, account, req)
	case "ListUserPolicies":
		// Inline-policy enumeration: drives destroy preflight and
		// also the Read path on aws_iam_user_policy. Backed by
		// user_inline_policies.
		app.iamListUserPolicies(w, account, req)
	case "ListAttachedUserPolicies":
		// Attached managed-policy enumeration. Backed by
		// user_policy_attachments so the resource Read sees the
		// state it just wrote.
		app.iamListAttachedUserPolicies(w, account, req)

	// ----- Access Keys -----
	case "CreateAccessKey":
		app.iamCreateAccessKey(w, account, req)
	case "ListAccessKeys":
		app.iamListAccessKeys(w, account, req)
	case "DeleteAccessKey":
		app.iamDeleteAccessKey(w, account, req)

	// ----- Role/Policy attachments -----
	case "AttachRolePolicy":
		app.iamAttachRolePolicy(w, account, req)
	case "DetachRolePolicy":
		app.iamDetachRolePolicy(w, account, req)
	case "ListAttachedRolePolicies":
		app.iamListAttachedRolePolicies(w, account, req)
	case "ListRolePolicies":
		app.iamListRolePolicies(w, account, req)
	case "PutRolePolicy":
		// Inline policy attachment. terraform-provider-aws's
		// aws_iam_role_policy resource uses this. We don't persist
		// inline policies (no scenario reads them back); a 200 envelope
		// is enough to unblock the apply.
		app.iamNoOpSuccess(w, "PutRolePolicy")
	case "DeleteRolePolicy":
		// Companion to PutRolePolicy on destroy. Idempotent no-op.
		app.iamNoOpSuccess(w, "DeleteRolePolicy")
	case "GetRolePolicy":
		// Refresh-path read. With no persisted inline state, return
		// an empty document.
		app.iamGetRolePolicyEmpty(w, account, req)
	case "ListRoleTags":
		app.iamListRoleTags(w, account, req)
	case "ListInstanceProfilesForRole":
		app.iamListInstanceProfilesForRole(w, account, req)

	default:
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("unsupported IAM action %q: %w", req.Action, models.ErrNotFound))
	}
}

// gatherIAMState (override of the stub in admin.go) emits the IAM
// block of /mock/state. Per concepts.md "Required surface" item 4 —
// topology_derive_aws (S43-T9) keys off this shape.
func (app *Application) gatherIAMStateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"roles":             []any{},
		"policies":          []any{},
		"instance_profiles": []any{},
		"users":             []any{},
		"access_keys":       []any{},
	}

	roles, _ := app.repo.ListRoles(account)
	rolesOut := make([]map[string]any, 0, len(roles))
	for _, r := range roles {
		rolesOut = append(rolesOut, map[string]any{
			"name":        r.Name,
			"arn":         r.ARN,
			"path":        r.Path,
			"description": r.Description,
			"created_at":  r.CreatedAt,
		})
	}
	out["roles"] = rolesOut

	policies, _ := app.repo.ListPolicies(account)
	pOut := make([]map[string]any, 0, len(policies))
	for _, p := range policies {
		// Filter AWS-managed policy stubs (arn:aws:iam::aws:policy/*)
		// that SeedManagedPolicy lazy-inserts on Attach*Policy calls.
		// They aren't tenant-owned resources — real AWS pre-creates
		// them globally — so they shouldn't surface in /mock/state's
		// per-account view and shouldn't count toward the
		// infrafactory countOrphans gate that fires on non-empty
		// collections after destroy. (Ticket B closeout.)
		if strings.HasPrefix(p.ARN, "arn:aws:iam::aws:policy/") {
			continue
		}
		pOut = append(pOut, map[string]any{
			"name":       p.Name,
			"arn":        p.ARN,
			"path":       p.Path,
			"created_at": p.CreatedAt,
		})
	}
	out["policies"] = pOut

	profs, _ := app.repo.ListInstanceProfiles(account)
	profsOut := make([]map[string]any, 0, len(profs))
	for _, p := range profs {
		profsOut = append(profsOut, map[string]any{
			"name":          p.Name,
			"arn":           p.ARN,
			"path":          p.Path,
			"attached_role": p.AttachedRole,
			"created_at":    p.CreatedAt,
		})
	}
	out["instance_profiles"] = profsOut

	users, _ := app.repo.ListUsers(account)
	uOut := make([]map[string]any, 0, len(users))
	for _, u := range users {
		uOut = append(uOut, map[string]any{
			"name":       u.Name,
			"arn":        u.ARN,
			"path":       u.Path,
			"created_at": u.CreatedAt,
		})
	}
	out["users"] = uOut

	// Access keys — account-wide enumeration (Codex pass 10 BLOCKING
	// #1 fix: previously absent, so terraform-provider-aws's
	// aws_iam_access_key drift checks were invisible to topology
	// derivation). ListAccessKeys with empty userName lists all users.
	keys, _ := app.repo.ListAccessKeys(account, "")
	kOut := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		kOut = append(kOut, map[string]any{
			"user_name":     k.UserName,
			"access_key_id": k.ID,
			"status":        k.Status,
			"created_at":    k.CreatedAt,
		})
	}
	out["access_keys"] = kOut

	return out
}

// ----- Role handlers -----

// iamRoleXML is the XML projection of an IAMRole that real IAM emits
// inside <Role>...</Role>. Per concepts.md "Anti-patterns" item 3
// (payload field-name variations): we use the canonical AWS field
// names exactly so terraform-provider-aws's parser doesn't complain.
type iamRoleXML struct {
	XMLName                  xml.Name `xml:"Role"`
	RoleName                 string   `xml:"RoleName"`
	Path                     string   `xml:"Path"`
	Arn                      string   `xml:"Arn"`
	AssumeRolePolicyDocument string   `xml:"AssumeRolePolicyDocument,omitempty"`
	Description              string   `xml:"Description,omitempty"`
	MaxSessionDuration       int      `xml:"MaxSessionDuration,omitempty"`
	CreateDate               string   `xml:"CreateDate"`
}

func roleToXML(r *repository.IAMRole) iamRoleXML {
	return iamRoleXML{
		RoleName:                 r.Name,
		Path:                     pathOrSlash(r.Path),
		Arn:                      r.ARN,
		AssumeRolePolicyDocument: urlEscapeIfNotEmpty(r.AssumeRolePolicyDocument),
		Description:              r.Description,
		MaxSessionDuration:       r.MaxSessionDuration,
		CreateDate:               r.CreatedAt,
	}
}

func (app *Application) iamCreateRole(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("RoleName")
	if name == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("RoleName is required: %w", models.ErrConflict))
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	role := &repository.IAMRole{
		Name:                     name,
		Path:                     pathOrSlash(req.Params.Get("Path")),
		ARN:                      awsproto.BuildIAMRoleARN(name),
		AssumeRolePolicyDocument: req.Params.Get("AssumeRolePolicyDocument"),
		Description:              req.Params.Get("Description"),
		CreatedAt:                now,
	}
	if mds := req.Params.Get("MaxSessionDuration"); mds != "" {
		fmt.Sscanf(mds, "%d", &role.MaxSessionDuration)
	}
	if err := app.repo.CreateRole(account, role); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	r := roleToXML(role)
	awsproto.WriteQueryRPCResponse(w, "CreateRole", &r)
}

func (app *Application) iamGetRole(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("RoleName")
	role, err := app.repo.GetRole(account, name)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	r := roleToXML(role)
	awsproto.WriteQueryRPCResponse(w, "GetRole", &r)
}

func (app *Application) iamListRoles(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	roles, err := app.repo.ListRoles(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := iamListRolesResult{Roles: make([]iamRoleXML, 0, len(roles))}
	for _, r := range roles {
		out.Roles = append(out.Roles, roleToXML(r))
	}
	awsproto.WriteQueryRPCResponse(w, "ListRoles", &out)
}

func (app *Application) iamUpdateRole(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("RoleName")
	role, err := app.repo.GetRole(account, name)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	if v := req.Params.Get("Description"); v != "" {
		role.Description = v
	}
	if v := req.Params.Get("MaxSessionDuration"); v != "" {
		fmt.Sscanf(v, "%d", &role.MaxSessionDuration)
	}
	if err := app.repo.UpdateRole(account, role); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "UpdateRole", nil)
}

func (app *Application) iamDeleteRole(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteRole(account, req.Params.Get("RoleName")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteRole", nil)
}

// ----- Policy handlers -----

type iamPolicyXML struct {
	XMLName        xml.Name `xml:"Policy"`
	PolicyName     string   `xml:"PolicyName"`
	Path           string   `xml:"Path"`
	Arn            string   `xml:"Arn"`
	Description    string   `xml:"Description,omitempty"`
	CreateDate     string   `xml:"CreateDate"`
	DefaultVersion string   `xml:"DefaultVersionId,omitempty"`
}

func policyToXML(p *repository.IAMPolicy) iamPolicyXML {
	return iamPolicyXML{
		PolicyName:     p.Name,
		Path:           pathOrSlash(p.Path),
		Arn:            p.ARN,
		Description:    p.Description,
		CreateDate:     p.CreatedAt,
		DefaultVersion: "v1",
	}
}

func (app *Application) iamCreatePolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("PolicyName")
	if name == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("PolicyName is required: %w", models.ErrConflict))
		return
	}
	policy := &repository.IAMPolicy{
		Name:           name,
		Path:           pathOrSlash(req.Params.Get("Path")),
		ARN:            awsproto.BuildIAMPolicyARN(name),
		PolicyDocument: req.Params.Get("PolicyDocument"),
		Description:    req.Params.Get("Description"),
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreatePolicy(account, policy); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	p := policyToXML(policy)
	awsproto.WriteQueryRPCResponse(w, "CreatePolicy", &p)
}

func (app *Application) iamGetPolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	// Real IAM accepts either PolicyArn or PolicyName; we try both.
	name := req.Params.Get("PolicyName")
	if name == "" {
		if arn := req.Params.Get("PolicyArn"); arn != "" {
			name, _ = repository.ResolveSameAccountName(account, arn, "policy")
		}
	}
	policy, err := app.repo.GetPolicy(account, name)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	p := policyToXML(policy)
	awsproto.WriteQueryRPCResponse(w, "GetPolicy", &p)
}

// iamGetPolicyVersion returns the policy document for the named
// version. fakeaws only stores a single policy document per policy
// (no version history) so every request resolves to v1 with the
// stored document. terraform-provider-aws calls this immediately
// after CreatePolicy to read the document back into state; without
// it the apply fails with "reading IAM Policy ... 404
// ResourceNotFoundException". M69.
func (app *Application) iamGetPolicyVersion(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("PolicyName")
	if name == "" {
		if arn := req.Params.Get("PolicyArn"); arn != "" {
			name, _ = repository.ResolveSameAccountName(account, arn, "policy")
		}
	}
	policy, err := app.repo.GetPolicy(account, name)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	// PolicyDocument must be URL-encoded per the IAM wire contract —
	// SDK calls url.QueryUnescape on the response. CreatePolicy
	// receives an already-encoded document (the provider sends it
	// that way), so we round-trip the persisted value verbatim.
	awsproto.WriteQueryRPCResponse(w, "GetPolicyVersion", &iamPolicyVersionResult{
		PolicyVersion: iamPolicyVersionXML{
			Document:         policy.PolicyDocument,
			VersionID:        "v1",
			IsDefaultVersion: true,
			CreateDate:       policy.CreatedAt,
		},
	})
}

// iamListPolicyVersions returns the single v1 version every fakeaws
// policy has. The provider sometimes calls this before
// GetPolicyVersion to find the default-version-id; without it the
// pre-Read flow 404s. M69.
func (app *Application) iamListPolicyVersions(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("PolicyName")
	if name == "" {
		if arn := req.Params.Get("PolicyArn"); arn != "" {
			name, _ = repository.ResolveSameAccountName(account, arn, "policy")
		}
	}
	policy, err := app.repo.GetPolicy(account, name)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "ListPolicyVersions", &iamListPolicyVersionsResult{
		Versions: []iamPolicyVersionXML{{
			// ListPolicyVersions returns the metadata only (no Document).
			VersionID:        "v1",
			IsDefaultVersion: true,
			CreateDate:       policy.CreatedAt,
		}},
	})
}

type iamPolicyVersionXML struct {
	Document         string `xml:"Document,omitempty"`
	VersionID        string `xml:"VersionId"`
	IsDefaultVersion bool   `xml:"IsDefaultVersion"`
	CreateDate       string `xml:"CreateDate"`
}

type iamPolicyVersionResult struct {
	PolicyVersion iamPolicyVersionXML `xml:"PolicyVersion"`
}

type iamListPolicyVersionsResult struct {
	Versions []iamPolicyVersionXML `xml:"Versions>member"`
}

func (app *Application) iamListPolicies(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	policies, err := app.repo.ListPolicies(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := iamListPoliciesResult{Policies: make([]iamPolicyXML, 0, len(policies))}
	for _, p := range policies {
		out.Policies = append(out.Policies, policyToXML(p))
	}
	awsproto.WriteQueryRPCResponse(w, "ListPolicies", &out)
}

func (app *Application) iamDeletePolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("PolicyName")
	if name == "" {
		if arn := req.Params.Get("PolicyArn"); arn != "" {
			name, _ = repository.ResolveSameAccountName(account, arn, "policy")
		}
	}
	if err := app.repo.DeletePolicy(account, name); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeletePolicy", nil)
}

// ----- InstanceProfile handlers -----

type iamInstanceProfileXML struct {
	XMLName             xml.Name     `xml:"InstanceProfile"`
	InstanceProfileName string       `xml:"InstanceProfileName"`
	Path                string       `xml:"Path"`
	Arn                 string       `xml:"Arn"`
	CreateDate          string       `xml:"CreateDate"`
	Roles               []iamRoleXML `xml:"Roles>member,omitempty"`
}

func instanceProfileToXML(p *repository.IAMInstanceProfile, attached *repository.IAMRole) iamInstanceProfileXML {
	out := iamInstanceProfileXML{
		InstanceProfileName: p.Name,
		Path:                pathOrSlash(p.Path),
		Arn:                 p.ARN,
		CreateDate:          p.CreatedAt,
	}
	if attached != nil {
		out.Roles = []iamRoleXML{roleToXML(attached)}
	}
	return out
}

func (app *Application) iamCreateInstanceProfile(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("InstanceProfileName")
	if name == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("InstanceProfileName is required: %w", models.ErrConflict))
		return
	}
	p := &repository.IAMInstanceProfile{
		Name:      name,
		Path:      pathOrSlash(req.Params.Get("Path")),
		ARN:       awsproto.BuildIAMInstanceProfileARN(name),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateInstanceProfile(account, p); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := instanceProfileToXML(p, nil)
	awsproto.WriteQueryRPCResponse(w, "CreateInstanceProfile", &out)
}

func (app *Application) iamGetInstanceProfile(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	p, err := app.repo.GetInstanceProfile(account, req.Params.Get("InstanceProfileName"))
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	var attached *repository.IAMRole
	if p.AttachedRole != "" {
		attached, _ = app.repo.GetRole(account, p.AttachedRole)
	}
	out := instanceProfileToXML(p, attached)
	awsproto.WriteQueryRPCResponse(w, "GetInstanceProfile", &out)
}

func (app *Application) iamListInstanceProfiles(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	profs, err := app.repo.ListInstanceProfiles(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := iamListInstanceProfilesResult{InstanceProfiles: make([]iamInstanceProfileXML, 0, len(profs))}
	for _, p := range profs {
		var attached *repository.IAMRole
		if p.AttachedRole != "" {
			attached, _ = app.repo.GetRole(account, p.AttachedRole)
		}
		out.InstanceProfiles = append(out.InstanceProfiles, instanceProfileToXML(p, attached))
	}
	awsproto.WriteQueryRPCResponse(w, "ListInstanceProfiles", &out)
}

func (app *Application) iamDeleteInstanceProfile(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteInstanceProfile(account, req.Params.Get("InstanceProfileName")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteInstanceProfile", nil)
}

func (app *Application) iamAddRoleToInstanceProfile(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.AddRoleToInstanceProfile(account,
		req.Params.Get("InstanceProfileName"),
		req.Params.Get("RoleName")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "AddRoleToInstanceProfile", nil)
}

func (app *Application) iamRemoveRoleFromInstanceProfile(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.RemoveRoleFromInstanceProfile(account,
		req.Params.Get("InstanceProfileName"),
		req.Params.Get("RoleName")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "RemoveRoleFromInstanceProfile", nil)
}

// ----- User + AccessKey handlers -----

type iamUserXML struct {
	XMLName    xml.Name `xml:"User"`
	UserName   string   `xml:"UserName"`
	Path       string   `xml:"Path"`
	Arn        string   `xml:"Arn"`
	UserId     string   `xml:"UserId"`
	CreateDate string   `xml:"CreateDate"`
}

func userToXML(u *repository.IAMUser) iamUserXML {
	return iamUserXML{
		UserName:   u.Name,
		Path:       pathOrSlash(u.Path),
		Arn:        u.ARN,
		UserId:     "AIDA" + strings.ToUpper(u.Name), // synthetic
		CreateDate: u.CreatedAt,
	}
}

func (app *Application) iamCreateUser(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("UserName")
	if name == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("UserName is required: %w", models.ErrConflict))
		return
	}
	u := &repository.IAMUser{
		Name:      name,
		Path:      pathOrSlash(req.Params.Get("Path")),
		ARN:       awsproto.BuildIAMUserARN(name),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateUser(account, u); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := userToXML(u)
	awsproto.WriteQueryRPCResponse(w, "CreateUser", &out)
}

func (app *Application) iamGetUser(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	u, err := app.repo.GetUser(account, req.Params.Get("UserName"))
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := userToXML(u)
	awsproto.WriteQueryRPCResponse(w, "GetUser", &out)
}

func (app *Application) iamListUsers(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	users, err := app.repo.ListUsers(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := iamListUsersResult{Users: make([]iamUserXML, 0, len(users))}
	for _, u := range users {
		out.Users = append(out.Users, userToXML(u))
	}
	awsproto.WriteQueryRPCResponse(w, "ListUsers", &out)
}

func (app *Application) iamDeleteUser(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteUser(account, req.Params.Get("UserName")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteUser", nil)
}

// iamListGroupsForUser returns an empty <Groups/> list. fakeaws
// doesn't model IAM Groups — terraform-provider-aws's aws_iam_user
// destroy walks this endpoint to detach group memberships before
// DeleteUser, and a 404 here stops the destroy mid-flight.
func (app *Application) iamListGroupsForUser(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	awsproto.WriteQueryRPCResponse(w, "ListGroupsForUser", &struct {
		Groups []string `xml:"Groups>member,omitempty"`
	}{})
}

// iamListSSHPublicKeys returns an empty <SSHPublicKeys/> list.
// Mirrors iamListGroupsForUser — see the dispatcher comment for
// the destroy-preflight rationale. Without this, aws-full-stack
// destroy fails on "removing public SSH keys of user X" with
// ListSSHPublicKeys 404.
func (app *Application) iamListSSHPublicKeys(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	awsproto.WriteQueryRPCResponse(w, "ListSSHPublicKeys", &struct {
		SSHPublicKeys []string `xml:"SSHPublicKeys>member,omitempty"`
		IsTruncated   bool     `xml:"IsTruncated"`
	}{})
}

// iamListServiceSpecificCredentials returns an empty list. Same
// destroy-preflight rationale as iamListSSHPublicKeys.
func (app *Application) iamListServiceSpecificCredentials(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	awsproto.WriteQueryRPCResponse(w, "ListServiceSpecificCredentials", &struct {
		ServiceSpecificCredentials []string `xml:"ServiceSpecificCredentials>member,omitempty"`
	}{})
}

// iamListMFADevices returns an empty <MFADevices/> list. Same
// destroy-preflight rationale; the provider walks MFA devices to
// deactivate before DeleteUser.
func (app *Application) iamListMFADevices(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	awsproto.WriteQueryRPCResponse(w, "ListMFADevices", &struct {
		MFADevices  []string `xml:"MFADevices>member,omitempty"`
		IsTruncated bool     `xml:"IsTruncated"`
	}{})
}

// iamListSigningCertificates returns an empty <Certificates/> list.
// Same destroy-preflight rationale.
func (app *Application) iamListSigningCertificates(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	awsproto.WriteQueryRPCResponse(w, "ListSigningCertificates", &struct {
		Certificates []string `xml:"Certificates>member,omitempty"`
		IsTruncated  bool     `xml:"IsTruncated"`
	}{})
}

// iamListUserPolicies returns the inline-policy names attached to a
// user. Read-side of PutUserPolicy.
func (app *Application) iamListUserPolicies(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	user := req.Params.Get("UserName")
	names, err := app.repo.ListUserPolicies(account, user)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "ListUserPolicies", &iamListUserPoliciesResult{PolicyNames: names})
}

// iamListAttachedUserPolicies returns the managed-policy attachments
// for a user, backed by user_policy_attachments so the resource's
// Read sees state it just wrote.
func (app *Application) iamListAttachedUserPolicies(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	user := req.Params.Get("UserName")
	arns, err := app.repo.ListAttachedUserPolicies(account, user)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	members := make([]iamAttachedPolicy, 0, len(arns))
	for _, arn := range arns {
		name := arn
		if i := strings.LastIndex(arn, "/"); i >= 0 {
			name = arn[i+1:]
		}
		members = append(members, iamAttachedPolicy{PolicyName: name, PolicyArn: arn})
	}
	awsproto.WriteQueryRPCResponse(w, "ListAttachedUserPolicies", &iamListAttachedUserPoliciesResult{AttachedPolicies: members})
}

// iamListUserPoliciesResult — XML wrapper for the inline-policy name
// list. The anonymous-struct version that previously held this shape
// marshalled fine for the empty-list path; the persistence path needs
// a named type so xml.Encoder doesn't trip on a nil slice.
type iamListUserPoliciesResult struct {
	PolicyNames []string `xml:"PolicyNames>member"`
	IsTruncated bool     `xml:"IsTruncated"`
}

// iamListAttachedUserPoliciesResult — XML wrapper symmetric with
// iamListAttachedRolePoliciesResult.
type iamListAttachedUserPoliciesResult struct {
	AttachedPolicies []iamAttachedPolicy `xml:"AttachedPolicies>member"`
	IsTruncated      bool                `xml:"IsTruncated"`
}

type iamAccessKeyXML struct {
	XMLName         xml.Name `xml:"AccessKey"`
	UserName        string   `xml:"UserName"`
	AccessKeyId     string   `xml:"AccessKeyId"`
	Status          string   `xml:"Status"`
	SecretAccessKey string   `xml:"SecretAccessKey,omitempty"`
	CreateDate      string   `xml:"CreateDate"`
}

type iamAccessKeyMetadataXML struct {
	UserName    string `xml:"UserName"`
	AccessKeyId string `xml:"AccessKeyId"`
	Status      string `xml:"Status"`
	CreateDate  string `xml:"CreateDate"`
}

func (app *Application) iamCreateAccessKey(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	user := req.Params.Get("UserName")
	id := "AKIA" + strings.ToUpper(randHex(8))
	secret := randHex(20)
	k := &repository.IAMAccessKey{
		ID: id, UserName: user, Secret: secret, Status: "Active",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateAccessKey(account, k); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := iamAccessKeyXML{
		UserName: user, AccessKeyId: id, Status: "Active",
		SecretAccessKey: secret, CreateDate: k.CreatedAt,
	}
	awsproto.WriteQueryRPCResponse(w, "CreateAccessKey", &out)
}

func (app *Application) iamListAccessKeys(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	user := req.Params.Get("UserName")
	keys, err := app.repo.ListAccessKeys(account, user)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := iamListAccessKeysResult{AccessKeyMetadata: make([]iamAccessKeyMetadataXML, 0, len(keys))}
	for _, k := range keys {
		out.AccessKeyMetadata = append(out.AccessKeyMetadata, iamAccessKeyMetadataXML{
			UserName: user, AccessKeyId: k.ID, Status: k.Status, CreateDate: k.CreatedAt,
		})
	}
	awsproto.WriteQueryRPCResponse(w, "ListAccessKeys", &out)
}

func (app *Application) iamDeleteAccessKey(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteAccessKey(account,
		req.Params.Get("UserName"), req.Params.Get("AccessKeyId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteAccessKey", nil)
}

// ----- Role/Policy attachments -----

func (app *Application) iamAttachRolePolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	roleName := req.Params.Get("RoleName")
	policyARN := req.Params.Get("PolicyArn")
	// AWS-managed policies (arn:aws:iam::aws:policy/X) are pre-created
	// by AWS in real accounts — customers can attach them without
	// ever calling CreatePolicy. fakeaws's repo only knows about
	// customer-created policies, so a managed-ARN attach fails 404
	// even though it's legal usage. Lazy-seed the managed policy
	// here on first reference, mirroring the AMI auto-seed pattern.
	if strings.HasPrefix(policyARN, "arn:aws:iam::aws:policy/") {
		_ = app.repo.SeedManagedPolicy(account, policyARN)
	}
	if err := app.repo.AttachRolePolicy(account, roleName, policyARN); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "AttachRolePolicy", nil)
}

// iamNoOpSuccess returns a minimal 200 for IAM actions we accept but
// don't persist (PutRolePolicy / DeleteRolePolicy). Real AWS returns
// an action-named envelope; the provider just needs successful parse.
func (app *Application) iamNoOpSuccess(w http.ResponseWriter, action string) {
	awsproto.WriteQueryRPCResponse(w, action, nil)
}

// iamAttachUserPolicy attaches a managed policy to a user. Auto-seeds
// AWS-managed policy ARNs the same way AttachRolePolicy does and
// persists into user_policy_attachments so subsequent
// ListAttachedUserPolicies sees the write.
func (app *Application) iamAttachUserPolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	user := req.Params.Get("UserName")
	policyARN := req.Params.Get("PolicyArn")
	if strings.HasPrefix(policyARN, "arn:aws:iam::aws:policy/") {
		_ = app.repo.SeedManagedPolicy(account, policyARN)
	}
	if err := app.repo.AttachUserPolicy(account, user, policyARN); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "AttachUserPolicy", nil)
}

// iamDetachUserPolicy removes the (user, ARN) attachment.
func (app *Application) iamDetachUserPolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	user := req.Params.Get("UserName")
	policyARN := req.Params.Get("PolicyArn")
	if err := app.repo.DetachUserPolicy(account, user, policyARN); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DetachUserPolicy", nil)
}

// iamPutUserPolicy stores an inline policy verbatim. The provider
// expects the same document back from GetUserPolicy (the policy is
// state-tracked by hash) so round-trip fidelity matters.
func (app *Application) iamPutUserPolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	user := req.Params.Get("UserName")
	name := req.Params.Get("PolicyName")
	doc := req.Params.Get("PolicyDocument")
	if err := app.repo.PutUserPolicy(account, user, name, doc); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "PutUserPolicy", nil)
}

// iamDeleteUserPolicy removes the inline policy. Idempotent w.r.t.
// the provider's destroy flow.
func (app *Application) iamDeleteUserPolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	user := req.Params.Get("UserName")
	name := req.Params.Get("PolicyName")
	if err := app.repo.DeleteUserPolicy(account, user, name); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteUserPolicy", nil)
}

// iamGetUserPolicy reads back the inline policy. Returns the verbatim
// document so the provider's hash matches between Create and Read.
// The named iamGetUserPolicyResult wrapper exists because the
// awsproto encoder rejects anonymous structs (see queryrpc.go
// marshalInnerXML — element-name detection trips on Go's anonymous-
// struct synthesised name).
func (app *Application) iamGetUserPolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	user := req.Params.Get("UserName")
	name := req.Params.Get("PolicyName")
	doc, err := app.repo.GetUserPolicy(account, user, name)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "GetUserPolicy", &iamGetUserPolicyResult{
		UserName:       user,
		PolicyName:     name,
		PolicyDocument: doc,
	})
}

// iamGetUserPolicyResult — named wrapper for GetUserPolicy. NO
// XMLName field, so marshalInnerXML's outer-element detection sees
// the lowercase Go type name and strips the wrapper — preventing
// the double-nested <GetUserPolicyResult><GetUserPolicyResult>...</...>...</...>
// that would otherwise break terraform-provider-aws's XML parser
// (aws-full-stack iter 4 "empty result" wait-loop).
type iamGetUserPolicyResult struct {
	UserName       string `xml:"UserName"`
	PolicyName     string `xml:"PolicyName"`
	PolicyDocument string `xml:"PolicyDocument"`
}

// iamGetRolePolicyEmpty returns an empty inline-policy document for
// the refresh path. Since PutRolePolicy is a no-op, there's nothing
// to read back; the empty document avoids a 404 that would break the
// provider's refresh.
func (app *Application) iamGetRolePolicyEmpty(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	awsproto.WriteQueryRPCResponse(w, "GetRolePolicy", &struct {
		RoleName       string `xml:"RoleName"`
		PolicyName     string `xml:"PolicyName"`
		PolicyDocument string `xml:"PolicyDocument"`
	}{
		RoleName:       req.Params.Get("RoleName"),
		PolicyName:     req.Params.Get("PolicyName"),
		PolicyDocument: `{"Version":"2012-10-17","Statement":[]}`,
	})
}

func (app *Application) iamDetachRolePolicy(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DetachRolePolicy(account,
		req.Params.Get("RoleName"), req.Params.Get("PolicyArn")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DetachRolePolicy", nil)
}

func (app *Application) iamListAttachedRolePolicies(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	arns, err := app.repo.ListAttachedRolePolicies(account, req.Params.Get("RoleName"))
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	members := make([]iamAttachedPolicy, 0, len(arns))
	for _, arn := range arns {
		// Pull the policy name out of the ARN (last segment after '/').
		name := arn
		if i := strings.LastIndex(arn, "/"); i >= 0 {
			name = arn[i+1:]
		}
		members = append(members, iamAttachedPolicy{PolicyName: name, PolicyArn: arn})
	}
	out := iamListAttachedRolePoliciesResult{AttachedPolicies: members}
	awsproto.WriteQueryRPCResponse(w, "ListAttachedRolePolicies", &out)
}

// Named wrapper types for List/multi-field responses. xml.Encoder
// rejects anonymous struct values; named types with explicit XMLName
// (or a tagged outer element) marshal correctly.

type iamListRolesResult struct {
	Roles       []iamRoleXML `xml:"Roles>member"`
	IsTruncated bool         `xml:"IsTruncated"`
}

type iamListPoliciesResult struct {
	Policies    []iamPolicyXML `xml:"Policies>member"`
	IsTruncated bool           `xml:"IsTruncated"`
}

type iamListInstanceProfilesResult struct {
	InstanceProfiles []iamInstanceProfileXML `xml:"InstanceProfiles>member"`
	IsTruncated      bool                    `xml:"IsTruncated"`
}

type iamListUsersResult struct {
	Users       []iamUserXML `xml:"Users>member"`
	IsTruncated bool         `xml:"IsTruncated"`
}

type iamListAccessKeysResult struct {
	AccessKeyMetadata []iamAccessKeyMetadataXML `xml:"AccessKeyMetadata>member"`
	IsTruncated       bool                      `xml:"IsTruncated"`
}

type iamAttachedPolicy struct {
	PolicyName string `xml:"PolicyName"`
	PolicyArn  string `xml:"PolicyArn"`
}

type iamListAttachedRolePoliciesResult struct {
	AttachedPolicies []iamAttachedPolicy `xml:"AttachedPolicies>member"`
	IsTruncated      bool                `xml:"IsTruncated"`
}

// iamListRolePolicies returns the inline-policy names attached to a
// role. terraform-provider-aws calls this as part of the aws_iam_role
// Read flow after CreateRole; returning the default unsupported-action
// 404 made the provider conclude the role didn't exist. We model the
// real IAM behavior: 404 ResourceNotFoundException when the role is
// missing, otherwise an empty PolicyNames list (no inline-policy
// storage in fakeaws yet — separate handler when needed).
func (app *Application) iamListRolePolicies(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("RoleName")
	if _, err := app.repo.GetRole(account, name); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "ListRolePolicies", &iamListRolePoliciesResult{PolicyNames: []string{}})
}

// iamListRoleTags mirrors ListRolePolicies: provider Read calls it
// post-create, default 404 breaks the apply loop. Returns an empty
// Tags list when the role exists.
func (app *Application) iamListRoleTags(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("RoleName")
	if _, err := app.repo.GetRole(account, name); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "ListRoleTags", &iamListRoleTagsResult{Tags: []iamTagXML{}})
}

// iamListInstanceProfilesForRole is called by terraform-provider-aws
// as part of the aws_iam_role Delete preflight: it checks for
// dependent instance profiles so the destroy ordering is correct.
// We model the real behavior — 404 when the role is missing,
// otherwise an empty InstanceProfiles list (fakeaws's CreateRole
// doesn't auto-attach an instance profile, and AddRoleToInstanceProfile
// stores the membership in instance-profile state, not role state).
func (app *Application) iamListInstanceProfilesForRole(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("RoleName")
	if _, err := app.repo.GetRole(account, name); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "ListInstanceProfilesForRole", &iamListInstanceProfilesForRoleResult{InstanceProfiles: []iamInstanceProfileXML{}})
}

type iamListRolePoliciesResult struct {
	PolicyNames []string `xml:"PolicyNames>member"`
	IsTruncated bool     `xml:"IsTruncated"`
}

type iamTagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type iamListRoleTagsResult struct {
	Tags        []iamTagXML `xml:"Tags>member"`
	IsTruncated bool        `xml:"IsTruncated"`
}

type iamListInstanceProfilesForRoleResult struct {
	InstanceProfiles []iamInstanceProfileXML `xml:"InstanceProfiles>member"`
	IsTruncated      bool                    `xml:"IsTruncated"`
}

// ----- helpers -----

func pathOrSlash(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func urlEscapeIfNotEmpty(s string) string {
	if s == "" {
		return s
	}
	// Real IAM URL-encodes the AssumeRolePolicyDocument in responses.
	// terraform-provider-aws tolerates either form; we URL-encode to
	// match the documented wire shape.
	return url.QueryEscape(s)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}
