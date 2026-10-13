package handlers

// load_iam.go — the loaders of the IAM reader's role reads: GetRole,
// GetRolePolicy, ListRolePolicies, ListAttachedRolePolicies and
// ListInstanceProfilesForRole. Each writes through repository/load_iam.go
// and renders with its handler's encoder. Their rows' types:
//   - role: GetRole's role, with its tags.
//   - role-policy: GetRolePolicy's inline policy, id "<role>/<policy>"
//     (an IAM name holds no '/'), its document stored URL-decoded.
//   - role-policy-name: a ListRolePolicies name, id as role-policy's. It
//     writes no row, so loaded never counts it: it references the
//     role-policy GetRolePolicy loads, so a name no GetRolePolicy answered
//     is refused naming both.
//   - role-policy-attachment: an attached policy, id "<role>/<ARN>". A
//     customer-managed ARN is an unread policy reference (GetPolicy is
//     never read) and seeds no policy row.
//   - instance-profile: a ListInstanceProfilesForRole profile, bound to
//     the role its Roles holds.

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/repository"
)

// iamLoadNotFound are the codes an IAM read of nothing answers.
var iamLoadNotFound = []string{"NoSuchEntity"}

func init() {
	registerLoader(loader{key: LoadKey{"iam", "GetRole"}, table: "iam_roles", typ: "role", notFound: iamLoadNotFound,
		decode: loadGetRole, render: renderGetRole})
	registerLoader(loader{key: LoadKey{"iam", "GetRolePolicy"}, table: "role_inline_policies", typ: "role-policy", notFound: iamLoadNotFound,
		decode: loadGetRolePolicy, render: renderGetRolePolicy})
	registerLoader(iamListLoader("ListRolePolicies", "role_inline_policies", loadListRolePolicies, renderListRolePolicies))
	registerLoader(iamListLoader("ListAttachedRolePolicies", "role_policy_attachments", loadListAttachedRolePolicies, renderListAttachedRolePolicies))
	registerLoader(iamListLoader("ListInstanceProfilesForRole", "iam_instance_profiles", loadListInstanceProfilesForRole, renderListInstanceProfilesForRole))
	registerIgnores(IgnoreEntry{Key: LoadKey{"iam", "GetRole"}, Path: "GetRoleResult/Role/RoleLastUsed",
		Cite: "terraform-provider-aws@v5.100.0/internal/service/iam/role.go"})
	// fakeaws answers a document in its own encoding (urlEscapeIfNotEmpty),
	// which need not be the one IAM recorded.
	registerEncoded(
		EncodedEntry{Key: LoadKey{"iam", "GetRole"}, Path: "GetRoleResult/Role/AssumeRolePolicyDocument"},
		EncodedEntry{Key: LoadKey{"iam", "GetRolePolicy"}, Path: "GetRolePolicyResult/PolicyDocument"},
		EncodedEntry{Key: LoadKey{"iam", "ListInstanceProfilesForRole"},
			Path: "ListInstanceProfilesForRoleResult/InstanceProfiles/member/Roles/member/AssumeRolePolicyDocument"},
	)
}

// iamListLoader is a loader of an IAM list, paged by Marker while
// IsTruncated.
func iamListLoader(action, table string, decode func(*loadEnvelope, *loadExchange) ([]loadItem, error), render func(*repository.LoadTx, []string) ([]byte, error)) loader {
	return loader{key: LoadKey{"iam", action}, table: table, decode: decode, render: render,
		requestToken: "Marker", responseToken: "Marker", truncated: "IsTruncated"}
}

func loadGetRole(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body struct {
		Role iamRoleXML `xml:"GetRoleResult>Role"`
	}
	if err := xml.Unmarshal([]byte(ex.Body), &body); err != nil {
		return nil, err
	}
	r := body.Role
	// A role is keyed by its name, and its tags by its ARN.
	if err := iamMissingKey("GetRoleResult/Role", [2]string{"RoleName", r.RoleName}, [2]string{"Arn", r.Arn}); err != nil {
		return nil, err
	}
	doc, err := url.QueryUnescape(r.AssumeRolePolicyDocument)
	if err != nil {
		return nil, loadRefusal("role " + r.RoleName + ": AssumeRolePolicyDocument is not URL-encoded")
	}
	role := &repository.IAMRole{
		Name: r.RoleName, Path: r.Path, ARN: r.Arn, RoleID: r.RoleId, AssumeRolePolicyDocument: doc,
		Description: r.Description, MaxSessionDuration: r.MaxSessionDuration, CreatedAt: r.CreateDate,
	}
	item := loadItem{loadRef: loadRef{"role", r.RoleName}, Path: "GetRoleResult/Role"}
	if b := r.PermissionsBoundary; b != nil {
		role.PermissionsBoundary = &repository.IAMPermissionsBoundary{Type: b.PermissionsBoundaryType, ARN: b.PermissionsBoundaryArn}
		item.Refs = iamPolicyRefs(b.PermissionsBoundaryArn)
	}
	tags := map[string]string{}
	for _, t := range r.Tags {
		tags[t.Key] = t.Value
	}
	item.write = func(tx *repository.LoadTx) error { return tx.LoadRole(env.Account, role, tags) }
	return []loadItem{item}, nil
}

func renderGetRole(tx *repository.LoadTx, ids []string) ([]byte, error) {
	role, tags, err := tx.LoadedRole(ids[0])
	if err != nil || role == nil {
		return nil, errors.Join(err, errors.New("no role stored"))
	}
	r := roleToXML(role)
	r.Tags = iamTags(tags)
	return awsproto.QueryRPCResponse("GetRole", &iamRoleResult{Role: r}), nil
}

func loadGetRolePolicy(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body struct {
		Result iamGetRolePolicyResult `xml:"GetRolePolicyResult"`
	}
	if err := xml.Unmarshal([]byte(ex.Body), &body); err != nil {
		return nil, err
	}
	p := body.Result
	if p.RoleName == "" || p.PolicyName == "" {
		return nil, loadRefusal("GetRolePolicyResult holds no RoleName or no PolicyName")
	}
	id := p.RoleName + "/" + p.PolicyName
	doc, err := url.QueryUnescape(p.PolicyDocument)
	if err != nil {
		return nil, loadRefusal("role-policy " + id + ": PolicyDocument is not URL-encoded")
	}
	return []loadItem{{loadRef: loadRef{"role-policy", id}, Path: "GetRolePolicyResult",
		write: iamUnderRole(env, "role-policy "+id, p.RoleName, func(tx *repository.LoadTx) error {
			return tx.LoadRolePolicy(env.Account, p.RoleName, p.PolicyName, doc)
		})}}, nil
}

func renderGetRolePolicy(tx *repository.LoadTx, ids []string) ([]byte, error) {
	role, name, _ := strings.Cut(ids[0], "/")
	doc, ok, err := tx.LoadedRolePolicy(role, name)
	if err != nil || !ok {
		return nil, errors.Join(err, errors.New("no role policy stored"))
	}
	return awsproto.QueryRPCResponse("GetRolePolicy", &iamGetRolePolicyResult{
		RoleName: role, PolicyName: name, PolicyDocument: urlEscapeIfNotEmpty(doc),
	}), nil
}

func loadListRolePolicies(_ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body struct {
		Names []string `xml:"ListRolePoliciesResult>PolicyNames>member"`
	}
	role, err := iamListBody(ex, &body)
	if err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.Names))
	for i, name := range body.Names {
		id := role + "/" + name
		items[i] = loadItem{loadRef: loadRef{"role-policy-name", id}, Path: "ListRolePoliciesResult/PolicyNames/member", Index: i,
			Refs: []loadReference{{loadRef: loadRef{"role-policy", id}}}}
	}
	return items, nil
}

// renderListRolePolicies answers each id's name that role_inline_policies
// holds.
func renderListRolePolicies(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := iamListRolePoliciesResult{PolicyNames: []string{}}
	for _, id := range ids {
		role, name, _ := strings.Cut(id, "/")
		_, ok, err := tx.LoadedRolePolicy(role, name)
		if err != nil {
			return nil, err
		}
		if ok {
			out.PolicyNames = append(out.PolicyNames, name)
		}
	}
	return awsproto.QueryRPCResponse("ListRolePolicies", &out), nil
}

func loadListAttachedRolePolicies(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body struct {
		Policies []iamAttachedPolicy `xml:"ListAttachedRolePoliciesResult>AttachedPolicies>member"`
	}
	role, err := iamListBody(ex, &body)
	if err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.Policies))
	for i, p := range body.Policies {
		id := role + "/" + p.PolicyArn
		items[i] = loadItem{loadRef: loadRef{"role-policy-attachment", id}, Path: "ListAttachedRolePoliciesResult/AttachedPolicies/member", Index: i,
			Refs: iamPolicyRefs(p.PolicyArn),
			write: iamUnderRole(env, "role-policy-attachment "+id, role, func(tx *repository.LoadTx) error {
				return tx.LoadRolePolicyAttachment(env.Account, role, p.PolicyArn)
			})}
	}
	return items, nil
}

func renderListAttachedRolePolicies(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := iamListAttachedRolePoliciesResult{AttachedPolicies: []iamAttachedPolicy{}}
	for _, id := range ids {
		role, arn, _ := strings.Cut(id, "/")
		ok, err := tx.RolePolicyAttached(role, arn)
		if err != nil {
			return nil, err
		}
		if ok {
			out.AttachedPolicies = append(out.AttachedPolicies, iamAttachedPolicyOf(arn))
		}
	}
	return awsproto.QueryRPCResponse("ListAttachedRolePolicies", &out), nil
}

func loadListInstanceProfilesForRole(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body struct {
		Profiles []iamInstanceProfileXML `xml:"ListInstanceProfilesForRoleResult>InstanceProfiles>member"`
	}
	if _, err := iamListBody(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.Profiles))
	for i, p := range body.Profiles {
		// A profile is keyed by its name, and its tags by its ARN.
		if err := iamMissingKey("ListInstanceProfilesForRoleResult/InstanceProfiles/member",
			[2]string{"InstanceProfileName", p.InstanceProfileName}, [2]string{"Arn", p.Arn}); err != nil {
			return nil, err
		}
		profile := &repository.IAMInstanceProfile{Name: p.InstanceProfileName, Path: p.Path, ARN: p.Arn, ID: p.InstanceProfileId, CreatedAt: p.CreateDate}
		write := func(tx *repository.LoadTx) error { return tx.LoadInstanceProfile(env.Account, profile, "") }
		// A profile holds one role; the diff refuses any other its Roles holds.
		if len(p.Roles) > 0 {
			role := p.Roles[0].RoleName
			write = iamUnderRole(env, "instance-profile "+profile.Name, role, func(tx *repository.LoadTx) error {
				return tx.LoadInstanceProfile(env.Account, profile, role)
			})
		}
		items[i] = loadItem{loadRef: loadRef{"instance-profile", profile.Name}, Path: "ListInstanceProfilesForRoleResult/InstanceProfiles/member", Index: i,
			write: write}
	}
	return items, nil
}

func renderListInstanceProfilesForRole(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := iamListInstanceProfilesForRoleResult{InstanceProfiles: []iamInstanceProfileXML{}}
	for _, id := range ids {
		p, err := tx.LoadedInstanceProfile(id)
		if err != nil || p == nil {
			return nil, errors.Join(err, errors.New("no instance profile stored"))
		}
		var role *repository.IAMRole
		if p.AttachedRole != "" {
			if role, _, err = tx.LoadedRole(p.AttachedRole); err != nil {
				return nil, err
			}
		}
		out.InstanceProfiles = append(out.InstanceProfiles, instanceProfileToXML(p, role))
	}
	return awsproto.QueryRPCResponse("ListInstanceProfilesForRole", &out), nil
}

// iamMissingKey refuses the first of fields, each a name and its
// value, in order, whose value is empty, naming it under path.
func iamMissingKey(path string, fields ...[2]string) error {
	for _, f := range fields {
		if f[1] == "" {
			return loadRefusal(path + " holds no " + f[0])
		}
	}
	return nil
}

// iamListBody decodes ex's body into body and returns the role its
// params name, refusing an exchange whose params name none.
func iamListBody(ex *loadExchange, body any) (string, error) {
	params, _ := ex.Params.(map[string]any)
	role, _ := params["RoleName"].(string)
	if role == "" {
		return "", loadRefusal("its params name no RoleName")
	}
	return role, xml.Unmarshal([]byte(ex.Body), body)
}

// iamUnderRole is a write of what (its type and id) that refuses, naming
// role, unless the load stored role, so it never fails role's foreign
// key.
func iamUnderRole(env *loadEnvelope, what, role string, write func(*repository.LoadTx) error) func(*repository.LoadTx) error {
	return func(tx *repository.LoadTx) error {
		ok, err := tx.RoleLoaded(env.Account, role)
		if err != nil {
			return err
		}
		if !ok {
			return loadRefusal(fmt.Sprintf("%s names role %s, which no exchange loaded", what, role))
		}
		return write(tx)
	}
}

// iamPolicyRefs is the reference a policy ARN makes: none for an
// AWS-managed policy, which every account holds, and an unread one for a
// customer-managed policy, which the reader never reads.
func iamPolicyRefs(arn string) []loadReference {
	if strings.HasPrefix(arn, iamAWSManagedPolicyPrefix) {
		return nil
	}
	return []loadReference{{loadRef: loadRef{"policy", arn}, Unread: true}}
}
