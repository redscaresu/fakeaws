package repository

import (
	"errors"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

const testAccount = "000000000000"

func setupRepo(t *testing.T) *Repository {
	t.Helper()
	r, err := New(":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// ----- Roles -----

func TestRoleCRUD(t *testing.T) {
	r := setupRepo(t)
	role := &IAMRole{
		Name: "admin", Path: "/", ARN: "arn:aws:iam::000000000000:role/admin",
		AssumeRolePolicyDocument: `{"Version":"2012-10-17"}`, CreatedAt: "2026-04-27T12:00:00Z",
	}

	if err := r.CreateRole(testAccount, role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	got, err := r.GetRole(testAccount, "admin")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.ARN != role.ARN {
		t.Errorf("ARN: got %q want %q", got.ARN, role.ARN)
	}

	if _, err := r.GetRole(testAccount, "missing"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("GetRole(missing) want ErrNotFound got %v", err)
	}

	roles, err := r.ListRoles(testAccount)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 1 {
		t.Errorf("ListRoles: got %d want 1", len(roles))
	}

	role.Description = "updated description"
	if err := r.UpdateRole(testAccount, role); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	got, _ = r.GetRole(testAccount, "admin")
	if got.Description != "updated description" {
		t.Errorf("UpdateRole did not persist Description: %q", got.Description)
	}

	if err := r.DeleteRole(testAccount, "admin"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if _, err := r.GetRole(testAccount, "admin"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("after Delete, GetRole should return ErrNotFound, got %v", err)
	}
}

func TestRoleCreateDuplicateConflicts(t *testing.T) {
	r := setupRepo(t)
	role := &IAMRole{Name: "x", Path: "/", ARN: "arn", CreatedAt: "t"}
	if err := r.CreateRole(testAccount, role); err != nil {
		t.Fatalf("first CreateRole: %v", err)
	}
	err := r.CreateRole(testAccount, role)
	if !errors.Is(err, models.ErrConflict) {
		t.Errorf("duplicate CreateRole should return ErrConflict, got %v", err)
	}
}

// ----- Policies + RolePolicyAttachment FK gates -----

func TestPolicyDeleteRefusesIfAttached(t *testing.T) {
	r := setupRepo(t)

	role := &IAMRole{Name: "r1", Path: "/", ARN: "arn:aws:iam::000000000000:role/r1", CreatedAt: "t"}
	if err := r.CreateRole(testAccount, role); err != nil {
		t.Fatal(err)
	}
	policy := &IAMPolicy{Name: "p1", Path: "/", ARN: "arn:aws:iam::000000000000:policy/p1", CreatedAt: "t"}
	if err := r.CreatePolicy(testAccount, policy); err != nil {
		t.Fatal(err)
	}

	// Attach.
	if err := r.AttachRolePolicy(testAccount, "r1", policy.ARN); err != nil {
		t.Fatalf("AttachRolePolicy: %v", err)
	}

	// DeletePolicy must refuse — policy is attached.
	err := r.DeletePolicy(testAccount, "p1")
	if !errors.Is(err, models.ErrInUse) {
		t.Errorf("DeletePolicy of attached policy: want ErrInUse, got %v", err)
	}

	// Detach, then delete succeeds.
	if err := r.DetachRolePolicy(testAccount, "r1", policy.ARN); err != nil {
		t.Fatalf("DetachRolePolicy: %v", err)
	}
	if err := r.DeletePolicy(testAccount, "p1"); err != nil {
		t.Errorf("DeletePolicy after detach: %v", err)
	}
}

func TestAttachRolePolicyValidatesBothEnds(t *testing.T) {
	r := setupRepo(t)

	// Missing role.
	err := r.AttachRolePolicy(testAccount, "nope", "arn:aws:iam::000000000000:policy/p")
	if !errors.Is(err, models.ErrNotFound) {
		t.Errorf("Attach with missing role: want ErrNotFound, got %v", err)
	}

	role := &IAMRole{Name: "r", Path: "/", ARN: "arn:aws:iam::000000000000:role/r", CreatedAt: "t"}
	if err := r.CreateRole(testAccount, role); err != nil {
		t.Fatal(err)
	}

	// Missing policy.
	err = r.AttachRolePolicy(testAccount, "r", "arn:aws:iam::000000000000:policy/missing")
	if !errors.Is(err, models.ErrNotFound) {
		t.Errorf("Attach with missing policy: want ErrNotFound, got %v", err)
	}
}

// ----- Roles cascade through role_policy_attachments -----

func TestDeleteRoleCascadesAttachments(t *testing.T) {
	r := setupRepo(t)
	role := &IAMRole{Name: "r", Path: "/", ARN: "arn:aws:iam::000000000000:role/r", CreatedAt: "t"}
	policy := &IAMPolicy{Name: "p", Path: "/", ARN: "arn:aws:iam::000000000000:policy/p", CreatedAt: "t"}
	if err := r.CreateRole(testAccount, role); err != nil {
		t.Fatal(err)
	}
	if err := r.CreatePolicy(testAccount, policy); err != nil {
		t.Fatal(err)
	}
	if err := r.AttachRolePolicy(testAccount, "r", policy.ARN); err != nil {
		t.Fatal(err)
	}

	if err := r.DeleteRole(testAccount, "r"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	// Attachment should be gone (CASCADE on role).
	attached, err := r.ListAttachedRolePolicies(testAccount, "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(attached) != 0 {
		t.Errorf("after DeleteRole, attachments should cascade: got %v", attached)
	}
	// Policy still exists (its FK is the policy, not the role).
	if _, err := r.GetPolicy(testAccount, "p"); err != nil {
		t.Errorf("policy should survive role delete: %v", err)
	}
}

// ----- Instance Profiles -----

func TestInstanceProfileAddRemoveRole(t *testing.T) {
	r := setupRepo(t)
	role := &IAMRole{Name: "r", Path: "/", ARN: "arn:aws:iam::000000000000:role/r", CreatedAt: "t"}
	prof := &IAMInstanceProfile{Name: "p", Path: "/", ARN: "arn:aws:iam::000000000000:instance-profile/p", CreatedAt: "t"}

	if err := r.CreateRole(testAccount, role); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateInstanceProfile(testAccount, prof); err != nil {
		t.Fatal(err)
	}
	if err := r.AddRoleToInstanceProfile(testAccount, "p", "r"); err != nil {
		t.Fatalf("AddRoleToInstanceProfile: %v", err)
	}

	got, err := r.GetInstanceProfile(testAccount, "p")
	if err != nil {
		t.Fatalf("GetInstanceProfile: %v", err)
	}
	if got.AttachedRole != "r" {
		t.Errorf("AttachedRole: got %q want r", got.AttachedRole)
	}

	if err := r.RemoveRoleFromInstanceProfile(testAccount, "p", "r"); err != nil {
		t.Fatalf("RemoveRoleFromInstanceProfile: %v", err)
	}
	got, _ = r.GetInstanceProfile(testAccount, "p")
	if got.AttachedRole != "" {
		t.Errorf("after remove, AttachedRole should be empty: %q", got.AttachedRole)
	}
}

func TestInstanceProfileWithRoleBlocksRoleDelete(t *testing.T) {
	r := setupRepo(t)
	if err := r.CreateRole(testAccount, &IAMRole{Name: "r", Path: "/", ARN: "arn", CreatedAt: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateInstanceProfile(testAccount, &IAMInstanceProfile{Name: "p", Path: "/", ARN: "arn2", CreatedAt: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddRoleToInstanceProfile(testAccount, "p", "r"); err != nil {
		t.Fatal(err)
	}

	// Real IAM rejects DeleteRole when an instance profile references it.
	// Our FK on instance_profile_roles uses RESTRICT for that reason.
	err := r.DeleteRole(testAccount, "r")
	if !errors.Is(err, models.ErrInUse) {
		t.Errorf("DeleteRole with instance-profile attachment: want ErrInUse, got %v", err)
	}
}

// ----- Users + Access Keys (CASCADE) -----

func TestUserAccessKeyCascade(t *testing.T) {
	r := setupRepo(t)
	user := &IAMUser{Name: "alice", Path: "/", ARN: "arn", CreatedAt: "t"}
	if err := r.CreateUser(testAccount, user); err != nil {
		t.Fatal(err)
	}

	key := &IAMAccessKey{ID: "AKIA0", UserName: "alice", Secret: "secret", Status: "Active", CreatedAt: "t"}
	if err := r.CreateAccessKey(testAccount, key); err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}

	keys, err := r.ListAccessKeys(testAccount, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("ListAccessKeys: got %d want 1", len(keys))
	}

	// CASCADE: deleting the user wipes the key.
	if err := r.DeleteUser(testAccount, "alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	keys, _ = r.ListAccessKeys(testAccount, "alice")
	if len(keys) != 0 {
		t.Errorf("CASCADE: ListAccessKeys after DeleteUser: got %d want 0", len(keys))
	}
}

func TestCreateAccessKeyForMissingUserIsNotFound(t *testing.T) {
	r := setupRepo(t)
	key := &IAMAccessKey{ID: "AKIA0", UserName: "ghost", Secret: "s", Status: "Active", CreatedAt: "t"}
	err := r.CreateAccessKey(testAccount, key)
	if !errors.Is(err, models.ErrNotFound) {
		t.Errorf("CreateAccessKey for missing user: want ErrNotFound got %v", err)
	}
}
