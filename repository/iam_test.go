package repository

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// ----- A managed-policy attachment blocks DeleteRole -----

// TestDeleteRoleRefusedWhileManagedPolicyAttached: IAM refuses
// DeleteRole while a managed policy is attached; the role, the
// attachment and the policy all stay.
func TestDeleteRoleRefusedWhileManagedPolicyAttached(t *testing.T) {
	r := setupRepo(t)
	policy := &IAMPolicy{Name: "p", Path: "/", ARN: "arn:aws:iam::000000000000:policy/p", CreatedAt: "t"}
	require.NoError(t, r.CreateRole(testAccount, &IAMRole{Name: "r", Path: "/", ARN: "arn:aws:iam::000000000000:role/r", CreatedAt: "t"}))
	require.NoError(t, r.CreatePolicy(testAccount, policy))
	require.NoError(t, r.AttachRolePolicy(testAccount, "r", policy.ARN))

	assert.ErrorIs(t, r.DeleteRole(testAccount, "r"), models.ErrInUse)
	_, err := r.GetRole(testAccount, "r")
	assert.NoError(t, err, "role kept")
	attached, err := r.ListAttachedRolePolicies(testAccount, "r")
	require.NoError(t, err)
	assert.Equal(t, []string{policy.ARN}, attached, "attachment kept")

	require.NoError(t, r.DetachRolePolicy(testAccount, "r", policy.ARN))
	require.NoError(t, r.DeleteRole(testAccount, "r"))
	_, err = r.GetPolicy(testAccount, "p")
	assert.NoError(t, err, "policy survives the role's delete")
	assert.ErrorIs(t, r.DeleteRole(testAccount, "r"), models.ErrNotFound, "a second delete")
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

// TestDeleteUserRefusedWhileHeld: IAM refuses DeleteUser while an
// access key, an inline policy or a managed-policy attachment remains;
// each alone blocks it and stays.
func TestDeleteUserRefusedWhileHeld(t *testing.T) {
	r := setupRepo(t)
	policy := &IAMPolicy{Name: "p", Path: "/", ARN: "arn:aws:iam::000000000000:policy/p", CreatedAt: "t"}
	require.NoError(t, r.CreatePolicy(testAccount, policy))
	for name, c := range map[string]struct{ hold, release func(user string) error }{
		"access key": {
			func(u string) error {
				return r.CreateAccessKey(testAccount, &IAMAccessKey{ID: "AKIA" + u, UserName: u, Secret: "s", Status: "Active", CreatedAt: "t"})
			},
			func(u string) error { return r.DeleteAccessKey(testAccount, u, "AKIA"+u) },
		},
		"inline policy": {
			func(u string) error { return r.PutUserPolicy(testAccount, u, "inline", "{}") },
			func(u string) error { return r.DeleteUserPolicy(testAccount, u, "inline") },
		},
		"managed policy": {
			func(u string) error { return r.AttachUserPolicy(testAccount, u, policy.ARN) },
			func(u string) error { return r.DetachUserPolicy(testAccount, u, policy.ARN) },
		},
	} {
		user := strings.ReplaceAll(name, " ", "-")
		require.NoError(t, r.CreateUser(testAccount, &IAMUser{Name: user, Path: "/", ARN: "arn:" + user, CreatedAt: "t"}), name)
		require.NoError(t, c.hold(user), name)

		assert.ErrorIs(t, r.DeleteUser(testAccount, user), models.ErrInUse, name)
		_, err := r.GetUser(testAccount, user)
		assert.NoError(t, err, "%s: user kept", name)

		require.NoError(t, c.release(user), "%s: the hold stayed", name)
		assert.NoError(t, r.DeleteUser(testAccount, user), name)
		assert.ErrorIs(t, r.DeleteUser(testAccount, user), models.ErrNotFound, "%s: a second delete", name)
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

// ----- Role inline policies -----

// TestRoleInlinePoliciesResetAndRestore: Reset empties
// role_inline_policies, and a restore holds exactly the policies the
// snapshot did.
func TestRoleInlinePoliciesResetAndRestore(t *testing.T) {
	r, err := New(filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	require.NoError(t, r.CreateRole(testAccount, &IAMRole{Name: "r", Path: "/", ARN: "arn:aws:iam::000000000000:role/r", CreatedAt: "t"}))
	require.NoError(t, r.PutRolePolicy(testAccount, "r", "first", "{}"))

	require.NoError(t, r.Snapshot())
	require.NoError(t, r.PutRolePolicy(testAccount, "r", "second", "{}"))
	require.NoError(t, r.Restore(nil))
	names, err := r.ListRolePolicies(testAccount, "r")
	require.NoError(t, err)
	assert.Equal(t, []string{"first"}, names, "restore holds exactly the snapshot's policies")

	require.NoError(t, r.Reset())
	var n int
	require.NoError(t, r.db.QueryRow(`SELECT COUNT(*) FROM role_inline_policies`).Scan(&n))
	assert.Zero(t, n, "Reset empties role_inline_policies")
}

// TestDeleteRoleRefusedWhileInlinePolicy: an inline policy blocks
// DeleteRole with ErrInUse and both stay.
func TestDeleteRoleRefusedWhileInlinePolicy(t *testing.T) {
	r := setupRepo(t)
	require.NoError(t, r.CreateRole(testAccount, &IAMRole{Name: "r", Path: "/", ARN: "arn:aws:iam::000000000000:role/r", CreatedAt: "t"}))
	require.NoError(t, r.PutRolePolicy(testAccount, "r", "p", "{}"))

	assert.ErrorIs(t, r.DeleteRole(testAccount, "r"), models.ErrInUse)
	_, err := r.GetRole(testAccount, "r")
	assert.NoError(t, err, "role kept")
	_, err = r.GetRolePolicy(testAccount, "r", "p")
	assert.NoError(t, err, "policy kept")

	require.NoError(t, r.DeleteRolePolicy(testAccount, "r", "p"))
	assert.NoError(t, r.DeleteRole(testAccount, "r"))
}

// TestDeletePolicyRacingAttachLeavesNoDanglingAttachment: DeletePolicy
// and Attach{Role,User}Policy each check and write in one statement, so
// however they interleave either the policy stays or nothing is
// attached to it.
func TestDeletePolicyRacingAttachLeavesNoDanglingAttachment(t *testing.T) {
	r := setupRepo(t)
	const holders, rounds = 4, 200
	for i := range holders {
		require.NoError(t, r.CreateRole(testAccount, &IAMRole{Name: fmt.Sprintf("r%d", i), Path: "/", ARN: fmt.Sprintf("arn:r%d", i), CreatedAt: "t"}))
		require.NoError(t, r.CreateUser(testAccount, &IAMUser{Name: fmt.Sprintf("u%d", i), Path: "/", ARN: fmt.Sprintf("arn:u%d", i), CreatedAt: "t"}))
	}
	for round := range rounds {
		name := fmt.Sprintf("p%d", round)
		arn := "arn:aws:iam::000000000000:policy/" + name
		require.NoError(t, r.CreatePolicy(testAccount, &IAMPolicy{Name: name, Path: "/", ARN: arn, CreatedAt: "t"}))
		start := make(chan struct{})
		var wg sync.WaitGroup
		run := func(f func() error, allowed ...error) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := f(); err != nil && !slices.ContainsFunc(allowed, func(a error) bool { return errors.Is(err, a) }) {
					t.Errorf("round %d: unexpected error %v", round, err)
				}
			}()
		}
		for i := range holders {
			run(func() error { return r.AttachRolePolicy(testAccount, fmt.Sprintf("r%d", i), arn) }, models.ErrNotFound)
			run(func() error { return r.AttachUserPolicy(testAccount, fmt.Sprintf("u%d", i), arn) }, models.ErrNotFound)
		}
		run(func() error {
			// Stagger the delete across the attaches, so in some rounds it
			// lands between an attach's check and its insert.
			for range round % 8 {
				runtime.Gosched()
			}
			return r.DeletePolicy(testAccount, name)
		}, models.ErrInUse)
		close(start)
		wg.Wait()

		var attached int
		require.NoError(t, r.db.QueryRow(`SELECT
			(SELECT COUNT(*) FROM role_policy_attachments WHERE policy_arn = ?) +
			(SELECT COUNT(*) FROM user_policy_attachments WHERE policy_arn = ?)`, arn, arn).Scan(&attached))
		if _, err := r.GetPolicy(testAccount, name); errors.Is(err, models.ErrNotFound) {
			assert.Zero(t, attached, "round %d: attachments to the deleted policy", round)
		} else {
			require.NoError(t, err)
		}
	}
}
