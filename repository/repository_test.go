package repository

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

// TestRepositoryAdminLifecycle pins reset/snapshot/restore against a
// file-backed db. Mirrors fakegcp's TestResetClearsDNSChangeCache —
// the lifecycle MUST cover both SQLite state and any in-process cache
// registered via RegisterCache.
func TestRepositoryAdminLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	r, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	// Register a fake cache to assert the hook fires across all three
	// lifecycle methods.
	cache := &countingCache{name: "fake"}
	r.RegisterCache(cache)

	// Audit table starts empty; insert a row to give snapshot
	// something to capture.
	if _, err := r.db.Exec(`INSERT INTO audit (ts, account_id, region, method, path, status_code) VALUES (datetime('now'), '000000000000', 'us-east-1', 'GET', '/iam/roles/foo', 200)`); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}

	// Snapshot the seeded state.
	if err := r.Snapshot(); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if cache.snapshots != 1 {
		t.Errorf("expected cache.Snapshot called once, got %d", cache.snapshots)
	}

	// Mutate: add a second audit row.
	if _, err := r.db.Exec(`INSERT INTO audit (ts, account_id, region, method, path, status_code) VALUES (datetime('now'), '000000000000', 'us-east-1', 'POST', '/iam/roles', 201)`); err != nil {
		t.Fatalf("seed audit row 2: %v", err)
	}

	// Reset: wipes BOTH rows AND clears the snapshot baseline so
	// Restore won't resurrect them.
	if err := r.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if cache.resets != 1 {
		t.Errorf("expected cache.Reset called once, got %d", cache.resets)
	}
	var n int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM audit`).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if n != 0 {
		t.Errorf("expected audit empty after Reset, got %d rows", n)
	}

	// Restore must NOT resurrect the seeded row because Reset cleared
	// the snapshot baseline (concepts.md "Standing patterns" — the
	// pass-18 cache-baseline lifecycle invariant).
	err = r.Restore()
	if !errors.Is(err, models.ErrNotFound) {
		t.Errorf("Restore after Reset should return ErrNotFound, got %v", err)
	}
}

func TestNewMemoryDBSnapshotIsConflict(t *testing.T) {
	r, err := New(":memory:")
	if err != nil {
		t.Fatalf("New :memory:: %v", err)
	}
	defer r.Close()

	if err := r.Snapshot(); err == nil {
		t.Errorf("Snapshot should refuse :memory: db")
	} else if !errors.Is(err, models.ErrConflict) {
		t.Errorf("expected ErrConflict, got %v", err)
	}
}

func TestRegisterCacheIsIdempotent(t *testing.T) {
	r, err := New(":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	c := &countingCache{name: "twice"}
	r.RegisterCache(c)
	r.RegisterCache(c)

	if got := len(r.caches); got != 1 {
		t.Errorf("RegisterCache should be idempotent; got %d entries", got)
	}
}

func TestResolveSameAccountName(t *testing.T) {
	const acct = "000000000000"
	const other = "999999999999"

	cases := []struct {
		name       string
		ref        string
		collection string
		want       string
		wantErr    bool
	}{
		{"empty", "", "role", "", false},
		{"bare-name", "admin", "role", "admin", false},
		{"iam-role-arn", "arn:aws:iam::" + acct + ":role/admin", "role", "admin", false},
		{"iam-policy-arn", "arn:aws:iam::" + acct + ":policy/p1", "policy", "p1", false},
		// S3 ARN has empty account segment — global, not cross-account.
		{"s3-bucket-arn", "arn:aws:s3:::my-bucket", "", "my-bucket", false},
		// Route53 too.
		{"route53-zone-arn", "arn:aws:route53:::hostedzone/Z123", "hostedzone", "Z123", false},
		// Cross-account ARN must reject.
		{"cross-account-iam", "arn:aws:iam::" + other + ":role/admin", "role", "", true},
		// RDS uses ':' separator instead of '/'.
		{"rds-db-arn", "arn:aws:rds:us-east-1:" + acct + ":db:mydb", "db", "mydb", false},
		// Wrong collection in ARN must reject (pass-28 fakegcp finding).
		{"wrong-collection", "arn:aws:iam::" + acct + ":policy/p1", "role", "", true},
		// Self-link / partial path returns trailing segment.
		{"path-style", "iam/roles/admin", "", "admin", false},
		{"malformed-arn", "arn:aws:iam:partial", "role", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveSameAccountName(acct, c.ref, c.collection)
			if c.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestPatchMergeShallowOverrides(t *testing.T) {
	base := map[string]any{
		"name":        "foo",
		"description": "old",
		"id":          "id-1",
	}
	patch := map[string]any{
		"description": "new",
		"id":          "id-attempt",
	}
	merged := PatchMerge(base, patch, "id")

	if merged["description"] != "new" {
		t.Errorf("description should be overwritten: %v", merged)
	}
	if merged["id"] != "id-1" {
		t.Errorf("id should be preserved (immutable skip-list): %v", merged)
	}
	if merged["name"] != "foo" {
		t.Errorf("name should be preserved: %v", merged)
	}
}

func TestPatchMergeNestedRecursive(t *testing.T) {
	base := map[string]any{
		"settings": map[string]any{
			"tier":    "small",
			"backups": true,
		},
	}
	patch := map[string]any{
		"settings": map[string]any{
			"tier": "large",
		},
	}
	merged := PatchMerge(base, patch)
	settings, ok := merged["settings"].(map[string]any)
	if !ok {
		t.Fatalf("settings should still be a map: %T", merged["settings"])
	}
	if settings["tier"] != "large" {
		t.Errorf("tier should be overwritten: %v", settings)
	}
	if settings["backups"] != true {
		t.Errorf("backups should be preserved: %v", settings)
	}
}

// ----- test helpers -----

type countingCache struct {
	name      string
	resets    int
	snapshots int
	restores  int
}

func (c *countingCache) Name() string                  { return c.name }
func (c *countingCache) Reset() error                  { c.resets++; return nil }
func (c *countingCache) Snapshot(_ string) error       { c.snapshots++; return nil }
func (c *countingCache) Restore(_ string) error        { c.restores++; return nil }
