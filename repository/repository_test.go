package repository

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	err = r.Restore(nil)
	if !errors.Is(err, models.ErrNotFound) {
		t.Errorf("Restore after Reset should return ErrNotFound, got %v", err)
	}
}

// TestNewRefusesAnotherSchemaVersion: a file db whose schema_version is
// not exactly one row, dbSchemaVersion, is refused naming the file and
// the stored and wanted versions. The file is left byte for byte as it
// was, in WAL or rollback-journal mode, and no -wal or -shm appears. A
// '?', '#' or '%' in the path is part of the file's name.
func TestNewRefusesAnotherSchemaVersion(t *testing.T) {
	cases := []struct {
		name, file, stored string
		stmts              []string
	}{
		{"older", "state.db", "1", []string{`UPDATE schema_version SET version = 1`}},
		{"older, rollback journal", "state.db", "1", []string{`PRAGMA journal_mode = DELETE`, `UPDATE schema_version SET version = 1`}},
		{"older, odd path", "state ?#%.db", "1", []string{`UPDATE schema_version SET version = 1`}},
		{"previous: route table associations without main", "state.db", fmt.Sprint(dbSchemaVersion - 1), []string{`DROP INDEX ec2_route_table_associations_one_main`, `ALTER TABLE ec2_route_table_associations DROP COLUMN main`, fmt.Sprintf(`UPDATE schema_version SET version = %d`, dbSchemaVersion-1)}},
		{"newer", "state.db", fmt.Sprint(dbSchemaVersion + 1), []string{fmt.Sprintf(`UPDATE schema_version SET version = %d`, dbSchemaVersion+1)}},
		{"no row", "state.db", "none", []string{`DELETE FROM schema_version`}},
		{"two rows", "state.db", fmt.Sprintf("1, %d", dbSchemaVersion), []string{`INSERT INTO schema_version (version) VALUES (1)`}},
		{"no table", "state.db", "none", []string{`DROP TABLE schema_version`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), c.file)
			r, err := New(dbPath)
			require.NoError(t, err)
			require.NoError(t, r.Close())
			execOnFile(t, dbPath, c.stmts...)
			require.NoFileExists(t, dbPath+"-wal")
			require.NoFileExists(t, dbPath+"-shm")
			before := sha256File(t, dbPath)

			_, err = New(dbPath)
			require.ErrorIs(t, err, models.ErrConflict)
			assert.Contains(t, err.Error(), fmt.Sprintf("%s: database schema version %s, fakeaws needs %d: reset or delete the file", dbPath, c.stored, dbSchemaVersion))
			assert.Equal(t, before, sha256File(t, dbPath), "the file is left as it was")
			assert.NoFileExists(t, dbPath+"-wal")
			assert.NoFileExists(t, dbPath+"-shm")
		})
	}
}

// killedDB copies the db at live and its -wal to dbPath, as a kill
// before any checkpoint would leave them: the tables only in the -wal.
func killedDB(t *testing.T, live *Repository, dbPath string) {
	t.Helper()
	require.NoError(t, copyFile(live.dbPath, dbPath))
	require.NoError(t, copyFile(live.dbPath+"-wal", dbPath+"-wal"))
}

// TestNewReadsTheVersionInTheWAL: a killed db's version is read from its
// -wal, through a symlink too. Version 1 is refused with the file and
// its -wal left as they were; the only file the refusal may add is a
// -shm. dbSchemaVersion opens.
func TestNewReadsTheVersionInTheWAL(t *testing.T) {
	for _, link := range []bool{false, true} {
		t.Run(fmt.Sprintf("symlink=%v", link), func(t *testing.T) {
			dir := t.TempDir()
			live, err := New(filepath.Join(dir, "live.db"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = live.Close() })
			current, older := filepath.Join(dir, "current.db"), filepath.Join(dir, "older.db")
			killedDB(t, live, current)
			_, err = live.db.Exec(`UPDATE schema_version SET version = 1`)
			require.NoError(t, err)
			killedDB(t, live, older)
			if link {
				for _, p := range []*string{&current, &older} {
					l := *p + ".link"
					require.NoError(t, os.Symlink(*p, l))
					*p = l
				}
			}
			file := filepath.Join(dir, "older.db")
			before, beforeWAL, beforeDir := sha256File(t, file), sha256File(t, file+"-wal"), dirNames(t, dir)

			_, err = New(older)
			require.ErrorIs(t, err, models.ErrConflict)
			assert.Contains(t, err.Error(), fmt.Sprintf("%s: database schema version 1, fakeaws needs %d", older, dbSchemaVersion))
			assert.Equal(t, before, sha256File(t, file), "the file is left as it was")
			assert.Equal(t, beforeWAL, sha256File(t, file+"-wal"), "the -wal is left as it was")
			assert.Subset(t, append(beforeDir, "older.db-shm"), dirNames(t, dir), "only a -shm may appear")

			r, err := New(current)
			require.NoError(t, err)
			t.Cleanup(func() { _ = r.Close() })
			assert.Equal(t, fmt.Sprint(dbSchemaVersion), storedVersion(t, r))
		})
	}
}

// TestNewWithAHotJournal: a db killed mid-transaction in rollback-journal
// mode has torn pages and a hot -journal. The check does not read the
// torn version 1: it fails naming the file, leaving the file and the
// -journal as they were, and once a read-write open rolls the journal
// back, the db opens at dbSchemaVersion.
func TestNewWithAHotJournal(t *testing.T) {
	dir := t.TempDir()
	live, dbPath := filepath.Join(dir, "live.db"), filepath.Join(dir, "killed.db")
	r, err := New(live)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	h, err := sql.Open("sqlite", dsn(live, ""))
	require.NoError(t, err)
	h.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = h.Close() })
	// A small cache spills the uncommitted update, version 1, into the
	// file, and its original page into the -journal.
	for _, stmt := range []string{`PRAGMA journal_mode = DELETE`, `PRAGMA cache_size = 10`, `BEGIN`, `UPDATE schema_version SET version = 1`} {
		_, err = h.Exec(stmt)
		require.NoError(t, err)
	}
	for i := 0; i < 400; i++ {
		_, err = h.Exec(`INSERT INTO audit (ts, account_id, method, path, status_code) VALUES ('t', 'a', 'GET', ?, 200)`, strings.Repeat("x", 4000))
		require.NoError(t, err)
	}
	require.NoError(t, copyFile(live, dbPath))
	require.NoError(t, copyFile(live+"-journal", dbPath+"-journal"))
	before, beforeJournal := sha256File(t, dbPath), sha256File(t, dbPath+"-journal")

	_, err = New(dbPath)
	require.Error(t, err)
	assert.NotErrorIs(t, err, models.ErrConflict, "the torn version is not read")
	assert.Contains(t, err.Error(), dbPath+": read schema")
	assert.Equal(t, before, sha256File(t, dbPath), "the file is left as it was")
	assert.Equal(t, beforeJournal, sha256File(t, dbPath+"-journal"), "the -journal is left as it was")

	execOnFile(t, dbPath, `SELECT 1`)
	r, err = New(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	assert.Equal(t, fmt.Sprint(dbSchemaVersion), storedVersion(t, r))
}

// TestNewFailedMigrateLeavesNewDBEmpty: migrate is one transaction, so
// a new file db it fails on keeps no table, and opens afterwards at
// dbSchemaVersion instead of being refused for a missing version row.
func TestNewFailedMigrateLeavesNewDBEmpty(t *testing.T) {
	saved := registeredMigrations
	t.Cleanup(func() { registeredMigrations = saved })
	registeredMigrations = append(append([]string(nil), saved...), `CREATE TABLE broken (`)
	dbPath := filepath.Join(t.TempDir(), "state.db")
	_, err := New(dbPath)
	require.ErrorContains(t, err, "migrate: CREATE TABLE broken (")
	registeredMigrations = saved

	r, err := New(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	assert.Equal(t, fmt.Sprint(dbSchemaVersion), storedVersion(t, r))
}

// TestNewFileDBAtSchemaVersion: a new file db is at dbSchemaVersion,
// reopens, and snapshot then restore succeeds.
func TestNewFileDBAtSchemaVersion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	r, err := New(dbPath)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprint(dbSchemaVersion), storedVersion(t, r))
	require.NoError(t, r.Close())

	r = restoreRepo(t, dbPath)
	require.NoError(t, r.Restore(nil))
	assert.Equal(t, []string{"vpc-snap"}, vpcIDs(t, r))
	assert.Equal(t, fmt.Sprint(dbSchemaVersion), storedVersion(t, r))
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

// execOnFile runs stmts on the db file at path and closes it.
func execOnFile(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", dsn(path, ""))
	require.NoError(t, err)
	for _, stmt := range stmts {
		_, err = db.Exec(stmt)
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())
}

// storedVersion is every schema_version row of r, comma-separated.
func storedVersion(t *testing.T, r *Repository) string {
	t.Helper()
	var v string
	require.NoError(t, r.db.QueryRow(`SELECT group_concat(version, ', ') FROM schema_version`).Scan(&v))
	return v
}

// dirNames lists the names in dir.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func sha256File(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return sha256.Sum256(b)
}

type countingCache struct {
	name      string
	resets    int
	snapshots int
	restores  int
}

func (c *countingCache) Name() string            { return c.name }
func (c *countingCache) Reset() error            { c.resets++; return nil }
func (c *countingCache) Snapshot(_ string) error { c.snapshots++; return nil }
func (c *countingCache) Restore(_ string) error  { c.restores++; return nil }
