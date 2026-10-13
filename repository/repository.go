// Package repository is the SQLite-backed state engine for fakeaws.
//
// One *Repository owns one database/sql handle (modernc.org/sqlite,
// pure Go, no CGO). FK constraints are declared at the schema level
// for hierarchical resources. Resource bodies live in a JSON `data`
// column; FK-bearing identity columns are extracted as proper SQL
// columns so cross-resource FK validation works.
//
// Per concepts.md § "Lessons we are explicitly carrying over":
//   - SetMaxOpenConns(1) — mandatory for FK enforcement and :memory:
//     isolation across goroutines (otherwise FKs silently drop)
//   - PRAGMA foreign_keys = ON — per-connection, applied at Open
//   - Reset/Snapshot/Restore lifecycle covers the SQLite file AND any
//     in-process cache registered via RegisterCache (S46 SQS visibility
//     timeouts, S47 Route53 change-id cache will use this)
//
// In S43-T3 the repository ships only the universal bookkeeping tables
// (operations + audit). Service-specific schemas land per-service:
// IAM in S43-T5, S3 in S43-T7, etc. Each service ticket adds its
// CREATE TABLE statements to migrate() and its Reset() truncations.
package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	_ "modernc.org/sqlite"

	"github.com/redscaresu/fakeaws/models"
)

// Repository wraps the SQLite handle plus the in-process cache hooks.
type Repository struct {
	db     *sql.DB
	dbPath string

	// caches holds optional cleanup callbacks for in-process state
	// that must travel with the SQLite snapshot/restore lifecycle.
	// Each cache registers a (name, reset, snapshot, restore) tuple
	// at Repository construction; lifecycle methods iterate over the
	// list. S46-T4 (SQS visibility timeouts) and S47-T4 (Route53
	// change-id cache) will use this hook.
	cachesMu sync.Mutex
	caches   []Cache
}

// Cache is the interface in-process state must satisfy to ride the
// repository's reset/snapshot/restore lifecycle. Implementations must
// be safe to call from any goroutine.
type Cache interface {
	Name() string
	// Reset wipes the cache's state. Called from Repository.Reset.
	Reset() error
	// Snapshot captures current state. The repository's Snapshot()
	// method calls this for every registered cache before the
	// SQLite VACUUM INTO; cache implementations may write to a
	// separate file under dbPath+"-cache-<name>" to keep the
	// SQLite snapshot pure.
	Snapshot(dbPath string) error
	// Restore reverses a prior Snapshot. Called by Repository.Restore.
	Restore(dbPath string) error
}

// dbSchemaVersion is the schema_version a db fakeaws creates holds, and
// the only one it opens or restores (checkSchemaVersion). It is not
// /mock/state's schema_version (handlers/admin.go stateSchemaVersion).
// A change to an existing CREATE TABLE, index or trigger bumps it and
// regenerates testdata/schema.golden, which TestSchemaGolden checks:
// migrate only creates what is missing, so an older db would keep the
// old shape. An added table needs no bump; it is appended to the golden.
// Nor does a new data-JSON key, unless an old row read without it
// answers wrongly: 4 adds the VPC DNS attributes, which an older row
// would answer false. 5 lets a route table association be main, with
// no subnet, and gives routes their origin and state.
const dbSchemaVersion = 5

// New opens the SQLite database at dbPath, refuses it with
// models.ErrConflict unless it is new or at dbSchemaVersion, applies
// migrations, and returns the Repository. dbPath of ":memory:" is
// supported but snapshot/restore become no-ops since there's no on-disk
// file to VACUUM INTO. For e2e scenarios that want snapshot/restore, pass a
// filesystem path.
func New(dbPath string) (*Repository, error) {
	return newRepository(dbPath, dbPath)
}

// newRepository is New, with name the file a refusal names: stage opens
// a .restore copy and names the snapshot it copied.
func newRepository(dbPath, name string) (*Repository, error) {
	if err := checkSchemaVersion(dbPath, name); err != nil {
		return nil, err
	}
	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}
	r := &Repository{db: db, dbPath: dbPath}
	if err := r.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return r, nil
}

// openDB opens the SQLite handle with the mandatory pragmas. Used by
// New and by Restore (which closes and reopens after copying its
// prepared copy of the snapshot baseline into the live file).
func openDB(dbPath string) (*sql.DB, error) {
	// SQLite gives -wal and -shm the db file's mode, so a db created
	// 0600 here keeps all three owner-only. An existing db keeps its mode.
	if dbPath != ":memory:" {
		if err := createOwnerOnly(dbPath); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create db file: %w", err)
		}
	}
	db, err := sql.Open("sqlite", dsn(dbPath, ""))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SetMaxOpenConns(1) is mandatory, not a guideline. modernc/sqlite
	// is goroutine-safe but FK pragmas are per-connection — multi-conn
	// pools end up with FK constraints partially applied.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign_keys pragma: %w", err)
	}
	if dbPath != ":memory:" {
		// WAL mode is the right default for file-backed DBs but breaks
		// `:memory:` (which has no journal file). Skip it for in-mem.
		if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("enable WAL mode: %w", err)
		}
	}
	return db, nil
}

// dsn is the SQLite URI of the file at dbPath, taken literally (a '?'
// or a "file:" in it is part of the name), with query params; ":memory:"
// is itself. openDB and checkSchemaVersion both open through it, so they
// read the same file.
func dsn(dbPath, params string) string {
	if dbPath == ":memory:" {
		return dbPath
	}
	if abs, err := filepath.Abs(dbPath); err == nil {
		dbPath = abs
	}
	return (&url.URL{Scheme: "file", Path: dbPath, RawQuery: params}).String()
}

// universalMigrations are the always-on tables (operations, audit,
// schema_version). Service-specific tables append to
// registeredMigrations via init() in their own files (iam.go, s3.go,
// etc.).
var universalMigrations = []string{
	// Per concepts.md "Required surface" item 7: countOrphans must
	// ignore these tables on destroy (they're audit trails of API
	// calls, not user resources).
	`CREATE TABLE IF NOT EXISTS operations (
		id          TEXT NOT NULL PRIMARY KEY,
		account_id  TEXT NOT NULL,
		region      TEXT,
		service     TEXT NOT NULL,
		operation   TEXT NOT NULL,
		status      TEXT NOT NULL,
		started_at  TEXT NOT NULL,
		completed_at TEXT,
		data        TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS audit (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		ts          TEXT NOT NULL,
		account_id  TEXT NOT NULL,
		region      TEXT,
		method      TEXT NOT NULL,
		path        TEXT NOT NULL,
		status_code INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER NOT NULL PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`,
}

// checkSchemaVersion passes a db with no tables, which migrate makes
// new, and a db whose schema_version holds one row, dbSchemaVersion.
// Anything else is models.ErrConflict naming name and the stored and
// wanted versions. It reads dbPath through a read-only handle, before
// openDB's pragmas, so the file and any -wal or -journal are left as
// they were. The handle is immutable, and makes no file, unless a -wal
// or a -journal is there: a -wal may hold the db's only copy of its
// tables, as after a kill before any checkpoint, and beside one SQLite
// may make a -shm; a hot -journal means the file's pages may be torn,
// and a read-only handle cannot roll it back, so the check fails,
// naming the file, until a read-write open of it does.
func checkSchemaVersion(dbPath, name string) error {
	if dbPath == ":memory:" {
		return nil
	}
	// SQLite keeps the -wal and -journal beside the file a symlinked path
	// resolves to.
	file, err := filepath.EvalSymlinks(dbPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	params := "mode=ro&immutable=1"
	for _, suffix := range []string{"-wal", "-journal"} {
		if _, err := os.Stat(file + suffix); err == nil {
			params = "mode=ro"
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat db %s: %w", suffix, err)
		}
	}
	db, err := sql.Open("sqlite", dsn(file, params))
	if err != nil {
		return fmt.Errorf("open sqlite read-only: %w", err)
	}
	defer db.Close()
	var entries, versionTables int
	if err := db.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE type = 'table' AND name = 'schema_version') FROM sqlite_master`).
		Scan(&entries, &versionTables); err != nil {
		return fmt.Errorf("%s: read schema: %w", name, err)
	}
	if entries == 0 {
		return nil
	}
	stored := "none"
	if versionTables == 1 {
		if err := db.QueryRow(`SELECT COALESCE(group_concat(version, ', '), 'none') FROM schema_version`).Scan(&stored); err != nil {
			return fmt.Errorf("%s: read schema version: %w", name, err)
		}
	}
	if stored != strconv.Itoa(dbSchemaVersion) {
		return fmt.Errorf("%w: %s: database schema version %s, fakeaws needs %d: reset or delete the file",
			models.ErrConflict, name, stored, dbSchemaVersion)
	}
	return nil
}

// registeredMigrations holds service-specific CREATE TABLE statements
// appended via init() in per-service files (iam.go, s3.go, etc.).
// Initialized empty; tickets append in their own init().
var registeredMigrations []string

// migrate runs the universal migrations followed by every registered
// service migration, then stores dbSchemaVersion. Idempotent — every
// statement uses CREATE TABLE IF NOT EXISTS / INSERT OR IGNORE.
//
// It runs only on a db checkSchemaVersion passed: it adds a table the
// db lacks but changes none it has. It is one transaction, so a new db
// it fails on, or is killed in, is left with no tables, and opens as new.
func (r *Repository) migrate() error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmts := append([]string(nil), universalMigrations...)
	stmts = append(stmts, registeredMigrations...)
	stmts = append(stmts, fmt.Sprintf(`INSERT OR IGNORE INTO schema_version(version) VALUES (%d)`, dbSchemaVersion))
	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("migrate: %s: %w", oneLine(s), err)
		}
	}
	return tx.Commit()
}

func oneLine(s string) string {
	first := strings.SplitN(s, "\n", 2)[0]
	return strings.TrimSpace(first)
}

// Close releases the underlying SQLite handle. Safe to call from any
// goroutine; calling Close on an already-closed Repository is a no-op.
func (r *Repository) Close() error {
	if r.db == nil {
		return nil
	}
	err := r.db.Close()
	r.db = nil
	return err
}

// DB exposes the underlying *sql.DB for handler-level helpers that need
// it directly (cross-resource FK validation, transactional batched
// changes). Most code should use the typed Get/Create/etc. methods on
// the per-resource files.
func (r *Repository) DB() *sql.DB { return r.db }

// RegisterCache hooks an in-process cache into the lifecycle. The
// cache's Reset/Snapshot/Restore are called when the corresponding
// Repository methods fire. Idempotent — registering the same cache
// twice produces a single entry.
//
// S46-T4 (SQS visibility timeouts) will be the first caller; S47-T4
// (Route53 change-id cache) the second.
func (r *Repository) RegisterCache(c Cache) {
	if c == nil {
		return
	}
	r.cachesMu.Lock()
	defer r.cachesMu.Unlock()
	for _, existing := range r.caches {
		if existing.Name() == c.Name() {
			return
		}
	}
	r.caches = append(r.caches, c)
}

// resetTables holds the truncation order for Reset(). Each service
// appends its tables in dependency order (children before parents) so
// FK-OFF + DELETE doesn't trip even if a future change re-enables FKs
// during reset. Universal bookkeeping is reset last.
//
// Service tickets append to this list:
//
//	S43-T5 (IAM): role_policy_attachments, iam_access_keys, iam_users,
//	              iam_instance_profiles, iam_policies, iam_roles
//	S43-T7 (S3):  s3_bucket_configs, s3_buckets
//	S44 (EC2):    ... etc
var resetTables = []string{
	// Universal bookkeeping always reset last.
	"operations",
	"audit",
}

// prependResetTables inserts service-specific tables in front of the
// universal bookkeeping. Call from init() in per-service files;
// children come before parents so even a future Reset that runs FK-ON
// works without reordering.
func prependResetTables(tables []string) {
	resetTables = append(append([]string(nil), tables...), resetTables...)
}

// mapInsertError translates a SQLite INSERT error into the right
// domain sentinel. PRIMARY KEY conflicts → ErrConflict; FK violations
// → ErrNotFound (the referenced parent doesn't exist).
func mapInsertError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "UNIQUE constraint failed"),
		strings.Contains(msg, "PRIMARY KEY"):
		return fmt.Errorf("%w: %s", models.ErrConflict, msg)
	case strings.Contains(msg, "FOREIGN KEY"):
		return fmt.Errorf("%w: %s", models.ErrNotFound, msg)
	}
	return err
}

// mapDeleteError translates a SQLite DELETE error. FK violations on
// delete (RESTRICT clauses) map to ErrInUse, matching real AWS's
// "resource in use by another resource" reason.
func mapDeleteError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "FOREIGN KEY") {
		return fmt.Errorf("%w: %s", models.ErrInUse, err.Error())
	}
	return err
}

// Reset wipes every table in resetTables, removes the snapshot
// baseline so a subsequent Restore cannot resurrect pre-reset state,
// and calls Reset on every registered in-process cache.
//
// Per concepts.md "Standing patterns" item "Cache-baseline lifecycle":
// any in-process cache MUST clear and snapshot/restore alongside the
// SQLite repo. Reset() and Restore() touch caches in the same call so
// callers can't accidentally leave them out of sync.
func (r *Repository) Reset() error {
	r.cachesMu.Lock()
	caches := append([]Cache(nil), r.caches...)
	r.cachesMu.Unlock()

	if _, err := r.db.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		return err
	}
	defer func() { _, _ = r.db.Exec("PRAGMA foreign_keys = ON") }()

	for _, table := range resetTables {
		if _, err := r.db.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("reset %s: %w", table, err)
		}
	}

	// Resolve the snapshot path BEFORE clearing caches so any path-
	// resolution failure surfaces with state intact.
	if r.dbPath != ":memory:" {
		snap := r.dbPath + ".snapshot"
		if err := os.Remove(snap); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove snapshot baseline: %w", err)
		}
	}

	for _, c := range caches {
		if err := c.Reset(); err != nil {
			return fmt.Errorf("reset cache %s: %w", c.Name(), err)
		}
	}
	return nil
}

// Snapshot writes a deterministic baseline of the current SQLite state
// to <dbPath>.snapshot: VACUUM INTO <dbPath>.snapshot.tmp, then a
// rename, so Restore never reads a partial file. Each registered cache's
// Snapshot is called too. Caller responsible for ensuring no
// concurrent writes are happening.
//
// Returns models.ErrConflict if the database is in-memory (snapshot
// is meaningless without an on-disk file).
func (r *Repository) Snapshot() error {
	if r.dbPath == ":memory:" {
		return fmt.Errorf("snapshot requires file-backed db, got :memory:: %w", models.ErrConflict)
	}
	snap := r.dbPath + ".snapshot"
	if err := os.MkdirAll(filepath.Dir(snap), 0o755); err != nil {
		return err
	}
	if err := os.Remove(snap); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale snapshot: %w", err)
	}
	if _, err := r.db.Exec("PRAGMA wal_checkpoint(FULL)"); err != nil {
		return fmt.Errorf("wal_checkpoint: %w", err)
	}
	// VACUUM INTO would create its target 0644; it accepts an empty
	// existing one, so create that 0600 first. The target is a .tmp
	// because an empty or partial file at snap, left by an error or a
	// kill mid-VACUUM, would pass Restore's Stat and be copied over
	// the live db. The rename keeps the 0600.
	tmp := snap + ".tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale snapshot tmp: %w", err)
	}
	if err := createOwnerOnly(tmp); err != nil {
		return fmt.Errorf("create snapshot tmp: %w", err)
	}
	if err := VacuumInto(r.db, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vacuum into: %w", err)
	}
	if err := os.Rename(tmp, snap); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename snapshot tmp: %w", err)
	}

	r.cachesMu.Lock()
	caches := append([]Cache(nil), r.caches...)
	r.cachesMu.Unlock()
	for _, c := range caches {
		if err := c.Snapshot(r.dbPath); err != nil {
			return fmt.Errorf("snapshot cache %s: %w", c.Name(), err)
		}
	}
	return nil
}

// Restore reverses a prior Snapshot: copies the snapshot baseline to
// <dbPath>.restore, opens that copy as New does, which refuses it with
// models.ErrConflict, naming the snapshot, unless it is at
// dbSchemaVersion, runs prepare (nil for none) on it, then closes the
// live db, copies the prepared bytes into the live path, reopens, and
// re-applies migrations. The live path
// is written, never replaced, so a symlinked db or a bind-mounted single
// file keeps working. A refused copy, a failed copy or a failed prepare
// leaves the live db as it was, and the .restore files are removed
// either way. Returns models.ErrNotFound if no baseline exists.
func (r *Repository) Restore(prepare func(staged *Repository) error) error {
	if r.dbPath == ":memory:" {
		return fmt.Errorf("restore requires file-backed db, got :memory:: %w", models.ErrConflict)
	}
	snap := r.dbPath + ".snapshot"
	if _, err := os.Stat(snap); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return models.ErrNotFound
		}
		return err
	}
	staged := r.dbPath + ".restore"
	defer removeDBFiles(staged)
	if err := stage(snap, staged, prepare); err != nil {
		return err
	}

	if err := r.db.Close(); err != nil {
		return fmt.Errorf("close before restore: %w", err)
	}
	if err := copyFile(staged, r.dbPath); err != nil {
		// Try to reopen so the repository is at least usable.
		if reopened, openErr := openDB(r.dbPath); openErr == nil {
			r.db = reopened
		}
		return fmt.Errorf("copy restored db over live db: %w", err)
	}
	// Best-effort: clear WAL/SHM journals from the previous handle so
	// the new handle starts fresh.
	_ = os.Remove(r.dbPath + "-wal")
	_ = os.Remove(r.dbPath + "-shm")

	db, err := openDB(r.dbPath)
	if err != nil {
		return fmt.Errorf("reopen after restore: %w", err)
	}
	r.db = db
	if err := r.migrate(); err != nil {
		return fmt.Errorf("migrate after restore: %w", err)
	}

	r.cachesMu.Lock()
	caches := append([]Cache(nil), r.caches...)
	r.cachesMu.Unlock()
	for _, c := range caches {
		if err := c.Restore(r.dbPath); err != nil {
			return fmt.Errorf("restore cache %s: %w", c.Name(), err)
		}
	}
	return nil
}

// stage copies snap to staged, opens it as New does, which refuses it,
// naming snap, unless it is at dbSchemaVersion, and runs prepare (if
// any) on it, then checkpoints the copy's WAL into its file, which is
// all Restore copies, and fails unless every frame was checkpointed.
func stage(snap, staged string, prepare func(*Repository) error) error {
	removeDBFiles(staged)
	if err := copyFile(snap, staged); err != nil {
		return fmt.Errorf("copy snapshot: %w", err)
	}
	repo, err := newRepository(staged, snap)
	if err != nil {
		return fmt.Errorf("open restored copy: %w", err)
	}
	if prepare != nil {
		err = prepare(repo)
	}
	if err == nil {
		err = checkpointAll(repo.db)
	}
	return errors.Join(err, repo.Close())
}

// checkpointAll moves every WAL frame of db into its file and truncates
// the WAL, and is an error unless all of them moved.
func checkpointAll(db *sql.DB) error {
	var busy, logFrames, checkpointed int
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil {
		return fmt.Errorf("checkpoint restored copy: %w", err)
	}
	if busy != 0 || logFrames != checkpointed {
		return fmt.Errorf("checkpoint restored copy: busy=%d, %d of %d WAL frames checkpointed", busy, checkpointed, logFrames)
	}
	return nil
}

// removeDBFiles removes a db file and its WAL, shared-memory and
// rollback-journal files. A kill while stage's openDB switches a copy
// to WAL can leave its -journal hot, which checkSchemaVersion refuses.
func removeDBFiles(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		_ = os.Remove(p)
	}
}

// VacuumInto writes db to the empty file dst. A var so a test can make
// Snapshot's VACUUM fail.
var VacuumInto = func(db *sql.DB, dst string) error {
	_, err := db.Exec(fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(dst, "'", "''")))
	return err
}

// createOwnerOnly creates path empty and 0600; fs.ErrExist if it exists.
func createOwnerOnly(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// copyFile copies src over dst; a dst it creates is 0600.
func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o600)
}

// ----- Cross-resource FK helpers -----

// ResolveSameAccountName parses a per-service AWS reference (which may
// be a bare name, a partial path, or a full ARN) and returns the
// resource name iff the embedded account-id matches the request
// account. Mirror of fakegcp's resolveSameProjectName helper.
//
// Real AWS rejects cross-account references in most APIs (you can't
// e.g. delete an IAM role in another account by passing its ARN); we
// surface the rejection as models.ErrNotFound to match what the SDK
// expects.
//
// If ref is a bare name (no '/' or ':'), it's returned unchanged.
// If ref is an ARN, its account segment must match `account` or the
// helper returns models.ErrNotFound.
//
// Per concepts.md "Standing patterns" item "Cross-account FK rejection".
// The pass-28 wrong-collection refinement is tested below.
func ResolveSameAccountName(account, ref, collection string) (string, error) {
	if ref == "" {
		return "", nil
	}
	// Bare names — no path, no ARN, just an identifier.
	if !strings.ContainsAny(ref, "/:") {
		return ref, nil
	}
	// ARN form: arn:aws:<service>:<region>:<account>:<resource-type>/<id>
	// or :<resource-type>:<id> (RDS uses ':' separator).
	if strings.HasPrefix(ref, "arn:aws:") {
		parts := strings.SplitN(ref, ":", 6)
		if len(parts) < 6 {
			return "", fmt.Errorf("malformed ARN: %s: %w", ref, models.ErrNotFound)
		}
		arnAccount := parts[4]
		// Some services (S3, Route53) emit ARNs with empty account
		// segments — those are global resources, not cross-account.
		if arnAccount != "" && arnAccount != account {
			return "", models.ErrNotFound
		}
		// parts[5] is "<resource-type>/<id>" or "<resource-type>:<id>"
		// or just "<id>" depending on service. Find the trailing
		// identifier and assert the resource-type segment matches the
		// expected collection if one was provided.
		tail := parts[5]
		if collection != "" {
			if !strings.HasPrefix(tail, collection+"/") && !strings.HasPrefix(tail, collection+":") && tail != collection {
				return "", fmt.Errorf("ARN resource-type does not match expected collection %q: %s: %w", collection, ref, models.ErrNotFound)
			}
		}
		// Strip "<collection>/" or "<collection>:" prefix if present.
		for _, sep := range []string{collection + "/", collection + ":"} {
			if collection != "" && strings.HasPrefix(tail, sep) {
				tail = strings.TrimPrefix(tail, sep)
				break
			}
		}
		return tail, nil
	}
	// Self-link or relative path: pull off the trailing segment.
	tail := ref
	if i := strings.LastIndex(tail, "/"); i >= 0 {
		tail = tail[i+1:]
	}
	if i := strings.LastIndex(tail, ":"); i >= 0 {
		tail = tail[i+1:]
	}
	if tail == "" {
		return "", fmt.Errorf("could not extract name from ref %q: %w", ref, models.ErrNotFound)
	}
	// URL-decode in case the caller passed a percent-encoded reference.
	if decoded, err := url.QueryUnescape(tail); err == nil {
		tail = decoded
	}
	return tail, nil
}

// PatchMerge merges patch into base and returns the result. Used by
// Update handlers — per concepts.md "Standing patterns" item "Post-
// merge PATCH validation", FK validators run on the MERGED state, not
// the raw patch. This helper exists so every caller produces the
// same merged shape for validation.
//
// Skip-list fields are removed from the patch before merging, so
// callers can't smuggle in immutable fields (id, arn, creationTime).
//
// Both base and patch are flat maps from JSON decoding. Nested fields
// are merged recursively when both sides are map[string]any; otherwise
// the patch value wins.
func PatchMerge(base, patch map[string]any, skipImmutable ...string) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	merged := make(map[string]any, len(base))
	for k, v := range base {
		merged[k] = v
	}
	skip := make(map[string]struct{}, len(skipImmutable))
	for _, s := range skipImmutable {
		skip[s] = struct{}{}
	}
	for k, v := range patch {
		if _, immutable := skip[k]; immutable {
			continue
		}
		if existing, ok := merged[k]; ok {
			if em, lhsOK := existing.(map[string]any); lhsOK {
				if pm, rhsOK := v.(map[string]any); rhsOK {
					merged[k] = PatchMerge(em, pm, skipImmutable...)
					continue
				}
			}
		}
		merged[k] = v
	}
	return merged
}
