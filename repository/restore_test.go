package repository

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/models"
)

// restoreRepo opens dbPath with vpc-snap in its snapshot and vpc-live
// stored after it.
func restoreRepo(t *testing.T, dbPath string) *Repository {
	t.Helper()
	r, err := New(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	require.NoError(t, createVPC(r, &EC2VPC{ID: "vpc-snap", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	require.NoError(t, r.Snapshot())
	require.NoError(t, createVPC(r, &EC2VPC{ID: "vpc-live", CidrBlock: "10.1.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	return r
}

func vpcIDs(t *testing.T, r *Repository) []string {
	t.Helper()
	vpcs, err := r.ListVPCs(testAccount, "")
	require.NoError(t, err)
	var ids []string
	for _, v := range vpcs {
		ids = append(ids, v.ID)
	}
	return ids
}

// stagedFiles lists what Restore left at <dbPath>.restore*.
func stagedFiles(t *testing.T, dbPath string) []string {
	t.Helper()
	files, err := filepath.Glob(dbPath + ".restore*")
	require.NoError(t, err)
	return files
}

// addVPC is a prepare that stores vpc-staged in the restored copy.
func addVPC(staged *Repository) error {
	return createVPC(staged, &EC2VPC{ID: "vpc-staged", CidrBlock: "10.2.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"})
}

// TestRestoreWritesThroughTheLivePath: Restore writes the prepared copy
// into the live path, never replaces it, so a bind-mounted single-file
// db keeps its inode and a symlinked --db stays a symlink. The prepared
// write is in the live db and no .restore file is left.
func TestRestoreWritesThroughTheLivePath(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	r := restoreRepo(t, dbPath)
	before, err := os.Stat(dbPath)
	require.NoError(t, err)
	require.NoError(t, r.Restore(addVPC))
	after, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, after), "the live file is written in place")
	assert.ElementsMatch(t, []string{"vpc-snap", "vpc-staged"}, vpcIDs(t, r))
	assert.Empty(t, stagedFiles(t, dbPath))

	dir := t.TempDir()
	target, link := filepath.Join(dir, "real.db"), filepath.Join(dir, "state.db")
	seed, err := New(target)
	require.NoError(t, err)
	require.NoError(t, seed.Close())
	require.NoError(t, os.Symlink(target, link))
	r = restoreRepo(t, link)
	require.NoError(t, r.Restore(addVPC))
	fi, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "--db is still a symlink")
	assert.ElementsMatch(t, []string{"vpc-snap", "vpc-staged"}, vpcIDs(t, r))
	assert.Empty(t, stagedFiles(t, link))
}

// TestRestoreFailsUnlessCheckpointed: Restore copies only the prepared
// copy's file, so its WAL must be checkpointed in full first. A reader
// left on the copy blocks the TRUNCATE checkpoint: Restore fails, the
// live db stays as it was, and the .restore files are removed.
func TestRestoreFailsUnlessCheckpointed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	r := restoreRepo(t, dbPath)
	var reader *sql.DB
	t.Cleanup(func() {
		if reader != nil {
			_ = reader.Close()
		}
	})
	holdReader := func(staged *Repository) error {
		if err := addVPC(staged); err != nil {
			return err
		}
		var err error
		if reader, err = sql.Open("sqlite", staged.dbPath); err != nil {
			return err
		}
		reader.SetMaxOpenConns(1)
		if _, err := reader.Exec("BEGIN"); err != nil {
			return err
		}
		var n int
		return reader.QueryRow(`SELECT COUNT(*) FROM ec2_vpcs`).Scan(&n)
	}

	err := r.Restore(holdReader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checkpoint restored copy")
	assert.ElementsMatch(t, []string{"vpc-snap", "vpc-live"}, vpcIDs(t, r), "the live db as it was")
	assert.Empty(t, stagedFiles(t, dbPath))
}

// TestRestoreRefusesAnotherSchemaVersion: a snapshot at another schema
// version is refused, with or without a prepare, before anything is
// copied over the live db: its rows and version are as they were, it
// still answers, and no .restore file is left.
func TestRestoreRefusesAnotherSchemaVersion(t *testing.T) {
	for name, prepare := range map[string]func(*Repository) error{"nil": nil, "addVPC": addVPC} {
		t.Run(name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "state.db")
			r := restoreRepo(t, dbPath)
			execOnFile(t, dbPath+".snapshot", `UPDATE schema_version SET version = 1`)

			err := r.Restore(prepare)
			require.ErrorIs(t, err, models.ErrConflict)
			assert.Contains(t, err.Error(), fmt.Sprintf("%s.snapshot: database schema version 1, fakeaws needs %d", dbPath, dbSchemaVersion))
			assert.ElementsMatch(t, []string{"vpc-snap", "vpc-live"}, vpcIDs(t, r), "the live db as it was")
			assert.Equal(t, fmt.Sprint(dbSchemaVersion), storedVersion(t, r))
			assert.Empty(t, stagedFiles(t, dbPath))
		})
	}
}

// TestRestoreClearsAStaleJournal: a kill while stage switched the
// .restore copy to WAL can leave <db>.restore-journal hot. Restore
// removes it with the copy's other files, so it still succeeds.
func TestRestoreClearsAStaleJournal(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	r := restoreRepo(t, dbPath)
	require.NoError(t, os.WriteFile(dbPath+".restore-journal", []byte("left by a kill"), 0o600))

	require.NoError(t, r.Restore(nil))
	assert.Equal(t, []string{"vpc-snap"}, vpcIDs(t, r))
	assert.Empty(t, stagedFiles(t, dbPath))
}
