package repository

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoad_ResetTablesChildrenFirst: Load deletes resetTables in order
// with FKs on, so a table must come before every table it references,
// or deleting the parent fails (RESTRICT) while a child row is left. A
// table that references itself needs a loadUnlink entry.
func TestLoad_ResetTablesChildrenFirst(t *testing.T) {
	repo, err := New(":memory:")
	require.NoError(t, err)
	defer repo.Close()
	for i, table := range resetTables {
		rows, err := repo.DB().Query(`SELECT "table" FROM pragma_foreign_key_list(?)`, table)
		require.NoError(t, err)
		for rows.Next() {
			var parent string
			require.NoError(t, rows.Scan(&parent))
			if parent == table {
				assert.Contains(t, loadUnlink, table, "%s references itself and has no loadUnlink entry", table)
				continue
			}
			p := slices.Index(resetTables, parent)
			assert.True(t, p > i, "%s references %s, which resetTables deletes first or never", table, parent)
		}
		require.NoError(t, rows.Close())
	}
}

// TestLoad_ClearsAReplicaChain: a source, its replica and the replica's
// own replica, stored in that order, are all deleted.
func TestLoad_ClearsAReplicaChain(t *testing.T) {
	repo, err := New(":memory:")
	require.NoError(t, err)
	defer repo.Close()
	source := ""
	for _, id := range []string{"db-source", "db-replica", "db-replica-of-replica"} {
		_, err := repo.DB().Exec(`INSERT INTO rds_db_instances (account_id, region, id, engine, instance_class, replicate_source_db, arn, data, created_at)
			VALUES ('222233334444', 'us-east-1', ?, 'mysql', 'db.t3.micro', NULLIF(?, ''), '', '{}', '')`, id, source)
		require.NoError(t, err)
		source = id
	}
	require.NoError(t, repo.Load(Identity{AccountID: "111122223333", Region: "eu-west-1"}, func(*LoadTx) error { return nil }))
	var n int
	require.NoError(t, repo.DB().QueryRow(`SELECT COUNT(*) FROM rds_db_instances`).Scan(&n))
	assert.Zero(t, n)
}

func TestLoad_FillErrorRollsBack(t *testing.T) {
	repo, err := New(":memory:")
	require.NoError(t, err)
	defer repo.Close()
	require.NoError(t, repo.SetIdentity(Identity{AccountID: "222233334444", Region: "us-east-1"}, "000000000000", nil))
	require.NoError(t, repo.CreateRole("222233334444", &IAMRole{Name: "kept", ARN: "arn:aws:iam::222233334444:role/kept", AssumeRolePolicyDocument: "{}"}))

	refused := errors.New("refused")
	err = repo.Load(Identity{AccountID: "111122223333", Region: "eu-west-1"}, func(lt *LoadTx) error {
		_, err := lt.Exec(`INSERT INTO ec2_vpcs (account_id, region, id, cidr_block, arn, data, created_at) VALUES ('111122223333', 'eu-west-1', 'vpc-0rolled', '10.0.0.0/16', '', '{}', '')`)
		require.NoError(t, err)
		return refused
	})
	require.ErrorIs(t, err, refused)

	id, err := repo.GetIdentity()
	require.NoError(t, err)
	assert.Equal(t, Identity{AccountID: "222233334444", Region: "us-east-1"}, id)
	loaded, err := repo.Loaded()
	require.NoError(t, err)
	assert.False(t, loaded)
	_, err = repo.GetRole("222233334444", "kept")
	assert.NoError(t, err, "the delete was not rolled back")
	var vpcs int
	require.NoError(t, repo.DB().QueryRow(`SELECT COUNT(*) FROM ec2_vpcs`).Scan(&vpcs))
	assert.Zero(t, vpcs, "fill's write was not rolled back")
}

// TestLoadTx_ExposesNoDB: a loader holding the db's handle could wait on
// the connection its own transaction holds.
func TestLoadTx_ExposesNoDB(t *testing.T) {
	db := reflect.TypeOf((*sql.DB)(nil))
	lt := reflect.TypeOf(&LoadTx{})
	for i := range lt.Elem().NumField() {
		f := lt.Elem().Field(i)
		assert.False(t, f.IsExported() && f.Type == db, "field %s is a *sql.DB", f.Name)
	}
	for i := range lt.NumMethod() {
		m := lt.Method(i)
		for j := range m.Type.NumIn() {
			assert.False(t, m.Type.In(j) == db, "%s takes a *sql.DB", m.Name)
		}
		for j := range m.Type.NumOut() {
			assert.False(t, m.Type.Out(j) == db, "%s returns a *sql.DB", m.Name)
		}
	}
}

// TestLoadTx_OnlyLoadGoTouchesTheTx: every statement a loader runs goes
// through a load.go method that records its failure (LoadTx.Failed), so
// no read or write added elsewhere can let a loader run on, or refuse,
// past a failed one.
func TestLoadTx_OnlyLoadGoTouchesTheTx(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	field := regexp.MustCompile(`\.sqlTx\b`)
	for _, path := range files {
		if path == "load.go" || strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.False(t, field.Match(src), "%s touches LoadTx's sqlTx; add the statement to load.go, through fail", path)
	}
	require.Contains(t, files, "load.go")
}
