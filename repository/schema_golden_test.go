package repository

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "rewrite testdata/schema.golden")

const (
	schemaGolden = "testdata/schema.golden"
	goldenHeader = "\n=== "
	goldenFirst  = "dbSchemaVersion %d\n"
	updateHint   = "go test ./repository -run TestSchemaGolden -update"
)

// freshSchema is the sql of every table, index and trigger of a new db,
// keyed "<type> <name>".
func freshSchema(t *testing.T) map[string]string {
	t.Helper()
	r, err := New(":memory:")
	require.NoError(t, err)
	defer r.Close()
	rows, err := r.db.Query(`SELECT type || ' ' || name, sql FROM sqlite_master WHERE sql IS NOT NULL`)
	require.NoError(t, err)
	defer rows.Close()
	schema := map[string]string{}
	for rows.Next() {
		var key, sql string
		require.NoError(t, rows.Scan(&key, &sql))
		schema[key] = sql
	}
	require.NoError(t, rows.Err())
	return schema
}

// readGolden parses schemaGolden: a goldenFirst line, then a
// goldenHeader "<type> <name>" line and the sql per entry. A missing
// file is version 0 with no entries.
func readGolden(t *testing.T) (int, map[string]string) {
	t.Helper()
	b, err := os.ReadFile(schemaGolden)
	if os.IsNotExist(err) {
		return 0, map[string]string{}
	}
	require.NoError(t, err)
	entries := strings.Split(string(b), goldenHeader)
	var version int
	_, err = fmt.Sscanf(entries[0], goldenFirst, &version)
	require.NoError(t, err, "first line of %s", schemaGolden)
	golden := map[string]string{}
	for _, e := range entries[1:] {
		key, sql, _ := strings.Cut(e, "\n")
		golden[key] = strings.TrimSuffix(sql, "\n")
	}
	return version, golden
}

func writeGolden(t *testing.T, schema map[string]string) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, goldenFirst, dbSchemaVersion)
	for _, key := range sortedKeys(schema) {
		fmt.Fprintf(&b, "%s%s\n%s\n", goldenHeader, key, schema[key])
	}
	require.NoError(t, os.WriteFile(schemaGolden, []byte(b.String()), 0o644))
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestSchemaGolden: a db at dbSchemaVersion has the schema in
// schemaGolden. migrate never changes an existing table, index or
// trigger, so changing one without a bump would leave every db made
// before it on the old shape. With -update it rewrites the golden, but
// a changed entry still fails until dbSchemaVersion is bumped.
func TestSchemaGolden(t *testing.T) {
	live := freshSchema(t)
	version, golden := readGolden(t)
	if version == dbSchemaVersion {
		for _, key := range sortedKeys(golden) {
			assert.Equal(t, golden[key], live[key],
				"%s differs from %s or is gone: bump dbSchemaVersion and run %s", key, schemaGolden, updateHint)
		}
	}
	if *update {
		if !t.Failed() {
			writeGolden(t, live)
		}
		return
	}
	require.Equal(t, dbSchemaVersion, version, "%s is not at dbSchemaVersion: run %s", schemaGolden, updateHint)
	for _, key := range sortedKeys(live) {
		_, ok := golden[key]
		assert.True(t, ok, "%s is not in %s: append it to the golden with %s", key, schemaGolden, updateHint)
	}
}
