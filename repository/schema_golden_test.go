package repository

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
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

// readGolden parses the golden at path: a goldenFirst line, then a
// goldenHeader "<type> <name>" line and the sql per entry.
func readGolden(path string) (int, map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, err
	}
	entries := strings.Split(string(b), goldenHeader)
	var version int
	if _, err := fmt.Sscanf(entries[0], goldenFirst, &version); err != nil {
		return 0, nil, fmt.Errorf("%s: first line: %w", path, err)
	}
	golden := map[string]string{}
	for _, e := range entries[1:] {
		key, sql, _ := strings.Cut(e, "\n")
		golden[key] = strings.TrimSuffix(sql, "\n")
	}
	return version, golden, nil
}

func writeGolden(path string, schema map[string]string) error {
	var b strings.Builder
	fmt.Fprintf(&b, goldenFirst, dbSchemaVersion)
	for _, key := range sortedKeys(schema) {
		fmt.Fprintf(&b, "%s%s\n%s\n", goldenHeader, key, schema[key])
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// schemaDrift compares live with the golden at path, one message per
// difference. A missing or unparsable golden is one, update or not: with
// no golden, a changed entry could not be told from an added one. At
// the golden's version, a changed or gone entry is one; only a golden
// below dbSchemaVersion (a bump) may differ. With update and no drift it
// rewrites the golden from live; without, an entry the golden lacks and
// a golden not at dbSchemaVersion are drift too.
func schemaDrift(path string, live map[string]string, update bool) []string {
	version, golden, err := readGolden(path)
	if err != nil {
		return []string{fmt.Sprintf("%v: restore %s from git, then run %s", err, path, updateHint)}
	}
	var drift []string
	switch {
	case version > dbSchemaVersion:
		drift = append(drift, fmt.Sprintf("%s is at dbSchemaVersion %d, above the const %d", path, version, dbSchemaVersion))
	case version == dbSchemaVersion:
		for _, key := range sortedKeys(golden) {
			if live[key] != golden[key] {
				drift = append(drift, fmt.Sprintf("%s differs from %s or is gone: bump dbSchemaVersion and run %s", key, path, updateHint))
			}
		}
	}
	if update {
		if len(drift) == 0 {
			if err := writeGolden(path, live); err != nil {
				drift = append(drift, err.Error())
			}
		}
		return drift
	}
	if version != dbSchemaVersion {
		drift = append(drift, fmt.Sprintf("%s is not at dbSchemaVersion: run %s", path, updateHint))
	}
	for _, key := range sortedKeys(live) {
		if _, ok := golden[key]; !ok {
			drift = append(drift, fmt.Sprintf("%s is not in %s: append it to the golden with %s", key, path, updateHint))
		}
	}
	return drift
}

// TestSchemaGolden: a db at dbSchemaVersion has the schema in
// schemaGolden. migrate never changes an existing table, index or
// trigger, so changing one without a bump would leave every db made
// before it on the old shape. With -update it rewrites the golden, but
// a changed entry still fails until dbSchemaVersion is bumped.
func TestSchemaGolden(t *testing.T) {
	for _, d := range schemaDrift(schemaGolden, freshSchema(t), *update) {
		t.Error(d)
	}
}

// TestSchemaDrift: -update cannot be used to skip a bump. A missing or
// unparsable golden fails with or without it, and a changed entry at the
// golden's version fails and is not written. An added entry is written,
// and so is a changed one after a bump.
func TestSchemaDrift(t *testing.T) {
	const (
		was = "CREATE TABLE a (x)"
		now = "CREATE TABLE a (x, y)"
	)
	golden := func(version int, sql string) string {
		return fmt.Sprintf(goldenFirst, version) + goldenHeader + "table a\n" + sql + "\n"
	}
	cases := []struct {
		name     string
		golden   *string // nil: no file
		live     map[string]string
		update   bool
		drift    string // "" when none
		rewrites bool
	}{
		{"missing", nil, map[string]string{"table a": was}, false, "no such file", false},
		{"missing, update", nil, map[string]string{"table a": was}, true, "no such file", false},
		{"unparsable, update", ptr("garbage\n"), map[string]string{"table a": was}, true, "first line", false},
		{"changed", ptr(golden(dbSchemaVersion, was)), map[string]string{"table a": now}, false, "table a differs", false},
		{"changed, update", ptr(golden(dbSchemaVersion, was)), map[string]string{"table a": now}, true, "table a differs", false},
		{"added", ptr(golden(dbSchemaVersion, was)), map[string]string{"table a": was, "table b": now}, false, "table b is not in", false},
		{"added, update", ptr(golden(dbSchemaVersion, was)), map[string]string{"table a": was, "table b": now}, true, "", true},
		{"changed after a bump, update", ptr(golden(dbSchemaVersion-1, was)), map[string]string{"table a": now}, true, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "schema.golden")
			if c.golden != nil {
				require.NoError(t, os.WriteFile(path, []byte(*c.golden), 0o644))
			}
			drift := schemaDrift(path, c.live, c.update)
			if c.drift == "" {
				assert.Empty(t, drift)
			} else if assert.Len(t, drift, 1) {
				assert.Contains(t, drift[0], c.drift)
				assert.Contains(t, drift[0], path)
			}
			b, err := os.ReadFile(path)
			if !c.rewrites {
				if c.golden == nil {
					assert.ErrorIs(t, err, os.ErrNotExist, "no golden is written")
				} else {
					assert.Equal(t, *c.golden, string(b), "the golden is not rewritten")
				}
				return
			}
			require.NoError(t, err)
			version, got, err := readGolden(path)
			require.NoError(t, err)
			assert.Equal(t, dbSchemaVersion, version)
			assert.Equal(t, c.live, got)
		})
	}
}

func ptr(s string) *string { return &s }
