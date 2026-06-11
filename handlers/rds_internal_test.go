package handlers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestContract_rds_dbi_resource_id_distinct_from_identifier — wire-shape
// regression for CRITICAL[rds-dbi-resource-id-distinct-from-identifier]
// in handlers/rds.go::dbiResourceIDFor. Asserts the synthesised
// DbiResourceId NEVER equals the user-given DBInstanceIdentifier, has
// the "db-" prefix the provider expects, and is stable across calls.
// If the helper were changed to e.g. `return id`, this test fails.
//
// Internal test (package handlers, not handlers_test) so it can call
// the unexported helper directly without exposing it on the public
// surface.
func TestContract_rds_dbi_resource_id_distinct_from_identifier(t *testing.T) {
	cases := []string{
		"mydb",
		"production-rds-1",
		"a", // shortest plausible identifier
		"db-already-prefixed",
	}
	for _, id := range cases {
		got := dbiResourceIDFor(id)
		assert.NotEqual(t, id, got, "dbiResourceIDFor(%q) returned the identifier verbatim — must NOT collide", id)
		assert.True(t, strings.HasPrefix(got, "db-"), "dbiResourceIDFor(%q) = %q, expected db-<hex> prefix", id, got)
		assert.Equal(t, got, dbiResourceIDFor(id), "dbiResourceIDFor(%q) is not stable", id)
	}
}
