// Package audit holds the machine-verifiable coverage audit.
//
// TestFullCoverageAudit walks fakeaws/coverage_matrix.yaml and asserts
// six invariants per entry:
//
//	(a) Integration test exists in handlers/handlers_test.go matching
//	    integration_test_func_name.
//	(b) examples/working/<working_dir_name>/ exists OR working_exempt: true
//	    with non-empty working_exempt_reason.
//	(c) examples/misconfigured/<misconfigured_dir_name>/ same contract.
//	(d) examples/updates/<updates_dir_name>/ same contract.
//	(e) For non-null scenario_resource_type, ≥1 aws-*.yaml in
//	    infrafactory/scenarios/training/ has the key under resources:
//	    AND names aws_resource_type in aws_resource_anchors.
//	(f) Exactly one of loadable: true and a non-blank
//	    loadable_exempt_reason, and a loadable row's type is declared by
//	    ≥1 example examples/load_round_trip_test.go round-trips
//	    (CoverageMatrix.RoundTripExamples). The matrix decodes with
//	    KnownFields, so a misspelt column fails the load.
//
// Per concepts.md § "Resolved decisions" item 14 + slices-43-48-plan.md
// S48-T7 acceptance — this audit ships in S43-T10 with EMPTY entries
// (the matrix is just the schema header). Entries land per service-
// bundle PR (S43-T14 adds IAM + S3, S44-T12 adds EC2 services, etc.).
//
// At S43-T10: matrix has 0 entries → audit passes vacuously.
// Service bundles add entries → audit enforces real invariants.
package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFullCoverageAudit(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locate fakeaws repo root: %v", err)
	}
	matrix, err := LoadCoverageMatrix(filepath.Join(root, "coverage_matrix.yaml"))
	if err != nil {
		t.Fatalf("load coverage_matrix.yaml: %v", err)
	}
	if len(matrix.Entries) == 0 {
		// S43-T10 acceptance: matrix is empty at seed time. Audit
		// passes vacuously. Service bundles add entries one by one.
		t.Logf("coverage_matrix.yaml has 0 entries (S43-T10 seed state); audit will run real assertions as services land")
		return
	}
	roundTrips, err := matrix.RoundTripExamples(root)
	if err != nil {
		t.Fatalf("list round-tripped examples: %v", err)
	}

	for _, entry := range matrix.Entries {
		t.Run(entry.AwsResourceType, func(t *testing.T) {
			assertHandlerTestExists(t, root, entry)
			assertExampleDirOrExempt(t, root, "working", entry.WorkingDirName, entry.AwsResourceType,
				entry.WorkingExempt, entry.WorkingExemptReason)
			assertExampleDirOrExempt(t, root, "misconfigured", entry.MisconfiguredDirName, entry.AwsResourceType,
				entry.MisconfiguredExempt, entry.MisconfiguredReason)
			assertExampleDirOrExempt(t, root, "updates", entry.UpdatesDirName, entry.AwsResourceType,
				entry.UpdatesExempt, entry.UpdatesReason)
			assertScenarioCoversResource(t, entry)
			if problem := loadableProblem(entry, roundTrips); problem != "" {
				t.Error(problem)
			}
		})
	}
}

// ----- helpers -----

// loadableProblem is what is wrong with e's loadable columns, given the
// round-tripped examples and their types, or "" when nothing is.
func loadableProblem(e CoverageMatrixEntry, roundTrips map[string][]string) string {
	if e.Loadable == (strings.TrimSpace(e.LoadableExemptReason) != "") {
		return fmt.Sprintf("%s: set exactly one of loadable: true and a loadable_exempt_reason", e.AwsResourceType)
	}
	if !e.Loadable {
		return ""
	}
	for _, types := range roundTrips {
		if slices.Contains(types, e.AwsResourceType) {
			return ""
		}
	}
	return fmt.Sprintf("%s is loadable, but no example examples/load_round_trip_test.go round-trips declares it", e.AwsResourceType)
}

// repoRoot walks up from the audit test source file's location to
// locate the fakeaws repo root (where coverage_matrix.yaml lives).
// Tests are typically run from the package directory; we walk up
// looking for the file.
func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 6; i++ { // bound the walk
		if _, err := os.Stat(filepath.Join(dir, "coverage_matrix.yaml")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("coverage_matrix.yaml not found")
}

func assertHandlerTestExists(t *testing.T, root string, e CoverageMatrixEntry) {
	t.Helper()
	pattern := e.IntegrationTestFuncName
	if pattern == "" {
		// Default: ^Test.*<aws_resource_type-camel-cased>.*
		camel := camelCase(strings.TrimPrefix(e.AwsResourceType, "aws_"))
		pattern = "^Test.*" + camel + ".*"
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("invalid integration_test_func_name regex %q: %v", pattern, err)
	}
	body, err := os.ReadFile(filepath.Join(root, "handlers", "handlers_test.go"))
	if os.IsNotExist(err) {
		// Fallback: walk all handlers/*_test.go for the regex match.
		// (Some test fixtures split by service file.)
		matched := false
		entries, _ := os.ReadDir(filepath.Join(root, "handlers"))
		for _, ent := range entries {
			if !strings.HasSuffix(ent.Name(), "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(root, "handlers", ent.Name()))
			if err != nil {
				continue
			}
			if hasFuncMatching(b, re) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("no Test func matching %q found in handlers/*_test.go", pattern)
		}
		return
	}
	if err != nil {
		t.Fatalf("read handlers_test.go: %v", err)
	}
	if !hasFuncMatching(body, re) {
		t.Errorf("integration_test_func_name %q has no matching Test func", pattern)
	}
}

var funcDeclRE = regexp.MustCompile(`(?m)^func\s+(\w+)\s*\(`)

func hasFuncMatching(body []byte, re *regexp.Regexp) bool {
	matches := funcDeclRE.FindAllSubmatch(body, -1)
	for _, m := range matches {
		if re.Match(m[1]) {
			return true
		}
	}
	return false
}

func camelCase(s string) string {
	parts := strings.Split(s, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

func assertExampleDirOrExempt(t *testing.T, root, tree, dirName, resourceType string, exempt bool, reason string) {
	t.Helper()
	if exempt {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s tree: %s_exempt is true but reason is empty (%s)", tree, tree, resourceType)
		}
		return
	}
	if dirName == "" {
		dirName = strings.TrimPrefix(resourceType, "aws_")
	}
	dir := filepath.Join(root, "examples", tree, dirName)
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("%s tree: examples/%s/%s does not exist (resource_type=%s)", tree, tree, dirName, resourceType)
	}
}

func assertScenarioCoversResource(t *testing.T, e CoverageMatrixEntry) {
	t.Helper()
	if e.ScenarioResourceType == "" {
		return // entry doesn't claim to be exposed to the generator
	}
	// Scenarios live in the sibling infrafactory repo. The audit
	// looks one directory up from fakeaws/ to find infrafactory/.
	root, err := repoRoot()
	if err != nil {
		return
	}
	scenarioDir := filepath.Join(root, "..", "infrafactory", "scenarios", "training")
	entries, err := os.ReadDir(scenarioDir)
	if err != nil {
		// Sibling repo not present in this checkout — skip the scenario
		// half of the audit. Real CI runs both repos side-by-side.
		t.Logf("scenarios/training not accessible from fakeaws (%v); scenario half of audit skipped — real CI must run from infrafactory checkout", err)
		return
	}
	matched := false
	for _, ent := range entries {
		if !strings.HasPrefix(ent.Name(), "aws-") || !strings.HasSuffix(ent.Name(), ".yaml") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(scenarioDir, ent.Name()))
		if err != nil {
			continue
		}
		// We require BOTH:
		//  (i) scenario_resource_type appears as a top-level key under
		//      `resources:` AND
		//  (ii) aws_resource_type is named in aws_resource_anchors.
		if scenarioMentionsResource(body, e.ScenarioResourceType, e.AwsResourceType) {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("no aws scenario covers %s (under resources.%s with anchor %s)",
			e.AwsResourceType, e.ScenarioResourceType, e.AwsResourceType)
	}
}

// scenarioMentionsResource verifies BOTH halves of the scenario
// contract by parsing the YAML structurally:
//
//	(i)  resources.<scenario_resource_type> exists as a top-level
//	     sub-key under "resources:".
//	(ii) aws_resource_anchors contains aws_resource_type as a list
//	     element.
//
// Codex pass 13 BLOCKING #1: the previous implementation used naked
// substring probes ("\n  X:" anywhere, "- Y" anywhere), so anchors
// embedded in unrelated lists or comments would false-green. The
// audit is the enforcement hook for coverage_matrix.yaml; the probe
// must not be structurally weak.
func scenarioMentionsResource(body []byte, scenarioType, awsResourceType string) bool {
	var doc struct {
		Resources          map[string]any `yaml:"resources"`
		AwsResourceAnchors []string       `yaml:"aws_resource_anchors"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return false
	}
	if _, ok := doc.Resources[scenarioType]; !ok {
		return false
	}
	for _, a := range doc.AwsResourceAnchors {
		if a == awsResourceType {
			return true
		}
	}
	return false
}

func TestLoadCoverageMatrixRefusesUnknownColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coverage_matrix.yaml")
	require.NoError(t, os.WriteFile(path, []byte("entries:\n  - aws_service: ec2\n    aws_resource_type: aws_vpc\n    loadabel: true\n"), 0o600))
	_, err := LoadCoverageMatrix(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loadabel")
}

func TestLoadableProblem(t *testing.T) {
	roundTrips := map[string][]string{"vpc_network": {"aws_subnet", "aws_vpc"}}
	for name, tc := range map[string]struct {
		entry CoverageMatrixEntry
		want  string
	}{
		"neither":         {CoverageMatrixEntry{AwsResourceType: "aws_vpc"}, "aws_vpc: set exactly one"},
		"blank reason":    {CoverageMatrixEntry{AwsResourceType: "aws_vpc", LoadableExemptReason: " "}, "aws_vpc: set exactly one"},
		"both":            {CoverageMatrixEntry{AwsResourceType: "aws_vpc", Loadable: true, LoadableExemptReason: "why"}, "aws_vpc: set exactly one"},
		"not round-trips": {CoverageMatrixEntry{AwsResourceType: "aws_key_pair", Loadable: true}, "aws_key_pair is loadable, but no example"},
		"round-trips":     {CoverageMatrixEntry{AwsResourceType: "aws_vpc", Loadable: true}, ""},
		"exempt":          {CoverageMatrixEntry{AwsResourceType: "aws_key_pair", LoadableExemptReason: "why"}, ""},
	} {
		got := loadableProblem(tc.entry, roundTrips)
		if tc.want == "" {
			assert.Empty(t, got, name)
		} else {
			assert.Contains(t, got, tc.want, name)
		}
	}
}

// TestRoundTripExamplesNeedEveryTypeLoadable: an example with one type
// that is not a loadable row, or that has no row, is not round-tripped,
// and a data block reads its data.<type> row when there is one.
func TestRoundTripExamplesNeedEveryTypeLoadable(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"all":      "resource \"aws_vpc\" \"a\" {}\ndata \"aws_vpc\" \"b\" {}\ndata \"aws_caller_identity\" \"c\" {}\n",
		"exempt":   "resource \"aws_vpc\" \"a\" {}\nresource \"aws_s3_bucket\" \"b\" {}\n",
		"no row":   "resource \"aws_vpc\" \"a\" {}\nresource \"aws_kms_key\" \"b\" {}\n",
		"data row": "data \"aws_security_group\" \"a\" {}\n",
	} {
		dir := filepath.Join(root, "examples", "working", name)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(body), 0o600))
	}
	m := &CoverageMatrix{Entries: []CoverageMatrixEntry{
		{AwsResourceType: "aws_vpc", Loadable: true},
		{AwsResourceType: "data.aws_vpc", Loadable: true},
		{AwsResourceType: "aws_caller_identity", Loadable: true},
		{AwsResourceType: "aws_s3_bucket", LoadableExemptReason: "rest"},
		{AwsResourceType: "aws_security_group", Loadable: true},
		{AwsResourceType: "data.aws_security_group", LoadableExemptReason: "data row"},
	}}
	got, err := m.RoundTripExamples(root)
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{"all": {"aws_caller_identity", "aws_vpc", "data.aws_vpc"}}, got)
}
