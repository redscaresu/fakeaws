// Package audit holds the machine-verifiable coverage audit.
//
// TestFullCoverageAudit walks fakeaws/coverage_matrix.yaml and asserts
// five invariants per entry:
//
//   (a) Integration test exists in handlers/handlers_test.go matching
//       integration_test_func_name.
//   (b) examples/working/<working_dir_name>/ exists OR working_exempt: true
//       with non-empty working_exempt_reason.
//   (c) examples/misconfigured/<misconfigured_dir_name>/ same contract.
//   (d) examples/updates/<updates_dir_name>/ same contract.
//   (e) For non-null scenario_resource_type, ≥1 aws-*.yaml in
//       infrafactory/scenarios/training/ has the key under resources:
//       AND names aws_resource_type in aws_resource_anchors.
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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// CoverageMatrixEntry mirrors the YAML schema documented in
// coverage_matrix.yaml and slices-43-48-plan.md S48-T7.
type CoverageMatrixEntry struct {
	AwsService              string `yaml:"aws_service"`
	AwsResourceType         string `yaml:"aws_resource_type"`
	ScenarioResourceType    string `yaml:"scenario_resource_type,omitempty"`
	WorkingExempt           bool   `yaml:"working_exempt,omitempty"`
	WorkingExemptReason     string `yaml:"working_exempt_reason,omitempty"`
	MisconfiguredExempt     bool   `yaml:"misconfigured_exempt,omitempty"`
	MisconfiguredReason     string `yaml:"misconfigured_exempt_reason,omitempty"`
	UpdatesExempt           bool   `yaml:"updates_exempt,omitempty"`
	UpdatesReason           string `yaml:"updates_exempt_reason,omitempty"`
	WorkingDirName          string `yaml:"working_dir_name,omitempty"`
	MisconfiguredDirName    string `yaml:"misconfigured_dir_name,omitempty"`
	UpdatesDirName          string `yaml:"updates_dir_name,omitempty"`
	IntegrationTestFuncName string `yaml:"integration_test_func_name,omitempty"`
}

// CoverageMatrix is the top-level YAML shape.
type CoverageMatrix struct {
	Entries []CoverageMatrixEntry `yaml:"entries"`
}

func TestFullCoverageAudit(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locate fakeaws repo root: %v", err)
	}
	matrix, err := loadCoverageMatrix(filepath.Join(root, "coverage_matrix.yaml"))
	if err != nil {
		t.Fatalf("load coverage_matrix.yaml: %v", err)
	}
	if len(matrix.Entries) == 0 {
		// S43-T10 acceptance: matrix is empty at seed time. Audit
		// passes vacuously. Service bundles add entries one by one.
		t.Logf("coverage_matrix.yaml has 0 entries (S43-T10 seed state); audit will run real assertions as services land")
		return
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
		})
	}
}

// ----- helpers -----

func loadCoverageMatrix(path string) (*CoverageMatrix, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m CoverageMatrix
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &m, nil
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

// scenarioMentionsResource is a lightweight YAML probe: does the
// scenario YAML contain BOTH a `resources:` block with the named
// scenario_resource_type AND an `aws_resource_anchors:` list naming
// the aws_resource_type? The check is regex-shaped because we don't
// want to import infrafactory/internal/scenario from fakeaws.
func scenarioMentionsResource(body []byte, scenarioType, awsResourceType string) bool {
	s := string(body)
	return strings.Contains(s, "\n  "+scenarioType+":") &&
		strings.Contains(s, "- "+awsResourceType)
}
