// Package examples — auto-discovered provider smoke harness.
//
// Per concepts.md "Coverage requirements" rule 2: every example dir
// under examples/{working,misconfigured,updates}/ is auto-discovered
// here and run through the per-tree contract:
//
//	working/      apply → plan -detailed-exitcode (no diff) → destroy
//	misconfigured/ apply MUST fail with the documented AWS error code
//	               (matched against expected.txt in the same dir)
//	updates/      apply -var-file=v1.tfvars → plan no-op → apply -var-file=v2.tfvars → plan no-op → destroy
//
// Adding a directory to ANY of the three trees auto-registers — no
// per-example test ticket. Each subdirectory is its own t.Run sub-test.
//
// Where it runs:
//   - The provider-smoke job in this repo's .github/workflows/ci.yml
//     builds fakeaws, starts it on :8082 and runs this package with
//     INFRAFACTORY_ENABLE_E2E=1 on every pull request.
//   - Locally: start fakeaws on :8082 (the examples' provider blocks
//     hardcode http://127.0.0.1:8082), then run with the same env var.
//     Without it, the test t.Skip's with a clear message — mirroring
//     the gating pattern infrafactory uses for tofu-driven e2e tests.
//
// The run starts from one POST /mock/reset, then every example runs in
// parallel. Examples listed in knownRed (known_red_test.go) must fail
// exactly as recorded there.
//
// This package is `examples_test` so the auto-discovery walks the
// repo via runtime.Caller (mirror of internal/audit/audit_test.go's
// repoRoot helper).
package examples_test

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultFakeAWSURL = "http://127.0.0.1:8082"
	gateEnvVar        = "INFRAFACTORY_ENABLE_E2E"
	shardEnvVar       = "SMOKE_SHARD"
)

// TestProviderSmokeWorking walks examples/working/<svc>/ and runs
// `tofu init && tofu apply -auto-approve && tofu plan -detailed-exitcode &&
// tofu destroy -auto-approve`. plan-after-apply MUST be no-op (exit 0
// from -detailed-exitcode means "no diff").
func TestProviderSmokeWorking(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	t.Parallel()
	walkExamplesAndRun(t, "working", runWorkingExample)
}

// TestProviderSmokeMisconfigured walks examples/misconfigured/<svc>/.
// `tofu apply` MUST fail; the failure output MUST contain the string
// in expected.txt (the documented AWS error code).
func TestProviderSmokeMisconfigured(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	t.Parallel()
	walkExamplesAndRun(t, "misconfigured", runMisconfiguredExample)
}

// TestProviderSmokeUpdates walks examples/updates/<svc>/, applies v1,
// asserts plan is clean, applies v2, asserts plan is clean, destroys.
// Each updates/ directory MUST contain v1.tfvars + v2.tfvars + main.tf.
func TestProviderSmokeUpdates(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	t.Parallel()
	walkExamplesAndRun(t, "updates", runUpdatesExample)
}

// ----- discovery -----

// walkExamplesAndRun runs every example under examples/<tree>/ in
// parallel and judges the outcome against knownRed, keyed
// "<tree>/<dir>". The examples share one fakeaws, so each must use
// resource names no other example uses.
func walkExamplesAndRun(t *testing.T, tree string, run func(t *testing.T, dir string) *stageErr) {
	t.Helper()
	resetFakeAWS(t)
	parent := filepath.Join(repoRoot(t), "examples", tree)
	entries, err := os.ReadDir(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Logf("skipping %s — directory does not exist (no examples in this tree yet)", parent)
			return
		}
		t.Fatalf("read %s: %v", parent, err)
	}
	any := false
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		any = true
		name := tree + "/" + ent.Name()
		if !inShard(t, name) {
			continue
		}
		dir := filepath.Join(parent, ent.Name())
		t.Run(ent.Name(), func(t *testing.T) {
			t.Parallel()
			failure := run(t, dir)
			require.NoError(t, checkKnownRed(knownRed, name, failure))
			if failure != nil {
				t.Logf("known red, failed as recorded at %s (owner: %s)", failure.stage, knownRed[name].owner)
			}
		})
	}
	if !any {
		t.Logf("no example subdirectories under %s — that's fine, gap-fill happens in S48-T6", parent)
	}
}

// ----- per-tree contracts -----

func runWorkingExample(t *testing.T, dir string) *stageErr {
	t.Helper()
	return runSteps(t, dir,
		step{"init", []string{"init"}},
		step{"apply", []string{"apply", "-auto-approve"}},
		step{"plan", []string{"plan", "-detailed-exitcode"}},
		step{"destroy", []string{"destroy", "-auto-approve"}},
	)
}

func runMisconfiguredExample(t *testing.T, dir string) *stageErr {
	t.Helper()
	expected, err := os.ReadFile(filepath.Join(dir, "expected.txt"))
	require.NoError(t, err, "misconfigured example missing expected.txt")
	expectedString := strings.TrimSpace(string(expected))
	require.NotEmpty(t, expectedString, "misconfigured example expected.txt is empty — must contain the AWS error code we expect")

	if failure := runSteps(t, dir, step{"init", []string{"init"}}); failure != nil {
		return failure
	}
	failure := runSteps(t, dir, step{"apply", []string{"apply", "-auto-approve"}})
	if failure == nil {
		return &stageErr{stage: "apply", out: fmt.Sprintf("apply UNEXPECTEDLY succeeded; expected failure containing %q", expectedString)}
	}
	if !strings.Contains(failure.out, expectedString) {
		failure.out = fmt.Sprintf("apply failed but output does not contain expected error %q\n%s", expectedString, failure.out)
		return failure
	}
	return nil
}

func runUpdatesExample(t *testing.T, dir string) *stageErr {
	t.Helper()
	v1 := filepath.Join(dir, "v1.tfvars")
	v2 := filepath.Join(dir, "v2.tfvars")
	for _, p := range []string{v1, v2} {
		_, err := os.Stat(p)
		require.NoError(t, err, "updates example missing %s", p)
	}

	return runSteps(t, dir,
		step{"init", []string{"init"}},
		step{"apply v1", []string{"apply", "-auto-approve", "-var-file=" + v1}},
		step{"plan v1", []string{"plan", "-detailed-exitcode", "-var-file=" + v1}},
		step{"apply v2", []string{"apply", "-auto-approve", "-var-file=" + v2}},
		step{"plan v2", []string{"plan", "-detailed-exitcode", "-var-file=" + v2}},
		step{"destroy", []string{"destroy", "-auto-approve", "-var-file=" + v2}},
	)
}

// ----- tofu wrappers -----

// step is one tofu invocation; stage is the name knownRed records.
type step struct {
	stage string
	args  []string
}

// stageErr is the first failed step of an example and its output.
type stageErr struct {
	stage string
	out   string
}

func (e *stageErr) Error() string {
	return fmt.Sprintf("tofu %s failed:\n%s", e.stage, e.out)
}

// runSteps runs steps in order, each in smokeEnv, and stops at the first
// non-zero exit. For `plan -detailed-exitcode` that covers both 1
// (error) and 2 (diff).
func runSteps(t *testing.T, dir string, steps ...step) *stageErr {
	t.Helper()
	for _, s := range steps {
		cmd := exec.Command("tofu", append(s.args, "-input=false", "-no-color")...)
		cmd.Dir = dir
		cmd.Env = smokeEnv(t, s.args[0])
		if out, err := cmd.CombinedOutput(); err != nil {
			return &stageErr{stage: s.stage, out: fmt.Sprintf("%v\n%s", err, out)}
		}
	}
	return nil
}

// ----- helpers -----

// resetOnce empties fakeaws once per run: the examples run in
// parallel, so a reset per example would wipe another's resources.
var resetOnce = sync.OnceValue(func() error {
	resp, err := http.Post(defaultFakeAWSURL+"/mock/reset", "application/json", nil)
	if err != nil {
		return fmt.Errorf("POST /mock/reset — is fakeaws running on %s? %w", defaultFakeAWSURL, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /mock/reset: status %d", resp.StatusCode)
	}
	return nil
})

func resetFakeAWS(t *testing.T) {
	t.Helper()
	require.NoError(t, resetOnce())
}

// smokeTests are the e2e tests outside the three trees; they are
// sharded along with the examples.
var smokeTests = []string{"TestSmokeEnvFailsClosed", "TestWebStepOneState"}

// inShard reports whether name ("<tree>/<dir>" or a smokeTests entry)
// runs in this job. SMOKE_SHARD=i/n (1-based) deals the sorted names
// round-robin across n CI jobs; unset, everything runs.
func inShard(t *testing.T, name string) bool {
	t.Helper()
	spec := os.Getenv(shardEnvVar)
	if spec == "" {
		return true
	}
	var i, n int
	_, err := fmt.Sscanf(spec, "%d/%d", &i, &n)
	require.NoError(t, err, "%s=%q, want i/n", shardEnvVar, spec)
	require.True(t, i >= 1 && i <= n, "%s=%q, want 1 <= i <= n", shardEnvVar, spec)
	names := smokeNames(t)
	idx := slices.Index(names, name)
	require.GreaterOrEqual(t, idx, 0, "%s is not a smoke example or test", name)
	return idx%n == i-1
}

// smokeNames lists every shardable name, sorted.
func smokeNames(t *testing.T) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(repoRoot(t), "examples", "*", "*", "main.tf"))
	require.NoError(t, err)
	names := slices.Clone(smokeTests)
	for _, d := range dirs {
		rel, err := filepath.Rel(filepath.Join(repoRoot(t), "examples"), filepath.Dir(d))
		require.NoError(t, err)
		names = append(names, filepath.ToSlash(rel))
	}
	slices.Sort(names)
	return names
}

// requireShard skips a smokeTests entry another shard runs.
func requireShard(t *testing.T) {
	t.Helper()
	if !inShard(t, t.Name()) {
		t.Skipf("%s runs in another %s shard", t.Name(), shardEnvVar)
	}
}

func TestShardsPartitionTheSmokeRun(t *testing.T) {
	names := smokeNames(t)
	for _, n := range []int{1, 3, 5} {
		seen := map[string]int{}
		for i := 1; i <= n; i++ {
			t.Setenv(shardEnvVar, fmt.Sprintf("%d/%d", i, n))
			for _, name := range names {
				if inShard(t, name) {
					seen[name]++
				}
			}
		}
		for _, name := range names {
			assert.Equal(t, 1, seen[name], "%s with %d shards", name, n)
		}
	}
}

// copyExample copies an example's main.tf into a temp dir, so a test
// can drive it while the smoke harness runs the original in parallel.
func copyExample(t *testing.T, tree, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "examples", tree, name, "main.tf"))
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), body, 0o644))
	return dir
}

func requireE2EGate(t *testing.T) {
	t.Helper()
	if os.Getenv(gateEnvVar) != "1" {
		t.Skipf("set %s=1 to run example smoke tests (requires tofu + fakeaws on %s)",
			gateEnvVar, defaultFakeAWSURL)
	}
}

// requireTofu fails rather than skips: with the gate set, a missing
// tofu would otherwise turn the provider-smoke job silently green.
func requireTofu(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("tofu")
	require.NoError(t, err, "tofu not on PATH but %s=1", gateEnvVar)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate fakeaws repo root from %s", file)
	return ""
}

var (
	resourceLine = regexp.MustCompile(`^resource "(\w+)"`)
	nameLine     = regexp.MustCompile(`^  (name|bucket|identifier|cluster_identifier|key_name)\s*=\s*"([^"]+)"`)
)

// TestExampleResourceNamesAreUnique: the examples run in parallel
// against one fakeaws, so two examples naming the same queue, role,
// table, ... would collide. Security group names are per VPC, and every
// example has its own VPC.
func TestExampleResourceNamesAreUnique(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "examples", "*", "*", "main.tf"))
	require.NoError(t, err)
	owner := map[string]string{}
	for _, f := range files {
		body, err := os.ReadFile(f)
		require.NoError(t, err)
		dir := filepath.Base(filepath.Dir(f))
		var typ string
		for _, line := range strings.Split(string(body), "\n") {
			if m := resourceLine.FindStringSubmatch(line); m != nil {
				typ = m[1]
			}
			m := nameLine.FindStringSubmatch(line)
			if m == nil || typ == "aws_security_group" {
				continue
			}
			key := typ + " " + m[2]
			if prev, ok := owner[key]; ok && prev != dir {
				t.Errorf("%s %q is named in both %s and %s", typ, m[2], prev, dir)
			}
			owner[key] = dir
		}
	}
}
