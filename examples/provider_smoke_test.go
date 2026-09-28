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
// Each example starts from POST /mock/reset. Examples listed in
// knownRed (known_red_test.go) must fail exactly as recorded there.
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
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	defaultFakeAWSURL = "http://127.0.0.1:8082"
	gateEnvVar        = "INFRAFACTORY_ENABLE_E2E"
)

// TestProviderSmokeWorking walks examples/working/<svc>/ and runs
// `tofu init && tofu apply -auto-approve && tofu plan -detailed-exitcode &&
// tofu destroy -auto-approve`. plan-after-apply MUST be no-op (exit 0
// from -detailed-exitcode means "no diff").
func TestProviderSmokeWorking(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	walkExamplesAndRun(t, "working", runWorkingExample)
}

// TestProviderSmokeMisconfigured walks examples/misconfigured/<svc>/.
// `tofu apply` MUST fail; the failure output MUST contain the string
// in expected.txt (the documented AWS error code).
func TestProviderSmokeMisconfigured(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	walkExamplesAndRun(t, "misconfigured", runMisconfiguredExample)
}

// TestProviderSmokeUpdates walks examples/updates/<svc>/, applies v1,
// asserts plan is clean, applies v2, asserts plan is clean, destroys.
// Each updates/ directory MUST contain v1.tfvars + v2.tfvars + main.tf.
func TestProviderSmokeUpdates(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	walkExamplesAndRun(t, "updates", runUpdatesExample)
}

// ----- discovery -----

// walkExamplesAndRun runs every example under examples/<tree>/ and
// judges the outcome against knownRed, keyed "<tree>/<dir>".
func walkExamplesAndRun(t *testing.T, tree string, run func(t *testing.T, dir string) *stageErr) {
	t.Helper()
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
		dir := filepath.Join(parent, ent.Name())
		t.Run(ent.Name(), func(t *testing.T) {
			resetFakeAWS(t)
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

func resetFakeAWS(t *testing.T) {
	t.Helper()
	resp, err := http.Post(defaultFakeAWSURL+"/mock/reset", "application/json", nil)
	require.NoError(t, err, "POST /mock/reset — is fakeaws running on %s?", defaultFakeAWSURL)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "POST /mock/reset")
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
