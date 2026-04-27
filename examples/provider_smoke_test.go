// Package examples — auto-discovered provider smoke harness.
//
// Per concepts.md "Coverage requirements" rule 2: every example dir
// under examples/{working,misconfigured,updates}/ is auto-discovered
// here and run through the per-tree contract:
//
//   working/      apply → plan -detailed-exitcode (no diff) → destroy
//   misconfigured/ apply MUST fail with the documented AWS error code
//                  (matched against expected.txt in the same dir)
//   updates/      apply -var-file=v1.tfvars → plan no-op → apply -var-file=v2.tfvars → plan no-op → destroy
//
// Adding a directory to ANY of the three trees auto-registers — no
// per-example test ticket. Each subdirectory is its own t.Run sub-test.
//
// Gating:
//   - The smoke loop is gated by INFRAFACTORY_ENABLE_E2E=1 because it
//     shells out to `tofu` and assumes a fakeaws server is reachable
//     at FAKEAWS_URL (default http://127.0.0.1:8082). CI runs this
//     job after `make fakeaws-up` from the infrafactory Makefile.
//   - Without the env var, the test t.Skip's with a clear message —
//     mirroring the gating pattern infrafactory uses for tofu-driven
//     e2e tests.
//
// This package is `examples_test` so the auto-discovery walks the
// repo via runtime.Caller (mirror of internal/audit/audit_test.go's
// repoRoot helper).
package examples_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
	root := repoRoot(t)
	dir := filepath.Join(root, "examples", "working")
	walkExamplesAndRun(t, dir, runWorkingExample)
}

// TestProviderSmokeMisconfigured walks examples/misconfigured/<svc>/.
// `tofu apply` MUST fail; the failure output MUST contain the string
// in expected.txt (the documented AWS error code).
func TestProviderSmokeMisconfigured(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	root := repoRoot(t)
	dir := filepath.Join(root, "examples", "misconfigured")
	walkExamplesAndRun(t, dir, runMisconfiguredExample)
}

// TestProviderSmokeUpdates walks examples/updates/<svc>/, applies v1,
// asserts plan is clean, applies v2, asserts plan is clean, destroys.
// Each updates/ directory MUST contain v1.tfvars + v2.tfvars + main.tf.
func TestProviderSmokeUpdates(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	root := repoRoot(t)
	dir := filepath.Join(root, "examples", "updates")
	walkExamplesAndRun(t, dir, runUpdatesExample)
}

// ----- discovery -----

func walkExamplesAndRun(t *testing.T, parent string, run func(t *testing.T, dir string)) {
	t.Helper()
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
		dir := filepath.Join(parent, ent.Name())
		t.Run(ent.Name(), func(t *testing.T) {
			run(t, dir)
		})
	}
	if !any {
		t.Logf("no example subdirectories under %s — that's fine, gap-fill happens in S48-T6", parent)
	}
}

// ----- per-tree contracts -----

func runWorkingExample(t *testing.T, dir string) {
	t.Helper()
	tofuInit(t, dir)
	tofuApply(t, dir, nil)
	tofuPlanNoOp(t, dir, nil)
	tofuDestroy(t, dir, nil)
}

func runMisconfiguredExample(t *testing.T, dir string) {
	t.Helper()
	expected, err := os.ReadFile(filepath.Join(dir, "expected.txt"))
	if err != nil {
		t.Fatalf("misconfigured example missing expected.txt: %v", err)
	}
	expectedString := strings.TrimSpace(string(expected))
	if expectedString == "" {
		t.Fatalf("misconfigured example expected.txt is empty — must contain the AWS error code we expect")
	}

	tofuInit(t, dir)
	out, err := tofuApplyExpectingFailure(t, dir)
	if err == nil {
		t.Fatalf("misconfigured example: tofu apply UNEXPECTEDLY succeeded; expected failure containing %q", expectedString)
	}
	if !strings.Contains(out, expectedString) {
		t.Fatalf("misconfigured example: tofu apply failed but output does not contain expected error %q\noutput:\n%s",
			expectedString, out)
	}
}

func runUpdatesExample(t *testing.T, dir string) {
	t.Helper()
	v1 := filepath.Join(dir, "v1.tfvars")
	v2 := filepath.Join(dir, "v2.tfvars")
	for _, p := range []string{v1, v2} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("updates example missing %s: %v", p, err)
		}
	}

	tofuInit(t, dir)
	tofuApply(t, dir, []string{"-var-file=" + v1})
	tofuPlanNoOp(t, dir, []string{"-var-file=" + v1})
	tofuApply(t, dir, []string{"-var-file=" + v2})
	tofuPlanNoOp(t, dir, []string{"-var-file=" + v2})
	tofuDestroy(t, dir, []string{"-var-file=" + v2})
}

// ----- tofu wrappers -----

func tofuInit(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("tofu", "init", "-input=false")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tofu init: %v\n%s", err, out)
	}
}

func tofuApply(t *testing.T, dir string, extraArgs []string) {
	t.Helper()
	args := append([]string{"apply", "-auto-approve", "-input=false"}, extraArgs...)
	cmd := exec.Command("tofu", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tofu apply: %v\n%s", err, out)
	}
}

func tofuApplyExpectingFailure(t *testing.T, dir string) (string, error) {
	t.Helper()
	cmd := exec.Command("tofu", "apply", "-auto-approve", "-input=false")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func tofuPlanNoOp(t *testing.T, dir string, extraArgs []string) {
	t.Helper()
	args := append([]string{"plan", "-detailed-exitcode", "-input=false"}, extraArgs...)
	cmd := exec.Command("tofu", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	// -detailed-exitcode: 0 = no changes, 1 = error, 2 = changes pending.
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 0 {
			t.Fatalf("tofu plan -detailed-exitcode (expected exit 0 = no diff): %v\n%s", err, out)
		}
	}
}

func tofuDestroy(t *testing.T, dir string, extraArgs []string) {
	t.Helper()
	args := append([]string{"destroy", "-auto-approve", "-input=false"}, extraArgs...)
	cmd := exec.Command("tofu", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tofu destroy: %v\n%s", err, out)
	}
}

// ----- helpers -----

func requireE2EGate(t *testing.T) {
	t.Helper()
	if os.Getenv(gateEnvVar) != "1" {
		t.Skipf("set %s=1 to run example smoke tests (requires tofu + fakeaws on %s)",
			gateEnvVar, defaultFakeAWSURL)
	}
}

func requireTofu(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tofu"); err != nil {
		t.Skipf("tofu not on PATH: %v", err)
	}
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
