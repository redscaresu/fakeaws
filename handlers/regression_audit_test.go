package handlers_test

// regression_audit_test.go — the two CI-enforced audits that keep
// the regression seed honest. Per concepts.md § "Resolved decisions"
// item 12 — both functions live in this single file.
//
// Test names start with TestRegressionSeedAudit so the CI workflow's
// regression-seed-audit job (declared in fakeaws/.github/workflows/ci.yml)
// runs them via `go test ./handlers/ -run "TestRegressionSeedAudit"`.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/redscaresu/fakeaws/handlers"
)

// TestRegressionSeedAuditManifestMatchesHandlers walks the manifest
// (handlers/regression_manifest.go::LandedServices) and the
// handlers/ directory; asserts:
//
//   (a) every id in LandedServices is satisfied by ≥1 handlers/<id>*.go
//       file (so "ec2" is satisfied collectively by ec2_network.go +
//       ec2_security.go + ec2_instance.go); and
//   (b) every service prefix in handlers/ has a manifest entry — the
//       audit groups files by their before-first-`_`-or-`.go` prefix
//       and asserts every prefix appears in LandedServices.
//
// Files that are not service handlers (handlers.go itself, admin.go,
// regression_manifest.go, regression_test.go, *_test.go) are excluded
// from the prefix check via the knownNonServiceFiles list.
func TestRegressionSeedAuditManifestMatchesHandlers(t *testing.T) {
	dir := handlersDir(t)

	// (a) Every LandedServices id has ≥1 satisfying file.
	for _, id := range handlers.LandedServices {
		matched := matchHandlerFile(t, dir, id)
		if !matched {
			t.Errorf("LandedServices entry %q has no matching handlers/%s*.go file", id, id)
		}
	}

	// (b) Every service prefix in handlers/ is in LandedServices.
	prefixes := serviceFilePrefixes(t, dir)
	for prefix := range prefixes {
		if !sliceContains(handlers.LandedServices, prefix) {
			t.Errorf("handlers/ has files with prefix %q but LandedServices is missing it; either add to manifest or rename the file", prefix)
		}
	}
}

// TestRegressionSeedAuditNoVacuousPasses parses every test file in
// handlers/ via go/ast and asserts no test function body contains
// both a requireHandlerImplemented(...) call AND an assert./require.
// call. That combination is a vacuous-pass smell — the manifest-
// gated skip should fire BEFORE the test reaches its assertions, so
// the two should never coexist in the same func body.
//
// When a service flips to landed in LandedServices, requireHandlerImplemented
// stops skipping and the assertions run; this audit catches the case
// where someone forgot to remove the requireHandlerImplemented call
// after lighting up the assertions.
func TestRegressionSeedAuditNoVacuousPasses(t *testing.T) {
	dir := handlersDir(t)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read handlers/: %v", err)
	}
	fset := token.NewFileSet()
	for _, ent := range entries {
		if !strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		// Skip the audit file itself.
		if ent.Name() == "regression_audit_test.go" {
			continue
		}
		path := filepath.Join(dir, ent.Name())
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			hasRequire := false
			hasAssert := false
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if name, ok := callIdentName(call); ok {
					if name == "requireHandlerImplemented" {
						hasRequire = true
					}
				}
				if pkg, sel, ok := callSelectorName(call); ok {
					if pkg == "assert" || pkg == "require" {
						hasAssert = true
					}
					_ = sel
				}
				return true
			})
			if hasRequire && hasAssert {
				t.Errorf("vacuous-pass risk in %s::%s — requireHandlerImplemented coexists with assert./require. in the same func body. Either remove the requireHandlerImplemented call (service has landed) or remove the assertion (this is a stub).",
					ent.Name(), fn.Name.Name)
			}
			return true
		})
	}
}

// ----- helpers (local to the audit suite) -----

func handlersDir(t *testing.T) string {
	t.Helper()
	// Tests run from the package directory; handlers/ is the package itself.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}

func matchHandlerFile(t *testing.T, dir, id string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read handlers/: %v", err)
	}
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		base := strings.TrimSuffix(name, ".go")
		// Exact match (e.g., "iam.go" → id "iam") or prefix-with-_
		// (e.g., "ec2_network.go" → id "ec2").
		if base == id || strings.HasPrefix(base, id+"_") {
			return true
		}
	}
	return false
}

// knownNonServiceFiles lists handler-package files that aren't
// service handlers — they're shared infrastructure (router wiring,
// admin endpoints, audit tests, etc.) and shouldn't appear in
// LandedServices.
var knownNonServiceFiles = map[string]bool{
	"handlers.go":             true,
	"admin.go":                true,
	"regression_manifest.go":  true,
}

func serviceFilePrefixes(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read handlers/: %v", err)
	}
	out := map[string]bool{}
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if knownNonServiceFiles[name] {
			continue
		}
		base := strings.TrimSuffix(name, ".go")
		// Service prefix: everything before the first '_' (so
		// ec2_network.go → "ec2"; iam.go → "iam").
		prefix := base
		if i := strings.Index(base, "_"); i > 0 {
			prefix = base[:i]
		}
		out[prefix] = true
	}
	return out
}

func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func callIdentName(call *ast.CallExpr) (string, bool) {
	if id, ok := call.Fun.(*ast.Ident); ok {
		return id.Name, true
	}
	return "", false
}

func callSelectorName(call *ast.CallExpr) (string, string, bool) {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok {
			return pkg.Name, sel.Sel.Name, true
		}
	}
	return "", "", false
}

// debugSortedServices returns the manifest sorted alphabetically; used
// only by failure messages.
func debugSortedServices() []string {
	out := append([]string(nil), handlers.LandedServices...)
	sort.Strings(out)
	return out
}

var _ = debugSortedServices // referenced to silence "unused" if no failure
