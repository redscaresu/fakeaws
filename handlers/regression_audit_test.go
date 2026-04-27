package handlers

import "testing"

// This file is the stub shipped by S43-T1. It exists so the CI
// `regression-seed-audit` job (declared in .github/workflows/ci.yml)
// resolves cleanly from day one — `go test ./handlers/ -run
// "TestRegressionSeedAudit"` finds something to run and passes
// vacuously.
//
// S43-T10 replaces these no-op bodies with the real audit logic:
//
//   - TestRegressionSeedAuditManifestMatchesHandlers walks
//     handlers/regression_manifest.go::LandedServices and asserts
//     every id is satisfied by ≥1 handlers/<id>*.go file, AND every
//     service prefix in handlers/ has a manifest entry.
//
//   - TestRegressionSeedAuditNoVacuousPasses parses test bodies via
//     go/ast and asserts no requireHandlerImplemented(...) call
//     coexists with assert./require. calls in the same func.
//
// See concepts.md § "Resolved decisions" item 12 for the full schema.

func TestRegressionSeedAuditManifestMatchesHandlers(t *testing.T) {
	t.Log("S43-T1 stub — real audit lands in S43-T10")
}

func TestRegressionSeedAuditNoVacuousPasses(t *testing.T) {
	t.Log("S43-T1 stub — real audit lands in S43-T10")
}
