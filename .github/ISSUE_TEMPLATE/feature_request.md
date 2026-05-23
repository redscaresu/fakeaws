---
name: Feature request
about: New AWS service or behavior change.
title: '[feature] '
labels: enhancement
assignees: ''
---

## What's missing

<!-- Which AWS service / endpoint / behavior isn't covered today. -->

## Why it matters

<!-- Which infrafactory training scenario needs it, or which provider operation hits the UNIMPLEMENTED log line. -->

## Wire format

<!-- Which of fakeaws's 5 wire formats does the new service use:
- Query-RPC (Action=...&Version=...)
- JSON 1.0 (X-Amz-Target)
- JSON 1.1
- REST/XML
- REST/JSON
-->

## Spec evidence

<!-- Link to AWS docs / terraform-provider-aws source / a captured real-AWS request-response pair. -->

## Per-bundle acceptance

A new service MUST land as a single PR including ALL of:

- [ ] `handlers/<service>.go` + dispatcher wiring
- [ ] `handlers/<service>_test.go` (CRUD + FK + cascade + state-machine where applicable)
- [ ] `examples/working/<service>/`
- [ ] `examples/misconfigured/<service>_*/` (a real fakeaws-only error terraform validate can't catch)
- [ ] `examples/updates/update_<service>/`
- [ ] `coverage_matrix.yaml` entry
- [ ] `LandedServices += "<service>"` in `handlers/regression_manifest.go`
- [ ] Scenario anchor in infrafactory's `scenarios/training/`

`TestFullCoverageAudit` + `TestRegressionSeedAuditManifestMatchesHandlers` enforce this at CI time. See `concepts.md` § "Per-bundle rule".
