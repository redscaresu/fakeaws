# Codex Review — Pass 14

## Verdict
2 BLOCKING findings, both fixed. All tests pass.

## BLOCKING #1 — PutSecretValue silently wrote to force-deleted secrets
The destroyed-secret terminal contract was only enforced on read
paths. `GetSecretValue` correctly used `GetSecretActiveOrPending`,
but `PutSecretValue` used plain `GetSecret`, which returns rows in
the `Destroyed` state too. Result: after
`DeleteSecret(... ForceDeleteWithoutRecovery=true)`, a fresh
`PutSecretValue` returned 200 and persisted a hidden version row
that `DescribeSecret`/`GetSecretValue`/`ListSecrets` all treated as
gone.

**Fix.** Replaced the lookup in `PutSecretValue` with
`GetSecretActiveOrPending`, matching every other write/read surface.
Pinned with `TestRegressionPutSecretValueRefusedAfterForceDelete`
in `handlers/regression_test.go`.

## BLOCKING #2 — coverage-audit CI job silently skipped scenario half
`assertScenarioCoversResource` reads `../infrafactory/scenarios/training`
relative to the fakeaws checkout. If that directory isn't present,
it logs and returns without failing. The CI workflow only checked
out fakeaws, so this branch was always taken — invariant `(e)`
(scenario_resource_type backed by anchors) was effectively
unenforced under the required `coverage-audit` job.

**Fix.** The `coverage-audit` workflow now checks out both
`fakeaws` (into `./fakeaws`) and `redscaresu/infrafactory` (into
`./infrafactory`) so the audit's sibling-dir lookup resolves and
the scenario half runs live.

## Test status
`go test ./... -count=1` — all green:
- `handlers` 0.590s
- `handlers/awsproto` 0.431s
- `internal/audit` 0.185s
- `repository` 0.657s
- `examples` 0.138s
