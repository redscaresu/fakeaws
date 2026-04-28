# Codex Review — Pass 15

## Verdict
2 BLOCKING findings, both fixed. All tests pass.

## BLOCKING #1 — Secrets Manager terminal-state refusal returned wrong wire shape
`ScheduleSecretDeletion` and `RestoreSecret` correctly described
"already destroyed" as a terminal-state refusal but wrapped the
error in `models.ErrConflict`. The wire mapping then surfaced
`ConflictException` instead of the dedicated `InvalidRequestException`
that `models.ErrTerminalState` is mapped to. Two distinct 409
sentinels collapsed into one.

**Fix.** Both refusal paths now use `models.ErrTerminalState`. The
existing `TestSecretStateMachine` repo test was updated. Pinned at
the wire layer with
`TestRegressionSecretsManagerTerminalStateWireShape`, which asserts
the body carries `InvalidRequestException`.

## BLOCKING #2 — /mock/state stripped FK-bearing fields from EC2 instances and EKS resources
The collections were emitted but with reduced fields. EC2 instance
state did not include `iam_instance_profile_name` or
`vpc_security_group_ids`. EKS clusters did not include
`security_group_ids` or `kubernetes_version`. EKS node groups did
not include `instance_types` or `scaling_config`. All are modeled
persistent fields; mutations to any of them were invisible through
the state surface, so update verification could false-green.

**Fix.** Extended `gatherEC2StateReal` instance entries and
`gatherEKSStateReal` cluster + nodegroup entries to include each
of the missing fields. `scaling_config` is JSON-decoded into
structured form so callers can pattern-match without re-parsing.

## Test status
`go test ./... -count=1` — all green:
- `handlers` 0.479s
- `handlers/awsproto` 0.329s
- `internal/audit` 0.480s
- `repository` 0.739s
- `examples` 0.170s
