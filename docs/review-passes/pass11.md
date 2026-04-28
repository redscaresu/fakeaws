# Codex Review — Pass 11

## Verdict
2 BLOCKING findings, both fixed. All tests pass.

## BLOCKING #1 — coverage_matrix.yaml missing landed S3 sub-resources
The matrix declared only `aws_s3_bucket`,
`aws_s3_bucket_versioning`, and
`aws_s3_bucket_server_side_encryption_configuration`. But the
shipped S3 surface also includes bucket policy, public access
block, and ownership controls — all with real handlers, repo rows,
and tests. Same source-of-truth drift class pass 5 fixed for
IAM/EC2/RDS, just in S3.

**Fix.** Added matrix entries for `aws_s3_bucket_policy`,
`aws_s3_bucket_public_access_block`, and
`aws_s3_bucket_ownership_controls` with appropriate
working/misconfigured/updates exemption metadata and
`integration_test_func_name` regexes pointing at existing tests.

## BLOCKING #2 — Vacuous-pass audit detector blind to plain testing.T assertions
`TestRegressionSeedAuditNoVacuousPasses` was supposed to flag any
test that retains `requireHandlerImplemented(...)` after the
service has landed (the skip helper becomes a no-op, but the
intent is to remove the call). The detector only counted
`assert.` and `require.` (testify) calls. This regression suite
uses plain `t.Errorf`/`t.Fatalf` instead, so 5 IAM tests retained
the now-vacuous `requireHandlerImplemented` call without the
audit catching it.

**Fix.** Broadened the detector to also count standard
`testing.T` failure paths: `Error`, `Errorf`, `Fatal`, `Fatalf`,
`Fail`, `FailNow`. The audit then correctly flagged 5 IAM tests
in `regression_test.go` (CrossAccountFKRejection,
WrongCollectionFKRejection, Distinct409Sentinels,
ResourceExistenceGateOnSubResource,
ServerStampedFieldsNeverTrusted). Removed the now-vacuous
`requireHandlerImplemented` calls from those 5 tests.

## Test status
`go test ./... -count=1` — all green:
- `handlers` 1.128s
- `handlers/awsproto` 0.338s
- `internal/audit` 0.608s
- `repository` 1.294s
- `examples` 0.285s
