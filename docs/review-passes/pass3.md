# Codex pass 3 — cumulative cross-service review

Date: 2026-04-28
Scope: full repo state across S43–S47, post pass 1+2 fixes
Verdict: **BLOCKING**

## BLOCKING

### 1. Bare t.Skip in regression test #3

**Files:** `handlers/regression_test.go:92-95`, `handlers/regression_audit_test.go:58-121`

`TestRegressionRelativePathWrongCollectionRejection` still uses a bare `t.Skip()`. That violates the repo rule that `t.Skip` only appears inside `requireHandlerImplemented`, and it leaves standing-pattern #3 as a permanent vacuous pass. The audit misses it because it only looks for `requireHandlerImplemented` + `assert/require`, not direct `t.Skip`.

**Fix:** replace the skip with a real assertion on a landed surface (the comment notes EC2 in S44 might surface relative-path refs but doesn't yet), or keep it manifest-gated and extend the audit to fail any direct `t.Skip`/`t.Skipf` outside `requireHandlerImplemented`.

### 2. /mock/state gatherers partially populated

**Files:** `handlers/ec2.go:1340-1378`, `handlers/rds.go:544-561`, `handlers/eks.go:338-349`, `handlers/route53.go:383-395`, `handlers/secretsmanager.go:245-260`

`/mock/state` is only partially populated for several landed services:

- EC2 declares `security_groups` and `key_pairs` keys but never fills them
- RDS initializes `db_clusters` / `db_subnet_groups` but only emits instances and omits parameter-group collections entirely
- EKS emits clusters but not nodegroups / addons
- Route53 emits hosted zones but not record sets
- Secrets Manager emits secrets but not versions

That makes the load-bearing state surface incomplete and can false-green update/identity checks that rely on `/mock/state`.

**Fix:** make each gatherer emit every modeled collection as a non-nil list.

## SUGGEST

### A. SSE coverage matrix entry points at wrong test

**Files:** `coverage_matrix.yaml:85-93`, `handlers/s3_test.go:201-217`, `handlers/coverage_boost_test.go:661-690`

The `aws_s3_bucket_server_side_encryption_configuration` entry points `integration_test_func_name` at `^TestS3_PublicAccessBlockRoundTrip$`, but that test never touches encryption. The audit only checks regex existence, so this overclaims coverage.

**Fix:** point the matrix entry at a test that actually asserts SSE round-trip, or add a dedicated `TestS3_EncryptionRoundTrip` and reference that.

## Resolution

All BLOCKING findings addressed in follow-up commit. SUGGEST item A
addressed via the existing `TestCoverage_S3OwnershipAndEncryption`
test which exercises Put/Get encryption — matrix entry repointed.
