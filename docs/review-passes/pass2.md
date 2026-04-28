# Codex pass 2 — S47 (Route53 + Secrets Manager) review

Date: 2026-04-28
Scope: Slice 47 commits afbb56f..d7e4a2d (Phase 5 — Route53 + Secrets Manager)
Verdict: **BLOCKING**

## BLOCKING

### 1. Route53 AliasTarget silently discarded

**Files:** `handlers/route53.go:258-261, 273-283, 320-325`

Apex CNAME is rejected with "use ALIAS", but `AliasTarget` is then silently discarded on write and never emitted on read. The repo schema already has `alias_target`, so this is an in-scope contract miss, not a deferred feature.

**Fix:** persist `rs.AliasTarget` in `ChangeResourceRecordSets` (encode as JSON into the alias_target column), round-trip it in `ListResourceRecordSets` (decode JSON, emit XML), and add a handler test for apex ALIAS create/list.

### 2. Destroyed secrets remain readable + listable

**Files:** `repository/secretsmanager.go:173-183, 273-308`, `handlers/secretsmanager.go:133-145, 219-236`

`ForceDeleteWithoutRecovery` moves a secret to `Destroyed`, but the secret remains readable and listable because `GetSecretValue`, `DescribeSecret`, and `ListSecrets` never gate on state. That violates the "fully destroyed" contract in `concepts.md`; only `RestoreSecret` is blocked today.

**Fix:** introduce `GetSecretActiveOrPending` (returns ErrNotFound for Destroyed), have `DescribeSecret` and `GetSecretValue` use it, and have `ListSecrets` filter out `state = Destroyed` rows. Pin with a test that all three read paths 404 after force-delete.

## SUGGEST

### A. Missing Secrets Manager operations

**Files:** `handlers/secretsmanager.go:35-53`, `handlers/secretsmanager_test.go:26-108`

The dispatcher still lacks `UpdateSecret`, `TagResource`, `UntagResource`, and `ListSecretVersionIds`, even though `concepts.md` and S47-T5 call out version listing and tagging in the v1 Secrets Manager surface.

**Fix:** either implement them in this slice with tests, or explicitly move them out of scope in the plan/backlog/docs so the accepted surface is consistent.

## Resolution

All BLOCKING findings addressed in follow-up commit. SUGGEST item A
resolved by explicit out-of-scope declaration in fakeaws/PLAN.md
§ "Phase 5 — DNS + secrets (S47) → Out of scope at v1" — these
operations are deferred to S48-T6 gap-fill if scenarios require them.
terraform-provider-aws tolerates their absence (no provider error).
