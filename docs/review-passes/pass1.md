# Codex pass 1 — S46 (EKS + SQS) review

Date: 2026-04-28
Scope: Slice 46 commits e1b25dd..14e74ca (Phase 4 — EKS + SQS)
Verdict: **BLOCKING**

## BLOCKING

### 1. EKS cluster create lacks single-VPC subnet/SG validation

**Files:** `repository/eks.go:133`, `repository/eks.go:139`, `handlers/eks_test.go:57`, `repository/eks_test.go:22`

Cluster create only existence-checks subnets and security groups; it never verifies that all subnets are in the same VPC or that every `security_group_id` belongs to that same VPC. `concepts.md` calls out EKS cluster create as requiring IAM-role / VPC subnet / security-group FK validation, and this is the same cross-parent mismatch class that already bit EC2.

**Fix:** on `CreateEKSCluster`, load the referenced subnets/SGs, derive the cluster VPC from the first subnet, reject any subnet or SG outside that VPC, and pin it in both repo and handler tests.

### 2. SQS queue delete violates tombstone-on-parent-delete contract

**Files:** `repository/sqs.go:38`, `repository/sqs.go:147`, `handlers/regression_test.go:273`

SQS queue delete hard-deletes messages via FK cascade. That violates the standing contract in `concepts.md` for tombstone semantics on parent delete, where in-flight messages must be rebadged to a deleted-queue tombstone instead of disappearing under consumers.

**Fix:** stop using plain `ON DELETE CASCADE` for the message rows in this path, implement queue-delete rebadging before parent removal, and replace the empty regression placeholder with a real assertion.

### 3. S46 regression tests are vacuous passes after LandedServices flip

**Files:** `handlers/regression_test.go:218`, `handlers/regression_test.go:278`

The S46 standing-pattern tests for `cache-baseline-lifecycle` and `tombstone-semantics-on-parent-delete` are vacuous passes now that `sqs` is in `LandedServices`; `requireHandlerImplemented(...)` returns and the test exits with no assertions. The current audit only catches skip-plus-assert patterns, not empty landed tests.

**Fix:** either implement real assertions for cache/reset and tombstone semantics now, or keep these tests gated until the behavior exists and extend the audit to fail landed-service regression stubs with zero assertions.

## SUGGEST

### A. SQS state gather is region-pinned to us-east-1

**File:** `handlers/sqs.go:267`

`/mock/state` only lists SQS queues from `us-east-1`. The rest of fakeaws state gatherers enumerate all regions, and this will silently drop queues if AWS scenarios move to `eu-west-1`.

**Fix:** add a region-agnostic list path for SQS state gathering, matching EKS/EC2/RDS.

## Resolution

All BLOCKING findings addressed in follow-up commits before continuing
to S47 implementation. SUGGEST item A also addressed.
