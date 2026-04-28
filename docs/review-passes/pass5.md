# Codex pass 5 — cumulative cross-service review

Date: 2026-04-28
Scope: full repo state post pass 1+2+3+4 fixes
Verdict: **BLOCKING**

## BLOCKING

### 1. coverage_matrix.yaml is incomplete relative to shipped surface

**Files:** `AGENTS.md:14-16`, `coverage_matrix.yaml:35-205`, `handlers/iam_test.go:195-280`, `handlers/ec2_test.go:521-620`, `handlers/rds.go:258-374`

`coverage_matrix.yaml` is the declared source-of-truth manifest of every landed `aws_resource_type`, but it omits shipped surfaces with real handlers/tests: `aws_iam_instance_profile`, `aws_iam_user`, `aws_iam_access_key`, `aws_eip`, `aws_key_pair`, `aws_rds_cluster`, `aws_db_cluster_parameter_group`. The file even explicitly documented the RDS omission (commented as deferral). That left `TestFullCoverageAudit` blind for those resources — S48-T7's source-of-truth contract was false.

**Fix:** add matrix entries for every shipped resource type, using explicit `*_exempt` reasons where needed. Resources without a dedicated scenario use empty `scenario_resource_type` (the audit's `assertScenarioCoversResource` skips when empty).

## SUGGEST

### A. EKS gather bypasses repository List APIs

**Files:** `handlers/eks.go:356-404`, `repository/repository.go:96-100`, `repository/eks.go:194-219`

EKS `/mock/state` was the outlier after the pass-4 list-method cleanup: it bypassed repository list APIs, opened raw `rows`, then issued nested `GetEKSNodeGroup` / `GetEKSAddon` queries against a repo configured with `SetMaxOpenConns(1)`. Even if current tests happened to pass, this is the highest-risk handler/repo divergence in the state path.

**Fix:** add `ListEKSNodeGroups` and `ListEKSAddons` repository methods; have `gatherEKSStateReal` consume fully materialized slices only.

## Resolution

Both findings addressed:

- BLOCKING: 7 new matrix entries (3 IAM, 2 EC2, 2 RDS) covering
  every shipped resource type with explicit exemptions and integration-
  test regexes. Empty `scenario_resource_type` because none of these
  appear in scenario YAMLs at v1.
- SUGGEST: `repository.ListEKSNodeGroups` + `ListEKSAddons` added;
  `gatherEKSStateReal` rewritten to use them. Eliminates the nested-
  query deadlock risk under SetMaxOpenConns(1).
