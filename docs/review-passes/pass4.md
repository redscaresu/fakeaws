# Codex pass 4 — cumulative cross-service review

Date: 2026-04-28
Scope: full repo state post pass 1+2+3 fixes
Verdict: **BLOCKING**

## BLOCKING

### 1. EC2 /mock/state.security_groups still incomplete

**Files:** `handlers/ec2.go:1382-1413`, `repository/ec2.go:104-119`

`/mock/state.ec2.security_groups` was inferred from `instance.VPCSecurityGroupIDs`, so a standalone `aws_security_group` never appeared in state, and a shared SG appeared multiple times if attached to multiple instances. Breaks the "every collection populated" contract.

**Fix:** add a repository-level `ListSecurityGroups` path; have the gatherer emit each SG exactly once.

### 2. RDS /mock/state misses standalone groups + cluster_parameter_groups

**Files:** `handlers/rds.go:549-603`, `repository/rds.go:53-80`

`db_cluster_parameter_groups` was absent entirely; `db_subnet_groups` / `db_parameter_groups` were only surfaced if an instance referenced them, so standalone groups disappeared from state.

**Fix:** add list methods on the repo for subnet groups, parameter groups, cluster parameter groups, and clusters, then populate `/mock/state` directly from those collections instead of inferring from instances.

### 3. Secrets Manager /mock/state.versions only AWSCURRENT + AWSPREVIOUS

**Files:** `handlers/secretsmanager.go:265-279`, `repository/secretsmanager.go:232-320`

Older persisted rows in `secretsmanager_versions` remained in SQLite but became invisible after multiple rotations, so state under-reported the real collection.

**Fix:** add a repository `ListSecretVersions` path; emit every stored version row with its stage labels.

## Resolution

All three BLOCKING findings addressed in follow-up commit. Repository
gains four new list methods (ListSecurityGroups, ListDBSubnetGroups,
ListDBParameterGroups, ListDBClusterParameterGroups, ListDBClusters,
ListSecretVersions) and the four affected gatherers populate from
the new direct list paths.
