# Codex Review — Pass 6

## Verdict
3 BLOCKING findings, all fixed. All tests pass after the refactor.

## BLOCKING #1 — DynamoDB items leaked across regions
Tables had `region` in their PK, but `dynamodb_items` keyed on
`(account_id, table_name, hash_value, range_value)`. Same-named tables
in two regions shared a single item set, which violates AWS region
isolation.

**Fix.** Added `region` to the `dynamodb_items` PK and threaded it
through every Get/Put/Delete/Scan path. Pinned with
`TestDynamoDBItemRegionIsolation` in `repository/dynamodb_test.go`.

## BLOCKING #2 — EKS cluster keyed without region
`eks_clusters` PK was `(account_id, name)`, so a cluster named "demo"
in `us-east-1` blocked the same name in `eu-west-1`. Child tables
(node groups, addons) inherited the same gap.

**Fix.** Region added to `eks_clusters` PK, FK columns expanded to
`(account_id, region, cluster_name) → eks_clusters(account_id, region, name)`,
and every handler/repo signature now threads region. The state-gather
list paths (`ListEKSNodeGroups`, `ListEKSAddons`) accept empty region
to mean "all regions" so the dashboard can still aggregate.

## BLOCKING #3 — RDS resources keyed without region
All five RDS tables (`db_subnet_groups`, `db_parameter_groups`,
`db_cluster_parameter_groups`, `db_clusters`, `db_instances`) had PKs
without region, so cross-region name collisions were impossible to
test. The handler dispatcher passed region only to Create paths.

**Fix.** Added region to every RDS PK and FK relationship. Updated
all `Get*`/`Delete*` repo signatures to take region as the second
argument. Dispatcher now threads `chi.URLParam(r, "region")` to
every Describe/Delete/Modify handler. `rdsInstanceToXML` reads the
subnet group from `inst.Region` (the instance's own region, not a
caller-supplied one). Pinned with `TestRDS_RegionIsolation` in
`repository/rds_test.go`.

## SUGGEST findings
None this pass — the cross-region isolation gap was the dominant
correctness issue.

## Test status
`go test ./... -count=1` — all green:
- `handlers` 0.595s
- `handlers/awsproto` 0.548s
- `internal/audit` 0.690s
- `repository` 0.889s
- `examples` 0.263s
