# Codex Review — Pass 8

## Verdict
2 BLOCKING findings, both fixed. All tests pass.

## BLOCKING #1 — DescribeSubnets and DescribeInternetGateways leaked across regions
Pass 6/7 closed region isolation on PKs and write-path FK validation,
but the EC2 read paths were still account-wide. `DescribeSubnets`
received the request region from `/ec2/region/<region>` and dropped
it; the repo `ListSubnets(account, vpcFilter)` filtered only by
account and (optionally) VPC. `DescribeInternetGateways` had the
same shape — `ListInternetGateways(account)` was account-wide and
deliberately rehydrated rows with empty-region lookups.

A caller hitting `/ec2/region/us-east-1` could see subnets and IGWs
that exist only in `eu-west-1`. Terraform refresh in one region
would observe foreign-region resources, breaking the same isolation
contract pass 6/7 closed on writes.

**Fix.** `ListSubnets(account, region, vpcID)` and
`ListInternetGateways(account, region)` now scope to region when
non-empty. Empty-region preserves the account-wide path used by
`/mock/state` aggregation. Handlers thread `chi.URLParam(r, "region")`.
Pinned with `TestRegressionEC2DescribeRegionScoped`.

## BLOCKING #2 — `/mock/state` hard-coded a region slice
`gatherEC2StateReal` (key pairs) and `gatherSecretsManagerStateReal`
walked a literal 8-region slice. Resources created in any region
outside that slice (e.g. `ap-northeast-1`, `ca-central-1`) remained
fully usable through the service handlers but disappeared from
`/mock/state`, creating a false-green path for update-phase
verification.

**Fix.** `ListKeyPairs(account, region)` and
`ListSecrets(account, region)` now treat empty region as
"all regions", returning every persisted row. Both gatherers
consume the account-wide path. While in the file, also added
`/mock/state.ec2.internet_gateways` (it had never been emitted,
even though IGWs are part of the topology). Pinned with
`TestRegressionStateGatherAccountWide` using `ap-northeast-1`.

## Test status
`go test ./... -count=1` — all green:
- `handlers` 0.495s
- `handlers/awsproto` 0.452s
- `internal/audit` 0.330s
- `repository` 0.659s
- `examples` 0.135s
