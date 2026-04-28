# Codex Review — Pass 10

## Verdict
2 BLOCKING findings, both fixed. All tests pass.

## BLOCKING #1 — IAM access keys missing from /mock/state.iam
The repo persists access keys (`CreateAccessKey`/`ListAccessKeys`),
the handler ships full CRUD, and the coverage matrix declares
`aws_iam_access_key`. But `gatherIAMStateReal()` only emitted
roles/policies/instance_profiles/users — access keys never appeared
in `/mock/state`, so update-phase verification was blind to them.

**Fix.** Extended `ListAccessKeys(account, userName)` to accept
empty `userName` as account-wide enumeration. `gatherIAMStateReal()`
now emits an `access_keys` collection with `user_name`,
`access_key_id`, `status`, and `created_at`. Pinned with
`TestIAM_MockStateAccessKeysSurfaced` in `handlers/iam_test.go`.

## BLOCKING #2 — EC2 route_tables / routes / route_table_associations / eips missing from /mock/state.ec2
`gatherEC2StateReal()` emitted only vpcs/subnets/security_groups/
instances/key_pairs/internet_gateways. Route tables, routes,
associations, and EIPs were creatable + describable through the
handlers and persisted in SQLite, but invisible in `/mock/state`.
The VPC-network scenario bundle relies on `/mock/state` for update
verification — orphaned route tables or unattached EIPs slipped
past the assertions.

**Fix.** Added repo list methods:
- `ListRouteTables(account, region)` — empty region = all regions.
- `ListRoutes(account)` — account-wide; routes follow parent table.
- `ListRouteTableAssociations(account)` — account-wide.
- `ListEIPs(account, region)` — empty region = all regions.

Plus `awsproto.BuildEC2EIPARN(region, allocationID)` for topology
parity. `gatherEC2StateReal()` now emits all four collections with
the standard non-nil empty-list initialization. Pinned with
`TestRegressionStateGatherEC2Collections` in
`handlers/regression_test.go`.

## Test status
`go test ./... -count=1` — all green:
- `handlers` 0.505s
- `handlers/awsproto` 0.351s
- `internal/audit` 0.498s
- `repository` 0.691s
- `examples` 0.173s
