# Codex Review — Pass 7

## Verdict
2 BLOCKING findings, both fixed. All tests pass.

## BLOCKING #1 — Cross-region FK validation ignored region
EC2 parent lookups (`GetVPC`, `GetSubnet`, `GetSecurityGroup`,
`GetRouteTable`, `GetInternetGateway`, plus instance + EIP getters)
queried by `(account_id, id)` only. A handler at `/ec2/region/us-east-1`
could legitimately reference parents that exist only in `eu-west-1`,
because the lookup never checked region. EKS cluster create and RDS
subnet group create inherited the same gap via their own parent
checks.

**Fix.** Threaded region through every Get/Delete signature:
`GetVPC(account, region, id)`, `GetSubnet(account, region, id)`, etc.
Each query now filters on `region = ?` when region is non-empty
(empty region preserves account-wide list semantics for the audit
and state-gather paths). Every Create that does FK validation now
passes the child's `Region` to the parent lookup. EKS + RDS Create
paths thread region too.

Pinned with `TestEC2_CrossRegionFKRejected` in
`repository/ec2_test.go` — Subnet/SG/RouteTable referencing
different-region VPC IDs all return `ErrNotFound`.

## BLOCKING #2 — `/mock/state` omitted DynamoDB items + SQS messages
Both repositories persist their child collections (`dynamodb_items`,
`sqs_messages`), but their `gather*StateReal` only emitted the
parents (tables/queues). DynamoDB had no item collection at all;
SQS surfaced only a tombstone counter. Update-phase verification
that watches `/mock/state` couldn't see message-send or item-put
mutations.

**Fix.** `gatherDynamoDBStateReal` now iterates every table and
calls `ScanDynamoDBTable` per `(account, region, table)` to emit
`items: [...]`. `gatherSQSStateReal` calls a new
`ListSQSMessages(account, region)` repo method and emits
`messages: [...]`, with tombstoned messages still counted
separately for the existing regression-test 12 assertion.

Pinned with `TestRegressionStateGatherCollectionsComplete` in
`handlers/regression_test.go`.

## Test status
`go test ./... -count=1` — all green:
- `handlers` 0.576s
- `handlers/awsproto` 0.153s
- `internal/audit` 0.444s
- `repository` 0.647s
- `examples` 0.137s
