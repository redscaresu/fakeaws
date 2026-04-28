# Codex Review — Pass 9

## Verdict
1 BLOCKING finding, fixed. All tests pass.

## BLOCKING — RunInstances accepted unknown AMI ids; fixtures only in 8 regions
`RunInstances` validated subnet, security groups, and instance
profile, but never `ImageId`. The repo backstop in `CreateInstance`
also skipped the AMI — whatever string the caller supplied was
inserted as `ami_id`. So `ami-does-not-exist` silently created an
instance, masking misconfigurations in training scenarios.

The same area had a second inconsistency: `SeedEC2AMIFixtures` was
called at boot for an 8-region slice. `GetAMI` and `ListAMIs` are
strictly region-scoped, so outside that slice the canonical fixture
ids were 404. `RunInstances` would still succeed (no AMI check)
while `DescribeImages` returned empty.

**Fix.**
1. `CreateInstance` now calls `GetAMI(account, region, AMIID)` and
   returns `ErrNotFound` if the AMI doesn't exist in that region.
2. New `ensureAMIFixturesForRegion(account, region)` helper lazy-seeds
   the canonical fixture list for any region the user references.
   Called at the top of `ec2RunInstances` and `ec2DescribeImages`.
   `SeedAMI` is idempotent so re-entry is harmless.
3. `setupVPCSubnet` test helper seeds a stub AMI so existing repo
   tests still pass.

Pinned with two regression tests in `handlers/regression_test.go`:
- `TestRegressionRunInstancesRejectsUnknownAMI` — typoed AMI → 404.
- `TestRegressionRunInstancesAvailableInAnyRegion` — `ap-northeast-1`
  (outside the boot-time slice) accepts the canonical fixture id.

## Test status
`go test ./... -count=1` — all green:
- `handlers` 0.574s
- `handlers/awsproto` 0.549s
- `internal/audit` 0.447s
- `repository` 0.896s
- `examples` 0.184s
