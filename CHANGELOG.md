# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (M68 + M69 + M73 + M77 + M82 + M85, 2026-05-28)
- **M68 — SQS QueueUrl bug.** `CreateQueue` now derives the QueueUrl from `X-Forwarded-Host` / `r.Host` (path-style `<host>/<account>/<queue>`); previously hardcoded `sqs.us-east-1.fakeaws.local` which the AWS SDK couldn't reach. Added `ListQueueTags` + `TagQueue` + `UntagQueue` + `SetQueueAttributes` no-op stubs and the AWS-spec `AWS.SimpleQueueService.NonExistentQueue` 400 (was generic 404) so destroy-wait converges.
- **M69 — IAM GetPolicyVersion + ListPolicyVersions handlers** added at `handlers/iam.go`. terraform-provider-aws calls these immediately after CreatePolicy; without them `aws_iam_policy` failed apply with ResourceNotFoundException. Returns URL-encoded PolicyDocument matching real IAM's CreatePolicy → v1 default-version contract.
- **M73 — README badges** (CI / License / Go-version) added under the `# fakeaws` heading for parity with the other 3 repos.
- **M82 — Dependabot.** `.github/dependabot.yml` with weekly grouped updates for gomod + github-actions ecosystems.
- **M85 — `TestRegressionSeedAuditHasPatterns`** added to `handlers/regression_audit_test.go`. Counts `^TestRegression` funcs (excluding `^TestRegressionSeedAudit`), fails CI if below `min(len(LandedServices), 8)`. Negative-path verified: disabling the 25 patterns trips the guard with an actionable error citing the M75/M79 catalogue.

### Changed (M77)
- **M77 — modernc.org/sqlite 1.50.0** baseline (was at 1.50.0 already; coordinated bump verified). go.mod stays at Go 1.25.0.

### Added (earlier — M51+)
- End-to-end TF lifecycle parity for `aws_db_instance` + `aws_db_subnet_group` + `aws_db_parameter_group` (M61): `awsproto.WriteServiceError` lets handlers emit the AWS-spec service-specific 404 codes (`DBInstanceNotFound`, `DBSubnetGroupNotFoundFault`, `DBParameterGroupNotFound`, `DBClusterNotFoundFault`) the SDK's delete-wait state machines actually check for — the generic `ResourceNotFoundException` previously bubbled as fatal. `DeleteDBInstance` returns the deleted instance wrapped in `<DeleteDBInstanceResult><DBInstance>` (was nil payload). `DescribeDBInstances` parses `Filters.Filter.N.Name=dbi-resource-id` and resolves back to the underlying instance. `DbiResourceId` is now a SHA-1 hash of the identifier (`db-<16hex>`) — stable across reads but visibly distinct from the user-given DBInstanceIdentifier. `repository.RDSInstance` persists user-supplied `MasterUsername` / `AllocatedStorage` / `StorageType` / `StorageEncrypted` / `MultiAZ` / `Port` / `PubliclyAccessible` / `BackupRetentionPeriod` / `Tags`; Read echoes them verbatim so plan no longer forces replacement on every refresh.
- End-to-end TF lifecycle parity for `aws_secretsmanager_secret` + `aws_secretsmanager_secret_version` (M62): repository's `GetSecret` / `ScheduleSecretDeletion` / `RestoreSecret` / `PutSecretValue` / `GetSecretValue` accept SecretId as either secret name OR full ARN (terraform-provider-aws hands the create-response ARN back as the id; name-only lookup broke create-wait with "couldn't find resource" until timeout). `DescribeSecret` returns `CreatedDate` / `LastChangedDate` / `DeletionDate` as JSON-number epoch (SDK rejects strings with "expected DeletionDateType to be a JSON Number"), populated `VersionIdsToStages`, and `Tags` as `[{Key,Value}]` slice. Added `GetResourcePolicy` (omits `ResourcePolicy` field entirely — empty string fails JSON parse), `ListSecretVersionIds`, and no-op `TagResource` / `UntagResource` / `PutResourcePolicy` / `DeleteResourcePolicy` handlers (provider polls these on every refresh; default "not yet implemented" 404 bubbled as fatal).
- Per-resource Read-flow field parity (M57, fakeaws@1206f7c): EC2 subnet (`availabilityZoneId`, `availableIpAddressCount`, `ownerId`, `subnetArn`, `mapPublicIpOnLaunch`, `assignIpv6AddressOnCreation`, `ipv6CidrBlockAssociationSet`, `defaultForAz`, `privateDnsNameOptionsOnLaunch`) + `SubnetId.N` filter parsing + `DescribeNetworkInterfaces` empty stub; EKS cluster (`endpointPublicAccess`/`endpointPrivateAccess` defaults, `createdAt` as Unix epoch float) + EKS node group (`scalingConfig` echo, `createdAt` epoch); RDS DB instance shape (`Endpoint`, `AllocatedStorage`, `StorageEncrypted`, `MasterUsername`, `AvailabilityZone`, `BackupRetentionPeriod`); RDS `ListTagsForResource` + `DescribeDBParameters` stubs.
- Query-RPC envelope rewrite (M51, fakeaws@f48dd0b): `WriteEC2QueryRPCResponse` added for EC2's wrapper-less envelope shape; `WriteQueryRPCResponse` (IAM/RDS) strips Go-type wrappers via `marshalInnerXML` using a lowercase-vs-uppercase first-letter rule (transparent `ec2CreateVpcResult` / `iamListRolePoliciesResult` wrappers stripped; legitimate AWS element names like `Role` / `AccessKey` / `Vpc` preserved by their XMLName). All 34 EC2 call sites migrated.
- IAM additions: `ListRolePolicies`, `ListRoleTags`, `ListInstanceProfilesForRole` handlers (fakeaws@fea333e).
- EC2 VPC response standardisation: `OwnerId`, `DhcpOptionsId`, `CidrBlockAssociationSet` (fakeaws@d7cce92).
- README "API Compatibility" section documenting the wire-shape contract + the `examples/working/<svc>` smoke harness (`apply → plan -detailed-exitcode 0 → destroy`) every handler is validated against (fakeaws@d5e68e3).
- 9 AWS services across 5 wire formats: IAM (Query-RPC), S3 (REST/XML), EC2 (Query-RPC: VPC + Subnet + IGW + RouteTable + Route + EIP + SG + Instance + KeyPair + AMI fixture set), RDS (Query-RPC: DBInstance + DBCluster + DBSubnetGroup + DBParameterGroup + ClusterParameterGroup), DynamoDB (JSON 1.0 with X-Amz-Target), EKS (JSON-REST), SQS (Query-RPC), Route53 (REST/XML), Secrets Manager (JSON 1.1).
- 201 handler-side tests + 16 standing-pattern regression tests + audit infrastructure (`coverage_matrix.yaml` + `internal/audit/audit_test.go` + `handlers/regression_manifest.go` + `handlers/regression_audit_test.go`).
- 10 working terraform examples + 5 misconfigured + 6 updates examples; auto-discovery via `examples/provider_smoke_test.go` walks all three trees.
- Aggregate handler coverage 82.4% (verified via `go test -coverprofile=cov.out -covermode=atomic ./handlers/...`).
- `awsproto/` helper package: Query-RPC parser + XML response writer, JSON 1.0/1.1 helpers, x-amz-target parser, per-protocol error mappers, per-service ARN builders.
- Admin endpoints (`/mock/state` schema-versioned at v1, `/mock/reset`, `/mock/snapshot`, `/mock/restore`, `/mock/state/{service}`).
- 17-pass codex review loop concluded at pass 17 (2 consecutive NOTHING_TO_IMPROVE responses); archived under `docs/review-passes/passN.md`.

### Security
- `.githooks/pre-commit` + `make install-hooks` runs `gitleaks protect --staged` (with strict `.gitleaks.toml` overriding the gitleaks 8.x default allowlist of canonical AWS placeholder keys) then `go test`.
- Full-history `gitleaks detect` sweep across 60 commits returned zero leaks (S48-T8).
- `SECURITY.md` with private vulnerability reporting via GitHub Security Advisories.
- Apache-2.0 LICENSE (added 2026-05-23).

### Removed
- `/mock/faults` fault-injection endpoint (S49-T1) — briefly shipped at fakeaws@0fa51c2, reverted at fakeaws@26e97c8 on design grounds. The mock's value is fast feedback; latency simulation defeats that. Retry/backoff logic lives in the SDK and provider, not in user HCL.
