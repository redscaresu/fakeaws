# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
