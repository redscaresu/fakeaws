# Contributing to fakeaws

`fakeaws` is the AWS-side mock server for the [InfraFactory](https://github.com/redscaresu/infrafactory) project. It simulates AWS APIs across 5 wire formats (Query-RPC, JSON 1.0, JSON 1.1, REST/XML, REST/JSON) against a local SQLite database so InfraFactory's Layer 2 validation can run offline against a deterministic backend.

## TL;DR

1. Open an issue first for non-trivial changes (especially new services).
2. Each service lands as a **bundle**: handler + tests + examples + scenario anchors + coverage_matrix.yaml entry + `LandedServices` flip — all in one PR (per the rule in `concepts.md`).
3. `make test` must be green.
4. Pre-commit hook (`make install-hooks`) runs `gitleaks` + `go test`.
5. `TestFullCoverageAudit` + `TestRegressionSeedAuditManifestMatchesHandlers` enforce the per-bundle rule at CI time.

## Setup

Required: Go 1.24+, `make`. Optional: `gitleaks` for the pre-commit hook.

```bash
git clone https://github.com/redscaresu/fakeaws.git
cd fakeaws
make install-hooks
make test
make run    # serves the mock at :8082
```

## Per-bundle rule

When you add a new AWS service to fakeaws, the SAME PR must include:

1. **Handler file**: `handlers/<service>.go` plus any per-action helpers.
2. **Handler tests**: `handlers/<service>_test.go` covering CRUD + FK + cascade + state-machine transitions where applicable.
3. **Examples**: `examples/working/<service>/`, `examples/misconfigured/<service>_*/` (where the misconfigured example demonstrates a real fakeaws-only error that `terraform validate` cannot catch), and `examples/updates/update_<service>/`.
4. **Scenario anchor**: a `cloud: aws` training scenario in InfraFactory's `scenarios/training/` that exercises the new service end-to-end.
5. **coverage_matrix.yaml entry**: documents the integration test + example dirs + scenario anchor for the new service.
6. **`LandedServices` flip**: add `<service>` to `handlers/regression_manifest.go::LandedServices` so the regression test suite stops skipping its standing patterns.

The two CI-enforced audits prevent partial bundles from sneaking past review:

- `TestRegressionSeedAuditManifestMatchesHandlers` (handlers/regression_audit_test.go): every service prefix in `handlers/` must appear in `LandedServices`.
- `TestFullCoverageAudit` (internal/audit/audit_test.go): every `coverage_matrix.yaml` entry must have an integration test, example dirs (or documented exemption), and ≥1 scenario anchor.

## Wire formats

AWS uses different wire formats per service family. The `handlers/awsproto/` package centralizes the wire-format burden:

- **Query-RPC** (`Action=Foo&Version=YYYY-MM-DD`): IAM, EC2, RDS, ELB, CloudFormation.
- **JSON 1.0** (`X-Amz-Target: Service_Version.Operation`): DynamoDB.
- **JSON 1.1**: Secrets Manager, SQS, EKS, KMS (when it lands).
- **REST/XML**: S3, Route53.
- **REST/JSON**: API Gateway (when it lands).

When adding a new service, check `awsproto/` for the matching format helpers before reinventing them.

## Fidelity issues

If terraform-provider-aws behaves differently against fakeaws than against real AWS, file a **fidelity issue** with the `fidelity` label. Include:

- The exact terraform-provider-aws version.
- The HCL block that triggers the divergence.
- The raw HTTP request + response from both real AWS and fakeaws.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Contributor Covenant v2.1.

## License

By contributing, you agree your work will be released under Apache-2.0.
