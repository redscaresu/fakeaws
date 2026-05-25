# fakeaws

A local Go-based mock of the AWS HTTP API surface, sibling to
[mockway](https://github.com/redscaresu/mockway) (Scaleway) and
[fakegcp](https://github.com/redscaresu/fakegcp) (GCP).

The goal: give `terraform-provider-aws` an HTTP server it can hit during
`tofu apply`, so [infrafactory](https://github.com/redscaresu/infrafactory)
can drive AWS-flavoured scenarios end-to-end without ever calling the
real cloud.

LocalStack used to fill this niche but has consolidated into a paid
product (April 2026). fakeaws keeps the freedom-to-modify, freedom-to-
fork story alive — narrow in coverage, deep in the few services we ship.

## Status

Nine services across five wire formats. The S43–S48 codex review loop
closed at pass 17 with zero allowlist entries; post-S48 polish landed
the M51 Query-RPC envelope rewrite, M57 per-resource field parity, M61
full RDS lifecycle (`aws_db_instance` apply → plan no-op → destroy
clean), and M62 full Secrets Manager lifecycle. The 17 review passes
are archived under `docs/review-passes/passN.md`. Aggregate handlers
coverage 77.2% on the `total:` line (`handlers` 79.4% + `handlers/awsproto` 53.4%).

| Service | Wire format | Endpoint | TF lifecycle |
| ------- | ----------- | -------- | ------------ |
| IAM | Query-RPC + XML | `POST /iam` | apply / plan-no-op / destroy ✓ |
| S3 | XML REST | `/s3/<bucket>/<key>?<sub-resource>` | apply / plan-no-op / destroy ✓ (S3 bucket sub-resource reads are limited — for `terraform-provider-aws`'s full Read flow infrafactory pairs fakeaws with SeaweedFS, see M59) |
| EC2 | Query-RPC + XML | `POST /ec2/region/<region>` | VPC + Subnet + IGW + RouteTable + Route + EIP + SG + Instance + KeyPair + AMI fixture; full lifecycle ✓ |
| RDS | Query-RPC + XML | `POST /rds/region/<region>` | DB Instance + Subnet/Parameter/Cluster Groups + Clusters; full lifecycle ✓ (M61: DbiResourceId stability, service-specific 404 codes, DeleteDBInstance envelope, user-field persistence) |
| DynamoDB | JSON 1.1 + X-Amz-Target | `POST /dynamodb/region/<region>` | apply / plan-no-op / destroy ✓ |
| EKS | JSON-REST | `/eks/region/<region>/clusters/...` | cluster + node group; full lifecycle ✓ |
| SQS | JSON 1.0 + X-Amz-Target | `POST /sqs/region/<region>` | apply / plan-no-op / destroy ✓ |
| Route53 | XML REST | `/route53/2013-04-01/...` | hosted zone + record set; full lifecycle ✓ |
| Secrets Manager | JSON 1.1 + X-Amz-Target | `POST /secretsmanager/region/<region>` | apply / plan-no-op / destroy ✓ (M62: ARN-or-name SecretId, epoch timestamps, VersionIdsToStages, GetResourcePolicy + ListSecretVersionIds) |

Per-resource details + load-bearing FK contracts live in `PLAN.md`;
the M61/M62 wire-shape lessons are documented in `AGENTS.md` under
"Provider-wait-state-machine debugging".

## Quickstart

```bash
go mod download
make install-hooks   # second step after clone — wires .githooks/pre-commit
go test ./...
```

`make install-hooks` is idempotent — re-running is a no-op. The hook
runs `gitleaks protect --staged --no-banner` *before* `go test ./...`,
so secret detection short-circuits the commit before tests have a
chance to print env vars to terminal logs.

## Run

```bash
make build && ./fakeaws --port 8082 --db :memory:
# or with logging of every method+path (useful when discovering
# unimplemented endpoints during provider integration testing):
./fakeaws --port 8082 --echo
```

### Docker

Pre-built multi-arch images are published to GitHub Container Registry on every push to `main`:

```bash
docker run --rm -p 8082:8082 ghcr.io/redscaresu/fakeaws:latest --port 8082
```

The Dockerfile in the repo root produces a `~15MB` static image (multi-stage build from `golang:1.25-alpine`).

## Provider version pin

This mock targets `hashicorp/aws ~> 5.70`. Bumps require an explicit PR
that updates this README, every `examples/*/required_providers` block,
every `prompts/aws/*.md` template, and the e2e harness's provider
config — together. Single source of truth for the constraint string is
`coverage_matrix.yaml`'s header comment.

## API compatibility

The point of fakeaws is to be wire-shape compatible with the real `hashicorp/aws` provider — every byte the provider sends or expects to receive must match what real AWS would do, or the provider detects "drift" and the apply loop fails. Three guardrails enforce this; they're identical across [`mockway`](https://github.com/redscaresu/mockway) (Scaleway), [`fakegcp`](https://github.com/redscaresu/fakegcp) (GCP), and [`fakeaws`](https://github.com/redscaresu/fakeaws) (AWS).

### 1. Three example trees, auto-discovered

Every directory under `examples/` is an executable contract against a real Terraform/OpenTofu provider:

| Tree | Contract |
|---|---|
| `examples/working/<svc>/` | `apply → plan -detailed-exitcode 0 → destroy` — second plan MUST be a no-op |
| `examples/misconfigured/<svc>/` | `apply` MUST fail with the documented AWS error code; if `expected.txt` is present, the error output MUST contain that fragment |
| `examples/updates/<svc>/` | `apply -var-file=v1.tfvars → plan no-op → apply -var-file=v2.tfvars → plan no-op → destroy` |

`examples/provider_smoke_test.go` walks the three trees with `runtime.Caller` and registers each subdirectory as its own `t.Run` sub-test. Adding a directory adds a test — no per-example test wiring. The harness assumes a fakeaws server is reachable at `FAKEAWS_URL` (default `http://127.0.0.1:8082`); CI runs it after `make fakeaws-up` from the infrafactory Makefile.

The **idempotency gate** (`plan -detailed-exitcode 0`) is the strongest compatibility signal: if fakeaws returns a single field with the wrong case, type, or default, the provider sees drift on the second plan and the test fails. Wire-shape parity across the nine S43–S48 services (S3, IAM, EC2, VPC, RDS, DynamoDB, SQS, Route53, Secrets Manager) was closed by the 17-pass codex review loop driving this gate.

### 2. No allowlist — every example must pass

mockway and fakegcp use an `examples/known_broken.yaml` ratchet for examples whose idempotency gate is currently expected to fail. fakeaws does not: the S43–S48 codex review loop closed at pass 17 with zero allowlist entries, so the smoke harness enforces the working-tree contract strictly. Any new example that drifts must be fixed before merge, not allowlisted. If a regression batch ever needs an allowlist, copy the pattern from `fakegcp/examples/provider_smoke_test.go` (ratchet-only-tighten: entries can only be REMOVED).

### 3. Cross-repo e2e from infrafactory

[`infrafactory`](https://github.com/redscaresu/infrafactory) builds fakeaws from this source tree on a free port for every gated AWS e2e test (`TestE2E_AWS*` in `internal/e2e/`, gated by `INFRAFACTORY_ENABLE_E2E=1`). Those tests drive scenarios end-to-end through infrafactory's harness (plan → mock-apply → topology derivation → destroy), so a compatibility regression surfaces in two places: the local `INFRAFACTORY_ENABLE_E2E=1 go test ./examples/...` and the upstream infrafactory CI.

### Adding coverage for a new resource

1. Add an `examples/working/<svc>/` directory with `providers.tf` + `main.tf`.
2. Run `INFRAFACTORY_ENABLE_E2E=1 go test ./examples/...` — auto-discovery picks it up.
3. If it drifts: either fix the handler, or (if the fix is non-trivial) add a `known_broken.yaml` entry pointing at a new BACKLOG ticket.
4. Mirror with `examples/misconfigured/<svc>/` (FK / validation paths) and `examples/updates/<svc>/` (update paths) as the service warrants.
5. Add a `TestE2E_AWS<Svc>` in infrafactory's `internal/e2e/aws_services_test.go` so the cross-repo gate covers the scenario flow too.
6. Append the service id to `LandedServices` in `handlers/regression_manifest.go`. This trips infrafactory's `TestCrossRepoParity_EveryLandedServiceHasScenario` (in its `internal/e2e/cross_repo_parity_test.go`) until either (a) a `scenarios/training/aws-<svc>.yaml` is added on the infrafactory side AND a `cloudParityMap["aws"]["<svc>"]` entry pointing at it lands in the same PR, or (b) the service is added to that test's `exempt` map with a written reason (only appropriate for read-only / meta APIs with no standalone resource type). The parity test runs in infrafactory CI on every push, so landing here without the upstream change will break the badge — coordinate the two PRs.

## Documentation

- [`concepts.md`](concepts.md) — load-bearing design doc (pre-flight
  checklist, service surface, wire-format strategy, anti-patterns,
  resolved decisions).
- [`AGENTS.md`](AGENTS.md) — fresh-agent entry point: layout,
  conventions, anti-patterns, where to look for AWS resource shapes,
  and the M61/M62 "Provider-wait-state-machine debugging" recipe.
- [`PLAN.md`](PLAN.md) — phase-by-phase delivery history with the
  FK-chain analyses that gated handler ordering.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — PR contract, quality gates,
  pre-commit hook setup.
- [`docs/review-passes/passN.md`](docs/review-passes/) — codex review
  prompts and findings archived per pass; 17 passes preserved
  alongside the implementation history.
- [`examples/README.md`](examples/README.md) — quickstart for running
  the auto-discovered example tree against a live fakeaws.

## Non-goals

- No SigV4 *validation* — we accept any `Authorization` header.
- No real S3 object payload store — buckets and bucket-level config
  are modelled; PutObject body is discarded.
- No CloudFormation, Lambda, KMS-as-a-service, EventBridge.
- No Smithy → Go codegen pipeline. Hand-written handlers, like the
  other two mocks.

## License

Apache 2.0 — see [LICENSE](LICENSE).
