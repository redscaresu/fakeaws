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

S43-T1 (scaffold + Day-1 gates) — landing now. Subsequent slices add the
service surface incrementally; see `concepts.md` § "Service surface (v1)"
for the full v1 plan and `infrafactory/BACKLOG.md` for the per-ticket
breakdown.

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

## Provider version pin

This mock targets `hashicorp/aws ~> 5.70`. Bumps require an explicit PR
that updates this README, every `examples/*/required_providers` block,
every `prompts/aws/*.md` template, and the e2e harness's provider
config — together. Single source of truth for the constraint string is
`coverage_matrix.yaml`'s header comment.

## Documentation

- `concepts.md` — load-bearing design doc (will be folded into
  `PLAN.md` once the repo has shape).
- `AGENTS.md` — fresh-agent entry point: layout, conventions,
  anti-patterns, where to look for AWS resource shapes.
- `docs/review-passes/passN.md` — codex review prompts and findings
  archived per pass; the planning loop's output is preserved alongside
  the implementation history.

## Non-goals

- No SigV4 *validation* — we accept any `Authorization` header.
- No real S3 object payload store — buckets and bucket-level config
  are modelled; PutObject body is discarded.
- No CloudFormation, Lambda, KMS-as-a-service, EventBridge.
- No Smithy → Go codegen pipeline. Hand-written handlers, like the
  other two mocks.

## License

TBD.
