# fakeaws — Agent Working Agreement

For AI coding agents working on fakeaws. Human contributors should use the
README.md quickstart.

## Mission
A local Go-based mock of the AWS HTTP API surface, narrow in coverage and
deep in the few services we ship. Sibling to mockway (Scaleway) and
fakegcp (GCP).

## Source of Truth
1. `concepts.md` — load-bearing design doc (Pre-flight checklist, service
   surface, wire-format strategy, anti-patterns, resolved decisions).
2. `coverage_matrix.yaml` — machine-readable manifest of every aws_resource_type
   and what coverage artefacts it requires (integration test, example dirs,
   scenario anchors). Source of truth for S48-T7's `TestFullCoverageAudit`.
3. `handlers/regression_manifest.go::LandedServices` — single tracked
   list of service-ids with a fully-implemented handler set. The
   `requireHandlerImplemented(t, "<id>")` helper checks against this.

## Layout

```
fakeaws/
├── cmd/fakeaws/main.go        # entrypoint, --port, --db, --echo
├── handlers/
│   ├── handlers.go            # Application struct, RegisterRoutes, auth
│   ├── admin.go               # /mock/reset, /snapshot, /restore, /state (S43-T4)
│   ├── awsproto/              # per-protocol marshalling helpers (S43-T2)
│   ├── iam.go, s3.go, ec2_*.go, ...  # one file per service
│   ├── handlers_test.go       # SHARED integration test file (TestXxx<Service>...)
│   ├── regression_test.go     # 16 standing patterns + per-pass top-up
│   ├── regression_manifest.go # LandedServices []string
│   ├── regression_audit_test.go  # manifest + vacuous-pass audits
│   └── unimplemented.go       # handled inline in handlers.go for now
├── repository/repository.go   # SQLite, schema + CRUD, snapshot/restore (S43-T3)
├── models/models.go           # ErrNotFound, ErrInUse, ErrTerminalState, ErrConflict
├── testutil/testutil.go       # NewTestServer, DoRaw, DoQueryRPC, DoXAmzTarget,
│                              # DoXMLREST, DoJSONREST, mustCreateXxx (per-protocol)
├── internal/audit/audit_test.go  # TestFullCoverageAudit
├── examples/{working,misconfigured,updates}/  # auto-discovered smoke gate
├── docs/review-passes/passN.md  # codex review archive
├── coverage_matrix.yaml       # source of truth for S48-T7 audit
├── .gitleaks.toml             # examples/.*\.tf$ allowlist
├── .githooks/pre-commit       # gitleaks → go test, in that order
├── .github/workflows/ci.yml   # six required jobs
├── Makefile                   # install-hooks, build, test, test-coverage
└── README.md, AGENTS.md, concepts.md, go.mod
```

## Key conventions

- **Wire formats vary**: 5 distinct shapes across 9 services. XML (S3, Route53),
  Query-RPC (EC2, RDS, IAM), JSON 1.0 with x-amz-target (SQS), JSON 1.1 with
  x-amz-target (DynamoDB, SecretsManager), JSON-REST (EKS). The `awsproto/`
  helper (S43-T2) handles the marshalling — handler files focus on resource
  semantics + FK validation.
- **Per-service ARN builders**: real AWS ARN formats vary per service.
  IAM omits region; S3 is bucket-scoped; Route53 is global; EC2/RDS/EKS
  embed region+account. Each in-scope service gets its own
  `BuildXxxARN(...)` helper in `handlers/awsproto/arn.go`.
- **No bare `t.Skip()`**: tests for not-yet-landed services call
  `requireHandlerImplemented(t, "<id>")`, which checks
  `regression_manifest.go::LandedServices` and either calls `t.Skipf`
  with a structured TODO message or falls through to the real
  assertions. Two CI audits enforce no silent green-lights.
- **No `t.Skip` outside that helper**: skipped tests count as zero coverage.
- **No silent 200**: every endpoint we don't model returns 501 with an
  `UNIMPLEMENTED` log line. Discovery surface for the next caller.
- **Examples are auto-discovered**: dropping a directory under
  `examples/{working,misconfigured,updates}/` registers it for the
  smoke gate (S43-T12). No per-service smoke ticket.

## Anti-patterns explicitly forbidden

Lifted from mockway's 14-bug catalogue (concepts.md § "Anti-patterns: the
mockway 14-bug catalogue") — these recurring bugs are what the standing-
patterns regression seed prevents from re-landing.

1. Wrong error helper on Create paths (writeCreateError vs writeDomainError).
2. SQL column / JSON blob desync on Update.
3. Payload field-name variations across provider versions.
4. Truncating multi-item lists.
5. Response-encoding mismatches.
6. Reset must include all tables.
7. Cross-resource state sync on create.
8. Multi-step writes must be atomic.
9. Validate referenced resources on set/replace.
10. Resource-existence gate on every sub-resource handler.
11. Never auto-generate IDs for unvalidated inputs.
12. Nested-path child ownership validation.
13. Cross-parent reference validation (subnet/VPC pairing).
14. Reverse fidelity — don't over-correct (if real API silently accepts,
    we accept).

## Where to find AWS resource shapes

1. `/Users/ehsanashouri/go/src/github.com/redscaresu/terraform-provider-aws`
   on disk if it's there — read `internal/service/<svc>/...`.
2. Otherwise `gh api repos/hashicorp/terraform-provider-aws/contents/internal/service/<svc>` for the list.
3. AWS documentation as a last resort — provider behaviour wins where
   docs and provider disagree (point 14 above).

## Codex review pass discipline

- Every accepted finding pins a regression test in `handlers/regression_test.go`
  named after the bug it prevents from regressing.
- Prompts and responses archived under `docs/review-passes/passN.md`.
- 2 consecutive `NOTHING_TO_IMPROVE` returns advance phase exit;
  any `BLOCKING:` finding restarts the count.

## Quality bar

- Aggregate `handlers/...` coverage ≥ 80% at the end of each phase
  (parsed from the `total:` line of `go tool cover -func=cov.out`).
- 6 required CI jobs: `lint`, `build`, `test`, `gitleaks`,
  `regression-seed-audit`, `coverage-audit`, `coverage`.
- No `--no-verify`. No bare `t.Skip()`. No silent partial implementations.
