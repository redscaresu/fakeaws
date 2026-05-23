# fakeaws — Concepts

A local Go-based mock of the AWS HTTP API surface, modelled after [mockway](https://github.com/redscaresu/mockway) (Scaleway) and [fakegcp](https://github.com/redscaresu/fakegcp) (GCP). The goal is to give terraform-provider-aws a server it can hit during `tofu apply` so infrafactory can drive AWS-flavoured scenarios end-to-end without ever calling the real cloud.

LocalStack used to fill this niche but has consolidated into a paid product (April 2026). fakeaws keeps the freedom-to-modify, freedom-to-fork story alive by being a small, hand-written, fully-Go alternative — narrow in coverage, deep in the few services we ship.

## Pre-flight checklist (before starting S43-T1)

Operational state and one-time setup items the build assumes. A fresh agent should verify or perform each before issuing the first commit.

**One-time manual steps (only the repo owner can do these):**
- Configure GitHub branch protection on the fakeaws repo's `main` to require all six CI jobs (`lint`, `build`, `test`, `gitleaks`, `regression-seed-audit`, `coverage-audit`, `coverage`) before merge. The agent can't do this — it's a `gh api` call or web-UI action that needs repo-admin auth.
- Confirm `codex login` is current; the iterative-review loop needs codex CLI access throughout the build.

**Repo state assumed:**
- `$GOPATH/src/github.com/redscaresu/fakeaws` exists as a directory with only `concepts.md` in it. **First action of S43-T1 is `git init` there**, then ship the four-file Day-1 invariant in commit 1.
- mockway runs on `:8080`, fakegcp on `:8081`, fakeaws will be `:8082`. mockway must be restarted after any code change in its repo (procedure documented in the user's MEMORY.md).
- Commit author identity: the repo owner's configured `user.name` / `user.email`.

**Build-time conventions:**
- Branch strategy: one long-lived `fakeaws-build` branch with per-ticket commits, opened as one PR-per-phase (six PRs total: S43..S48). Per-ticket PRs would be too noisy for ~70 tickets.
- For inner-loop dev use `go test ./...`; reserve `make test` (which also runs UI Playwright e2e) for end-of-phase gates — Playwright is slow.
- Filter `CLAUDECODE` from any subprocess env (carried over from earlier subprocess hygiene work in MEMORY.md).
- When editing `internal/cli/runtime.go`, `internal/harness/destroy.go`, `internal/harness/topology_derive.go`, `internal/harness/real_probe.go`, `internal/cli/test_command.go`, `internal/cli/validate_command.go`, `internal/cli/generate_command.go`, `internal/cli/mockway_client.go`, or `internal/e2e/helpers.go`, the same files also serve mockway+fakegcp paths. Every change requires `go test ./internal/...` green across all three clouds, not just the aws subset.

**Fallback signals for codex credit exhaustion:**
- `codex exec` returns non-zero exit AND stderr contains one of: `429`, `insufficient_quota`, `unauthorized`, `quota`, `credits`, `rate_limit`. Single transient failures (network, timeout) get one retry; persistent failures flip the run to ALL-OPUS mode (use general-purpose Agent for review passes; record the switch in BACKLOG.md).

**Pitfalls auto-learning loop:**
- When the agent encounters a generation-time mistake the LLM repeatedly makes (provider rejects same shape twice in a row), append the rule to `pitfalls/aws.yaml` rather than only fixing the immediate scenario. Same pattern as `pitfalls/scaleway.yaml`'s auto-append behaviour.

**Where to find AWS resource shapes during implementation:**
- Try `$GOPATH/src/github.com/redscaresu/terraform-provider-aws` first; if the path doesn't exist on this machine, fall back to `gh api repos/hashicorp/terraform-provider-aws/contents/...` for the relevant `internal/service/<svc>/` files.

**Run cleanup at end:**
- Archive `/tmp/codex-fakeaws-*-output.txt` files from the planning loop under `fakeaws/docs/review-passes/round-NN-planning.md` (the same directory where the build's review passes live), so the planning history is preserved alongside the implementation history.

## Goals & non-goals

**Goals**
- Cover full CRUD (Create / Read / Update / Delete / List) for the eight services infrafactory cares about: S3, EC2, Route53, EKS, RDS, DynamoDB, SQS, Secrets Manager. Plus IAM as a foundational dependency.
- Drive every service through the live `hashicorp/aws` provider via `tofu apply → mutate → tofu apply → tofu destroy`. The infrafactory `TestE2E_AWS*` gated suite is the source of truth.
- Match the architectural conventions and testing framework already proven in mockway and fakegcp. Same skeleton, same testutil, same regression-pinning discipline.
- Slot into infrafactory the same way fakegcp does — `StartFakeaws()` helper, per-cloud constraint policies, training scenarios, topology derivation.
- Be small enough to be carryable: target ≤ 5 KLoC across handlers + repository at v1, with no codegen pipeline.

**Non-goals**
- Not a replacement for LocalStack's full feature surface (multipart uploads, presigned URLs, EventBridge wiring, Lambda runtime, IAM policy evaluation engine, etc.). Out of scope.
- No SigV4 *validation*. We accept any `Authorization` header; the goal is to discover API shape, not enforce auth.
- No real S3 object store. S3 buckets and bucket-level config (versioning, encryption, tags) are modelled; object-payload storage is out.
- No CloudFormation, Lambda, KMS-as-a-service. CloudFormation might be added later when infrafactory stops driving AWS via raw resources.
- No Smithy → Go codegen pipeline. Hand-written handlers, like the other two mocks. Revisit if AWS publishes Smithy specs publicly and the cost of hand-writing exceeds the codegen integration cost.

## Lessons we are explicitly carrying over

From the 33 codex review passes that landed fakegcp, the patterns that paid for themselves repeatedly:

1. **Single-binary, single-process Go server.** `cmd/fakeaws/main.go` boots a chi router holding one `*Application` struct, which holds one `*Repository`, which holds one SQLite handle (`SetMaxOpenConns(1)` + `PRAGMA foreign_keys = ON`). No plugin layer, no service discovery — adding a service is one Go file.
2. **SQLite as the state engine.** `modernc.org/sqlite` (pure Go, no CGO). FK constraints declared at schema level for hierarchical resources (`ON DELETE CASCADE` for children-on-parent-delete; no clause for FK-blocked deletes). Resource-as-JSON column for everything else, with FK-bearing identity columns extracted (id, region, parent ref).
3. **Layered FK validation.** Repo-level FK constraints catch the easy cases. Handler-level validators (`resolveSameProjectName`-style helpers) catch cross-resource references that don't fit a single parent FK — cross-project rejection, wrong-collection rejection, post-merge validation on PATCH paths.
4. **Distinct 409 sentinels.** `ErrInUse` (FK-blocked delete) and `ErrTerminalState` (resource state can't transition further) carry different messages and reason strings. `ErrConflict` stays as a generic catch-all; new code should pick the specific sentinel.
5. **Three-tier test pyramid.** Unit tests (helper functions, internal package). Integration tests via `testutil.NewTestServer(t)` + `httptest` (handler tests). End-to-end tests gated by `INFRAFACTORY_ENABLE_E2E=1` driving the real Terraform provider through tofu. Each new behaviour gets a regression test in `handlers/regression_test.go` so the next refactor can't quietly break it.
6. **Examples as documentation.** `examples/working/` proves apply-then-destroy. `examples/misconfigured/` proves the FK gates. `examples/updates/` (with `v1.tfvars`/`v2.tfvars`) proves in-place patches don't drift.
7. **Admin lifecycle in one file.** `/mock/reset`, `/mock/snapshot`, `/mock/restore`, `/mock/state`, `/mock/state/{service}`. The repo's `Reset()` clears all tables and the snapshot baseline; `Snapshot()` is `VACUUM INTO`; `Restore()` swaps the file back. Any in-memory cache (DNS changes, similar) is reset/snapshot/restored at the same time so the lifecycle stays consistent.
8. **Server-stamped metadata, never trust the client.** `id`, `creationTimestamp`, `selfLink` (or AWS equivalent ARN/Id) are written by the repo on insert and never honoured from the request body. PATCH handlers carry an explicit skip-list of immutable fields.
9. **PATCH validation runs on the post-merge state, not the raw patch.** A partial PATCH that flips `subnetwork` without touching `network` should still be FK-validated against the merged result.

## Lessons we are explicitly NOT carrying over from LocalStack

After reading the LocalStack codebase (`$GOPATH/src/github.com/redscaresu/localstack`):

1. **No Python pickle persistence.** SQLite + JSON columns is enough.
2. **No HandlerChain / per-stage middleware.** chi groups + a single auth middleware is fine; we don't need 13 stages.
3. **No Moto fallback.** Either we model a service or we explicitly 501 it (`UnimplementedHandler` returns 501 with a log line so the next caller sees what's missing). No silent partial implementations.
4. **No auto-generated API types in version control.** The fakegcp/mockway pattern of hand-written handlers keeps diffs small and reviewable.
5. **No `(account_id, region)` keying in the repo.** AWS is multi-account / multi-region but for our purposes everything is scoped under one synthetic account. Region is a column on each table where it matters (ec2, rds, route53 record-set parent), not a repo-wide sharding key.

## Service surface (v1)

Eight services, plus IAM. Wire formats vary across AWS — this is the biggest practical difference from fakegcp (where everything was JSON-REST). The handler layer needs a small per-service serialiser to match each protocol.

| Service | Protocol | Routing | Complexity | Notes |
|---|---|---|---|---|
| **IAM** | Query-RPC (POST `Action=Foo&Version=2010-05-08&...` with XML response) | global single endpoint `iam.amazonaws.com` | M | Foundational — every other resource references roles, policies, instance-profiles. Build first. Same wire family as EC2/RDS, so the awsproto query-RPC parser + XML response writer cover IAM too. |
| **S3** | XML | path-style (`/<bucket>/<key>`) and virtual-host (`<bucket>.s3.amazonaws.com`) | XL | Bucket-level CRUD only at v1. No object payload store; PUT object accepts and discards the body, returns the right ETag/headers. |
| **EC2** | Query-RPC (POST `Action=Foo&...` with XML response) | single endpoint per region | XL | Instances, VPCs, subnets, security groups, internet gateways, route tables, EIPs, AMIs (read-only fixtures). |
| **RDS** | Query-RPC (POST `Action=Foo&...` with XML response) | single endpoint per region | L | DB instance, DB cluster, DB subnet group, DB parameter group. State machine (creating → available → deleting) collapsed to "always available". |
| **DynamoDB** | JSON (x-amz-target = `DynamoDB_20120810.<Op>`) | single endpoint per region | L | Tables + items. Stream support out of scope at v1. |
| **SQS** | JSON 1.0 (x-amz-target = `AmazonSQS.<Op>`) | per-region | M | Queues + messages. SendMessage / ReceiveMessage / DeleteMessage with at-least-once semantics. SQS adopted AWS-JSON 1.0 in 2023; the legacy Query-API is not modelled. |
| **EKS** | JSON-REST (`PUT /clusters/{name}` etc.) | per-region | L | Clusters + nodegroups. State machine collapsed. |
| **Secrets Manager** | JSON (x-amz-target = `secretsmanager.<Op>`) | per-region | S | Secrets + versions. Mirrors fakegcp's Secret Manager almost line-for-line. |
| **Route53** | XML REST (`POST /2013-04-01/hostedzone`) | global | M | Hosted zones + record sets. Mirrors fakegcp's DNS handler set. |

The grouping into "M / L / XL" maps roughly to: M = ~150–250 lines per handler set + ~80 lines per repo; L = ~250–400 + ~150; XL = ~400+ + ~200+.

## Wire-format strategy

fakegcp had one wire format (JSON/REST). fakeaws has **five distinct wire shapes** across nine services:

1. XML REST — S3 + Route53.
2. Query-RPC (form body, XML response) — EC2 + RDS + IAM.
3. JSON 1.0 with x-amz-target — SQS.
4. JSON 1.1 with x-amz-target — DynamoDB + Secrets Manager.
5. JSON REST — EKS.

Three implementation options:

1. **Per-service serialiser.** Each `handlers/<service>.go` knows its protocol — XML for S3/Route53, query-RPC encoding (POST `Action=...&Version=...` with XML responses) for EC2/RDS/IAM, JSON-1.0 with x-amz-target for SQS, JSON-1.1 with x-amz-target for DynamoDB/SecretsManager, JSON-REST for EKS. Total LoC cost is real but bounded; can crib from `aws-sdk-go-v2`'s vendored stubs in terraform-provider-aws to get response shape right.
2. **Smithy codegen.** AWS publishes Smithy models internally; the public sdk repos ship generated Go. We could hand-port the response-serialisation tables. Big upfront cost, no incremental option.
3. **Reverse-proxy via aws-sdk-go-v2's protocol layer.** Use the SDK's marshal/unmarshal helpers to convert between Go structs and the wire format, only writing the business logic. Possible but pulls a heavy dependency.

**Recommendation: option 1.** Per-service serialisers, hand-written. Infrafactory only needs the eight services for the resources it cares about; we don't need the rest of the SDK. Adding a ninth service means one file, not a codegen pipeline integration.

A small `handlers/awsproto/` helper package can encapsulate:
- `WriteXMLResponse(w, status, root, body)` for S3 + EC2 + RDS + Route53
- `WriteJSONResponse(w, status, body)` for the JSON family
- `ParseQueryRPC(r) (action, params)` for EC2 + RDS
- `ParseXTargetJSON(r) (target, params)` for DynamoDB + SQS + Secrets Manager
- `WriteAWSError(w, code int, awsCode, message string)` mapping `models.ErrInUse` etc. to the right wire shape per protocol

This keeps the per-service handler files focused on resource semantics and FK validation, like fakegcp's handlers are.

## Repository skeleton

Verbatim from fakegcp's pattern. The only fakeaws-specific change is the per-service table layout:

```
fakeaws/
├── cmd/fakeaws/main.go          # entrypoint, --port, --db, --echo
├── handlers/
│   ├── handlers.go              # Application struct, RegisterRoutes, auth, awsproto wiring
│   ├── admin.go                 # /mock/reset, /snapshot, /restore, /state
│   ├── awsproto/                # per-protocol marshalling helpers
│   ├── iam.go
│   ├── s3.go
│   ├── ec2.go
│   ├── rds.go
│   ├── dynamodb.go
│   ├── sqs.go
│   ├── eks.go
│   ├── secretsmanager.go
│   ├── route53.go
│   ├── handlers_test.go         # CRUD + FK tests, testutil-driven
│   ├── regression_test.go       # targeted regressions
│   └── unimplemented.go         # 501 + log "UNIMPLEMENTED" catch-all
├── repository/repository.go     # SQLite, schema + CRUD, snapshot/restore
├── models/models.go             # ErrNotFound, ErrInUse, ErrTerminalState, ErrConflict
├── testutil/testutil.go         # NewTestServer, DoRaw, DoQueryRPC, DoXAmzTarget, DoXMLREST, DoJSONREST, mustCreateXxx (per-protocol)
├── examples/
│   ├── README.md
│   ├── working/                 # apply → destroy
│   ├── misconfigured/           # FK-violation demos (apply must fail with our error shape)
│   └── updates/                 # v1.tfvars → v2.tfvars in-place patches
├── README.md
├── AGENTS.md
├── PLAN.md
├── BACKLOG.md
├── Makefile
├── .gitleaks.toml
└── go.mod / go.sum
```

## Testing framework — verbatim with mockway/fakegcp

This is non-negotiable per the user. Every contract below mirrors what already exists in `$GOPATH/src/github.com/redscaresu/fakegcp`.

**Three-tier pyramid**:

1. **Internal-package unit tests** (`handlers/<file>_internal_test.go`, `package handlers`) for helpers that touch unexported state.
2. **Integration tests via testutil** (`handlers/handlers_test.go`, `package handlers_test`) — a real `httptest.Server` backed by an in-memory SQLite. Each service gets `TestXxxCRUD`, `TestXxxFKViolation` (where applicable), and `TestXxxDeleteWithDependents` (where applicable).
3. **Regression tests** (`handlers/regression_test.go`, `package handlers_test`) — every codex/QA finding pinned by name. The test name describes the bug it prevents from regressing.

**testutil API contract** — different shape from fakegcp's because AWS isn't a single JSON wire. fakegcp's DoCreate/DoGet returning `(*http.Response, map[string]any)` works because every fakegcp endpoint speaks JSON. fakeaws speaks five wire formats; testutil exposes a low-level "raw" helper plus per-protocol convenience wrappers:

```go
package testutil

func NewTestServer(t *testing.T) (*httptest.Server, func())

// Low-level raw helper — returns the response + body bytes; tests parse
// per-protocol. This is the foundation every wrapper builds on.
func DoRaw(t *testing.T, srv *httptest.Server, req *http.Request) (*http.Response, []byte)

// Query-RPC: IAM, EC2, RDS. POST application/x-www-form-urlencoded with
// Action=<op>&Version=<api-version>&<params>. Response is XML; tests
// parse with encoding/xml.
func DoQueryRPC(t *testing.T, srv *httptest.Server, service, action, version string, params url.Values) (*http.Response, []byte)

// JSON 1.0 / 1.1 with x-amz-target: DynamoDB, SQS, Secrets Manager.
// POST application/x-amz-json-1.0 (or -1.1) with X-Amz-Target header.
// Response is JSON; tests get a parsed map back for convenience.
func DoXAmzTarget(t *testing.T, srv *httptest.Server, service, target string, body any) (*http.Response, map[string]any)

// XML REST: S3, Route53. Path-style request, XML body for non-GET.
// Response is XML; tests get raw bytes for encoding/xml parsing.
func DoXMLREST(t *testing.T, srv *httptest.Server, method, path string, xmlBody []byte) (*http.Response, []byte)

// JSON REST: EKS. Path-style request, JSON body for non-GET. Response
// is JSON; tests get a parsed map back.
func DoJSONREST(t *testing.T, srv *httptest.Server, method, path string, body any) (*http.Response, map[string]any)

// Path / endpoint builders — one per service, encoding the routing
// pattern fakeaws uses internally. Tests pass these to Do* helpers.
func IAMEndpoint() string                                    // global, single endpoint (Query-RPC)
func S3Path(bucket string, parts ...string) string           // path-style /<bucket>/<...>
func EC2Endpoint(region string) string                       // /ec2/region/<region> (Query-RPC)
func RDSEndpoint(region string) string                       // /rds/region/<region>
func DynamoDBEndpoint(region string) string                  // /dynamodb/region/<region>
func SQSEndpoint(region string) string                       // /sqs/region/<region>
func EKSPath(region string, parts ...string) string          // /eks/region/<region>/clusters/...
func SecretsEndpoint(region string) string                   // /secretsmanager/region/<region>
func Route53Path(parts ...string) string                     // /2013-04-01/...
```

The per-protocol Do* helpers paper over AWS's wire diversity inside a single chi tree. The handler files use `chi.URLParam` to pull region/bucket/etc. out where applicable; query-RPC handlers dispatch on the `Action` parameter inside the request body.

**`mustCreateXxx` helpers** — per-protocol `require`-based wrappers (one per Do* helper above: `mustQueryRPC`, `mustXAmzTarget`, `mustXMLREST`, `mustJSONREST`) that fail the test with a clear message if setup fails. Used pervasively in tests that seed prerequisite resources. Same role as fakegcp/mockway's single `mustCreate`, but split per protocol because there's no single "create" wire shape that covers AWS.

**E2E (gated)** — `infrafactory/internal/e2e/aws_*_test.go`. Same gating env var (`INFRAFACTORY_ENABLE_E2E=1`). Same StartFakeaws helper pattern. Same `runAWSServiceScenario` runner pattern as `runGCPServiceScenario` — apply → mutate → apply → destroy with identity-preservation and verify-callback hooks.

## infrafactory integration

The integration is broader than fakegcp's "three hooks" because infrafactory has grown surfaces since fakegcp landed. Adding a third cloud touches **16 surfaces** — numbered 1–16 in the "Required surface" + "Generator surface" sub-lists below, plus the runtime restructure that makes provider-schema extraction lazy/per-scenario. The plan tickets each surface explicitly so nothing slips into "TBD". Codex review pass 1 caught five of these missing in earlier drafts; pass 12 caught two more (policy plumbing + lazy provider-schema invocation order). They are now first-class deliverables.

### Required surface — one ticket each

1. **scenarios/training/aws-*.yaml** — one per service, declaring the resource shape, region, acceptance criteria. Mirror of `gcp-*.yaml`.
2. **`scenario.schema.json` cloud enum + resource decision + per-scenario coverage anchor** — `cloud` enum extended with `"aws"`. New service-specific resource types `dynamodb` and `messaging` added under `properties.resources` per concepts.md § "Resolved decisions" item 7 (the `messaging` slot stays cloud-neutral so Pub/Sub-style services from other clouds can reuse it). New optional top-level field `aws_resource_anchors: [string]` — a list of per-API resource types this scenario asserts end-to-end coverage for (e.g., `["aws_iam_role", "aws_iam_role_policy_attachment"]`); required on aws scenarios, ignored on others. The S48-T7 coverage audit reads this field so a single coarse-grained `compute` scenario doesn't trivially "cover" every AWS resource that maps to `compute`. Without these the loader rejects aws scenarios.
3. **`internal/scenario/scenario.go`** — Go-side struct mirrors the schema additions; loader validates aws scenarios.
4. **`internal/config/config.go`** — `Config` gains `Fakeaws FakeawsConfig` alongside `Mockway` and `Fakegcp`. URL + AutoReset fields, mirror of `FakegcpConfig`.
5. **`internal/cli/runtime.go` + `internal/cli/mockway_client.go`** — runtime construction wires fakeaws URL into the cloud router; the client routes `cloud: aws` to fakeaws. Currently hard-coded for two clouds; this is *not* a one-line change.
6. **`internal/harness/topology_derive.go`** — `detectCloud()` gains an `aws` branch (looks for top-level `ec2`/`s3`/`iam` keys in `/mock/state`); `DeriveTopology` dispatches to a new `deriveTopologyAWS` function reading aws state into a `rawAWSState` struct. Tests cover all three cloud paths.
7. **`internal/harness/destroy.go::countOrphans`** — ignored-roots / -collections list extended with fakeaws's bookkeeping tables (`operations`, `audit`, plus `sqs_messages` once SQS lands in S46 — the actual SQS table name; DynamoDB streams are out of scope at v1 so no streams_cursor table exists). The list is appended to as new bookkeeping tables ship; S43 lands `operations` + `audit` (universal across all services) and reserves the structure so later phases extend the list without touching countOrphans's design. This is part of S43 *not* S48 because the destroy gate fires from S43-T14's first e2e onwards — pushing it to S48 means every interim phase's destroy assertions fail spuriously.
8. **`internal/harness/real_probe.go::probeTargetResourceTypes`** — switch statement gains aws resource types per probe target: `aws_lb`/`aws_lb_target_group` for `load_balancer`, `aws_db_instance` for `database`, `aws_elasticache_cluster` for `redis`, `aws_instance` for `compute`, `aws_eks_cluster` for `kubernetes`. Without this, `real_probe` returns empty hosts for AWS scenarios.
9. **`internal/harness/provider_schema.go::ExtractProviderSchema`** — currently hard-codes `scaleway/scaleway` in the providers.tf template. Becomes cloud-aware: takes a `cloud` arg and emits the right `required_providers` block (`hashicorp/aws` for aws, `hashicorp/google` for gcp, `scaleway/scaleway` for scaleway). Tests cover all three. **Critical**: today the extractor is invoked via `CommandRuntime.EnsureProviderSchema()` (called from `internal/cli/generate_command.go` line ~166; the wrapper itself lives in `internal/cli/runtime.go` around line 114, with `CommandRuntime` constructed around line 238) before the active scenario's cloud is known. The S43-T9 ticket therefore *also* restructures `EnsureProviderSchema` so the extraction runs lazily after `LoadScenario` returns the cloud — without this change, the cloud-aware design is unreachable. A test pins the lazy-invocation order: a single process running scaleway then aws scenarios must re-extract per scenario.
10. **`internal/e2e/helpers.go::StartFakeaws`** — same shape as `StartFakegcp`: builds the binary, starts it on a free port, returns a handle with `.URL`, `.FetchState(t)`, `.LogPath()`. Lifecycle bound to `t.Cleanup`.
11. **`internal/e2e/aws_services_test.go`** — gated `TestE2E_AWS_{IAM,S3,VPC,Instance,RDS,DynamoDB,EKS,SQS,Route53,SecretsManager}` runners, using `runAWSServiceScenario` (clone/adapter of `runGCPServiceScenario`). Identity-preservation hooks: snapshot resource `name`/`arn` fields from `/mock/state` before the update phase, assert stability after, fail loudly if anything was destroy+recreated.
12. **`Makefile`** — `make run-fakeaws` boots fakeaws on `:8082` (mockway is `:8080`, fakegcp `:8081`). `make run-mocks` extended to start all three. `make e2e-aws` runs the gated aws e2e suite.

### Generator surface — one ticket each

Without these, the agent loop can't emit AWS HCL at all. fakegcp's experience is that `prompts/` and `pitfalls/` *together* are the gating bottleneck; without both, generated HCL fails syntactic checks before it even reaches the cloud mock.

13. **`prompts/aws/{phase1_plan_architecture,phase2_generate_hcl,phase3_self_review}.md`** — three cloud-aware prompt files, mirroring the *actual* `prompts/gcp/` and `prompts/scaleway/` layouts (which are three phase files per cloud, not a per-service matrix). The prompt files describe the *generation* phases of the agent loop; per-service rules don't live in prompts, they live in `pitfalls/aws.yaml`. The three files are seeded once in S43-T11; later phases extend `pitfalls/aws.yaml` with service-specific rules but do *not* add new prompt files. (Prior drafts of this section pictured a per-service `prompts/aws/<phase>/<service>.md` matrix; that design diverged from the existing two clouds and has been retracted — see resolved decision 11 in § "Resolved decisions".)
14. **`pitfalls/aws.yaml`** — starter ruleset of "the LLM repeatedly does X but should do Y" entries, modelled on `pitfalls/scaleway.yaml` and `pitfalls/gcp.yaml`. Initial set seeded from terraform-provider-aws's known footguns (e.g., `aws_security_group_rule` vs inline `ingress`/`egress` blocks; `aws_db_subnet_group` required for `aws_db_instance` with custom VPC; `aws_iam_instance_profile` is the bridge between roles and EC2). Auto-learning loop appends on successful self-correction, identical to the Scaleway pitfalls flow.
15. **`policies/aws/{region_restriction,encryption,vpc_required,no_public_db}.rego`** — per-cloud constraint policies. Same shape as `policies/gcp/`. region_restriction: allowlist `us-east-1`, `eu-west-1` by default. encryption: KMS-key-required guard for S3 SSE, RDS at rest, Secrets Manager. vpc_required: instances and DBs must reference a VPC, never default-VPC. no_public_db: RDS instances reject `publicly_accessible = true`. **Loader plumbing**: `infrafactory.yaml::validation.layers.static.policy_paths` extends to include `./policies/aws`, AND state-policy dispatch in `internal/cli/test_command.go` (which already does per-cloud lookup with a flat fallback) gains the `aws` mapping for AWS-specific resource types so `cloud: aws` scenarios route to the aws policies. Without these two glue changes the rego files would be dead.
16. **`internal/cli/mockway_client.go::cloudMockStateRouter`** (this lives in `internal/cli/`, not `internal/harness/` — the fakegcp dispatch is the existing reference) — dispatches `cloud: aws` to the running fakeaws instance. Tests cover **all four** cells of the routing contract: (a) positive dispatch — `cloud: aws` routes to `Config.Fakeaws.URL`; (b) unknown-cloud rejection with a clear error; (c) graceful fallback when `Fakeaws.URL == ""` (deterministic error, no panic — mirrors the existing `Fakegcp.URL == ""` shape); (d) per-cloud reset/snapshot/restore — a 3-mock concurrent test boots mockway + fakegcp + fakeaws on different ports, runs an aws scenario's reset, and asserts only fakeaws state was cleared.

### Test parity contract

The integration is *not* done until each of the **16 surfaces** above (items 1-16 across "Required surface" and "Generator surface" + the lazy provider-schema invocation restructure) has at least one targeted test asserting the aws path works. Mirror of how fakegcp's integration was tested: each public-API entry point gets an aws-specific subtest. This pre-empts the fakegcp drift where `cloudMockStateRouter` was wired but `real_probe` and `provider_schema` weren't, and aws scenarios silently used the scaleway code path.

### Per-phase pitfalls deliverables

The three `prompts/aws/phase*.md` files are seeded once in S43-T11 and do not change per phase (they describe generator stages, not services). Service-specific rules grow in `pitfalls/aws.yaml`, which IS extended per phase as new services land. The per-phase tickets `S44-T0`, `S45-T0`, `S46-T0`, `S47-T0` are *pitfalls extensions only* — each adds a documented set of terraform-provider-aws footguns for that phase's services.

| Slice | Pitfalls additions | Ticket |
|---|---|---|
| S43 | initial seed: 8+ entries covering IAM + S3 + general AWS provider footguns | S43-T11 |
| S44 | EC2-specific: security-group inline vs aws_security_group_rule; route-table FK shape; subnet/AZ pairing | S44-T0 |
| S45 | RDS: aws_db_subnet_group requirement, parameter-group attachment, deletion-protection footgun. DynamoDB: PK/SK shape, attribute-name uniqueness | S45-T0 |
| S46 | EKS: cluster→nodegroup ordering, IAM-role eks.amazonaws.com trust policy, subnet IPv4-block requirement. SQS: DLQ RedrivePolicy JSON shape, FIFO queue suffix | S46-T0 |
| S47 | Route53: atomic ChangeResourceRecordSets, hosted-zone NS-record auto-creation. Secrets Manager: recovery_window_in_days, force_overwrite_replica_secret semantics | S47-T0 |

Phase exit gate 9 (gated e2e in infrafactory) fails red if any service in that phase's scope is missing pitfalls coverage and the generator subsequently emits malformed HCL traceable to a known footgun. CI does *not* check prompt-file presence per service (there are no per-service prompt files); it does check that `pitfalls/aws.yaml` parses and that every entry's `pattern` field references a real provider resource type via a small static-analysis test.

## Resource coverage matrix

What "full CRUD" means per service. This is the surface infrafactory's training scenarios will exercise.

### IAM (foundation)
- Roles (Create/Get/List/Update/Delete + AttachRolePolicy / DetachRolePolicy)
- Policies (Create/Get/List/Delete + version management)
- Instance profiles (Create/Get/List/Delete + AddRoleToInstanceProfile)
- Users + access keys (Create/Get/List/Delete) — minimal, present for `aws_iam_user`
- ServiceLinkedRoles — synthesised on demand for EKS/etc.

### S3
- Buckets: Create/Head/Delete + GetBucketLocation, GetBucketTagging/PutBucketTagging
- Bucket versioning: Get/Put
- Bucket encryption: Get/Put
- Bucket policy: Get/Put/Delete
- Bucket public-access-block: Get/Put
- Bucket ownership controls: Get/Put
- Object operations: PutObject (accept + discard payload, return etag), GetObject (404), DeleteObject, ListObjectsV2 (returns empty list at v1) — present so terraform-provider-aws can probe the bucket without errors

### EC2
- VPC, Subnet, InternetGateway, RouteTable, Route, SecurityGroup + ingress/egress rules, EIP, NAT gateway
- Instance: Create / Describe / Terminate / Modify (limited: instance type, security groups, monitoring)
- KeyPair: Create / Describe / Delete
- AMI: read-only fixture set (so `data.aws_ami` works without us modelling the image lifecycle)

### RDS
- DBInstance, DBCluster (Aurora), DBSubnetGroup, DBParameterGroup, DBClusterParameterGroup
- Read replica via CreateDBInstance with SourceDBInstanceIdentifier
- ModifyDBInstance for in-place updates
- DescribeDBInstances filtering

### DynamoDB
- Table: Create / Describe / Update / Delete
- TimeToLive: Update / Describe
- Tagging: TagResource / UntagResource / ListTagsOfResource
- Item ops: PutItem / GetItem / UpdateItem / DeleteItem / Query / Scan (basic; no transactions/streams at v1)

### SQS
- Queue: Create / Get / Set attributes / Delete / List
- Tagging
- Message ops: SendMessage / ReceiveMessage / DeleteMessage. (`ChangeMessageVisibility` is OUT OF SCOPE at v1 — visibility timeout is collapsed to in-memory tracking that the request would have nothing meaningful to mutate. If a scenario actually needs runtime visibility-timeout changes later, it gets its own ticket.)

### EKS
- Cluster: Create / Describe / Update (config + version) / Delete
- NodeGroup: Create / Describe / Update / Delete
- AddOn: Create / Describe / Delete
- IAM-role / VPC subnet / security-group FK validation on cluster create

### Secrets Manager
- Secret: CreateSecret / DescribeSecret / UpdateSecret / DeleteSecret / RestoreSecret. `DeleteSecret` schedules deletion with `recovery_window_in_days`; `RestoreSecret` operates on the secret (not on a version) and reverses scheduled deletion when called within the window.
- Version: PutSecretValue / GetSecretValue / ListSecretVersionIds. Version-stage labels (`AWSCURRENT` / `AWSPENDING` / `AWSPREVIOUS`) are tracked. (AWS does not expose a per-version Restore operation — older fakegcp shorthand suggested otherwise; that was wrong.)
- Tagging: TagResource / UntagResource
- Terminal-state semantics: `DeleteSecret` schedules deletion with a `recovery_window_in_days` (default 30); `RestoreSecret` reverses scheduled deletion within the window; once the window elapses the secret is fully destroyed and any further `RestoreSecret` returns 409 `InvalidRequestException`. (Pattern lifted from fakegcp's Secret Manager terminal-state work — fakegcp pass 18 — but using the real AWS API names, not fakegcp's Pub/Sub `:destroy / :enable` shorthand.)

### Route53
- HostedZone: Create / Get / Delete (refuses non-empty)
- ResourceRecordSet: ChangeResourceRecordSets (CREATE / UPSERT / DELETE) — same transactional changes pattern fakegcp landed for Cloud DNS
- Tagging

## Phasing — six slices

The work is too large to land in one ticket. Slice it the way infrafactory was built:

**Phase 1 — Foundation** (`S43-T1` through `S43-T14` in BACKLOG)
- Repo scaffold (cmd, handlers, repository, models, testutil, Makefile, README, AGENTS.md, `.gitleaks.toml`, **tracked** `.githooks/pre-commit`, `make install-hooks` target)
- CI workflow (`.github/workflows/ci.yml`) on the very first commit: `go test ./... -race`, `gitleaks detect --redact --no-banner --source=.`, `go vet`, `go build`. CI is a required check on `main` from day one — see "Secret scanning from day one" for why this is mandatory pre-handler-code.
- Pre-seeded `regression_test.go` with the standing patterns from fakegcp's review loop (see § "Standing patterns to seed regression_test.go on day one"). All 16 tests are named and present from day one. Tests whose target handler doesn't yet exist call `requireHandlerImplemented(t, "<service>")`, which checks `regression_manifest.go` (a tracked file listing which services are landed in the current slice) and either calls `t.Skipf(...)` with a structured message — `TODO(slice=<S44>,service=<ec2>,pattern=<post-merge-PATCH>) regression awaits handler` (service ids are top-level only — `ec2`, not `ec2_instance` — per resolved decision 12) — *or* falls through to the real assertions when the manifest declares the service landed. **This refines, not contradicts, the "no `t.Skip()`" anti-pattern**: a bare `t.Skip()` is still forbidden, because the silent-greenlight risk is real; a manifest-gated skip is allowed because two CI checks remove the risk. Both checks live in a single file `fakeaws/handlers/regression_audit_test.go` (per resolved decision 12) with two functions: (1) `TestRegressionSeedAuditManifestMatchesHandlers` walks the manifest and the `handlers/` package and fails CI if a service prefix is in the handlers package but not in `LandedServices`, OR if `LandedServices` lists an id but its corresponding regression test still calls `requireHandlerImplemented`. (2) `TestRegressionSeedAuditNoVacuousPasses` parses test bodies via `go/ast` and fails if any test func contains both `requireHandlerImplemented(...)` and a passing `assert./require.` call (vacuous-pass detection). With both checks, the seed tests skip cleanly during phases when the handler isn't landed (so `go test ./...` stays green at every slice exit), and they're forced to flip to real assertions the moment the handler lands.
- `awsproto/` package: query-RPC parser, x-amz-target parser, XML / JSON response writers, per-protocol error-shape mappers (one mapper per wire format, each tested against `ErrInUse`/`ErrTerminalState`/`ErrConflict`/`ErrNotFound`).
- Repository skeleton with file-backed (`--db <path>`) and in-memory modes; `Reset()`/`Snapshot()`/`Restore()` lifecycle covers SQLite *plus* any in-process caches that exist in v1 — concretely: SQS visibility-timeout cache (lands with SQS in S46) and Route53 change-id cache (lands with Route53 in S47). DynamoDB streams are out of v1 scope so there is no stream-cursor cache. Cache-baseline lifecycle is pinned in `regression_test.go` from day one — no S48 deferral.
- Cross-resource FK validators (`resolveSameAccountName` helper, mirror of fakegcp's `resolveSameProjectName`) and the post-merge PATCH-validation pattern. Both land before the first handler so the conventions are enforced from line one, not retrofitted in Phase 6.
- **IAM service (full CRUD) — lands FIRST.** Every other service references IAM roles, policies, or instance profiles. IAM is the foundation; building S3 first would force re-stating the IAM contract.
- S3 service (bucket CRUD + minimal object ops, no payload store), built on top of IAM.
- infrafactory wiring (single ticket): `aws` added to `scenario.schema.json`'s cloud enum; `internal/config/config.go::Config` gains `Fakeaws FakeawsConfig`; `internal/cli/runtime.go` and `mockway_client.go` route `cloud: aws` to the fakeaws URL; `internal/harness/topology_derive.go::detectCloud` gains an aws branch with `deriveTopologyAWS`; `internal/harness/destroy.go::countOrphans` ignored-roots/-collections list extended to cover fakeaws's `operations` + `audit` bookkeeping tables (and `sqs_messages` once SQS lands in S46); `internal/harness/real_probe.go::probeTargetResourceTypes` gains AWS resource types per probe target; `internal/harness/provider_schema.go::ExtractProviderSchema` becomes cloud-aware; `internal/e2e/helpers.go::StartFakeaws` lands with the same shape as `StartFakegcp` (URL, FetchState, LogPath); Makefile gains `make run-fakeaws` and integrates fakeaws into the local mock-orchestration target.
- Generator surfaces seeded: `prompts/aws/{phase1_plan_architecture,phase2_generate_hcl,phase3_self_review}.md` (3 cloud-aware prompt files mirroring the *actual* `prompts/gcp/` and `prompts/scaleway/` layouts — service-specific guidance does NOT live in prompts, it lives in `pitfalls/aws.yaml`. See concepts.md § "Resolved decisions" item 11 for the retraction of an earlier per-service-matrix design); `pitfalls/aws.yaml` with a starter rule set (mirroring `pitfalls/gcp.yaml`), grown per phase via S44-T0..S47-T0; the **full** `policies/aws/{region_restriction,encryption,vpc_required,no_public_db}.rego` set — all four land at once in S43 so later phases don't have to revisit policy plumbing. Without these the generator can't emit aws-cloud HCL that the e2e harness can apply.
- Scenario-contract decision: DynamoDB lands as a new `dynamodb` resource type in `scenario.schema.json::properties.resources`, and SQS lands as a new cloud-neutral `messaging` resource type (so Pub/Sub-style services from other clouds can reuse the slot). Decided in concepts.md § "Resolved decisions" item 7 before any S43 ticket references the schema.
- One end-to-end gated test per foundation service: `TestE2E_AWS_IAM` and `TestE2E_AWS_S3`, wired through `runAWSServiceScenario` (clone of `runGCPServiceScenario`).

**Phase 2 — Networking + compute** (`S44-T0` through `S44-T12`)
- EC2 service (VPC, subnet, IGW, route table, SG, instance)
- AMI fixture data
- Training scenarios: `aws-vpc-network.yaml`, `aws-instance.yaml`
- Examples: `working/basic_instance`, `misconfigured/instance_missing_subnet`, `updates/update_security_group_rules`
- Gated e2e: `TestE2E_AWS_VPC`, `TestE2E_AWS_Instance`, `TestE2E_AWS_SecurityGroup`

**Phase 3 — Stateful data** (`S45-T0` through `S45-T10`)
- RDS (DBInstance, DBCluster, DBSubnetGroup, DBParameterGroup)
- DynamoDB (Tables + minimal item ops)
- Training scenarios + examples for both
- Gated e2e: `TestE2E_AWS_RDS`, `TestE2E_AWS_DynamoDB`

**Phase 4 — Containers + queues** (`S46-T0` through `S46-T10`)
- EKS (Cluster + NodeGroup + AddOn)
- SQS (Queue + minimal message ops)
- Training scenarios + examples
- Gated e2e: `TestE2E_AWS_EKS`, `TestE2E_AWS_SQS`

**Phase 5 — DNS + secrets** (`S47-T0` through `S47-T10`)
- Route53 (HostedZone + record sets via change API)
- Secrets Manager (Secret + version state machine)
- Training scenarios + examples
- Gated e2e: `TestE2E_AWS_Route53`, `TestE2E_AWS_SecretsManager`

**Phase 6 — Polish** (`S48-T1` through `S48-T8`; T2 and T3 vacated/MOVED to S43)
- Codex review iteration loop (mirror of the 33-pass fakegcp review)
- AGENTS.md, README, PLAN.md fleshed out to fakegcp parity (mockway-style "Common Bug Patterns" anti-pattern catalogue ported in; per-protocol wire-format reference; handler-registration walkthrough)
- `examples/{working,misconfigured,updates}/` coverage gap-fill, all three trees auto-discovered by mockway-style `examples/provider_smoke_test.go` so every directory is automatically a CI target — no hand-curation per service. The smoke test runs three distinct assertions per directory: `working/` directories must `apply → plan -detailed-exitcode → destroy` clean; `misconfigured/` directories must fail apply with a documented AWS error code (asserted via grep on the tofu output); `updates/` directories must `apply v1 → plan no-op → apply v2 → plan no-op → destroy` clean.
- Codex review-pass archive bootstrapped at `fakeaws/docs/review-passes/passN.md` so prompts and findings are version-controlled (mockway / fakegcp didn't archive theirs and that's a regret)
- Secret-scanning *audit*: re-run `gitleaks detect --no-banner --source=.` across the full repo history, confirm the day-one allowlist hasn't drifted, run a synthetic-positive injection test (try to commit a temp file containing `AKIAIOSFODNN7EXAMPLE`, expect rejection by both the local hook and CI). Initial gitleaks setup + tracked hook installer landed in Phase 1.

## Tickets

The full ticket list lives in `infrafactory/BACKLOG.md` under a new "fakeaws" slice. Each ticket follows the `S{slice}-T{n}` convention already in use. A summary follows; full descriptions are in the backlog.

```
S43 — fakeaws Phase 1: Foundation + full integration   (14 tickets)
S44 — fakeaws Phase 2: Networking + compute           (13 tickets — incl. S44-T0 pitfalls extension)
S45 — fakeaws Phase 3: Stateful data                  (11 tickets — incl. S45-T0 pitfalls extension)
S46 — fakeaws Phase 4: Containers + queues            (11 tickets — incl. S46-T0 pitfalls extension)
S47 — fakeaws Phase 5: DNS + secrets                  (11 tickets — incl. S47-T0 pitfalls extension)
S48 — fakeaws Phase 6: Polish + codex review          (6 active tickets; T2 + T3 vacated/MOVED to S43)
M39, M40 — Maintenance tickets folded into S43-T2 / S48-T4 acceptance (kept on the backlog as historical references; status: done-via-fold)
```

Total: 68 fakeaws S-ticket rows (S43 14 + S44 13 + S45 11 + S46 11 + S47 11 + S48 8 = 68; minus 2 vacated/MOVED in S48 = 66 active) plus 2 maintenance M-tickets folded into slice acceptance criteria (M39 + M40, marked "done via fold" in BACKLOG). The S43 expansion absorbs codex review pass 1's BLOCKING findings; the per-phase `T0` *pitfalls-extension* tickets (no new prompt files; pass-4 retracted the per-service prompt matrix) and the auto-discovery example contract absorb pass 2's findings; M39 (per-service ARN builders) and M40 (cross-pollination policy) absorbed into S43-T2 and S48-T4 in pass 6. The phases remain sequential — S44 depends on S43's awsproto package and integration plumbing; later phases depend on the foundation being green.

## Quality guarantees

How fakeaws will land at or above the bar that mockway and fakegcp set. The bar is concrete: every contract pinned by a test, every wire shape driven through the live `hashicorp/aws` provider at least once, every phase passed two consecutive codex `NOTHING_TO_IMPROVE` reviews before exiting.

### What "matches mockway quality" means in practice

Mockway has 280+ handler tests, full FK enforcement, an `examples/` harness that drives the live Scaleway provider, and three years of accepted-PR-rejected improvements baked in. fakegcp landed at the same bar in 33 codex review passes; each pass tightened a specific gap (FK shape, post-merge validation, wire-format edge cases, terminal-state semantics, snapshot-baseline lifecycle). The 33-pass count is the load-bearing data point: discovering quality after the fact is what makes the loop long. The only way to land at the same bar in fewer passes is to *wire the gates into the workflow before writing any handler code*. That is what this section commits to.

### Mandatory gates per implementation phase (S43–S47)

Each implementation slice exits only when every applicable gate is green. Gates 6, 7, and 8 (working / misconfigured / updates examples) apply *per service in scope for that phase*; if a phase ships only foundational scaffolding (S43's awsproto, repo, infrafactory wiring), the example gates fire only for the actual service deliverables in that phase (IAM and S3 for S43). No phase rolls forward with an outstanding red gate on a service it claims to ship.

1. **CRUD test** for every resource in scope: Create → Get → List → Update/Patch → Delete → 404. testutil-driven, integration-level. Asserts both the success path and the post-delete 404.
2. **FK violation tests** for every cross-resource reference: a misconfigured Create returns 404 with the right error reason. Both same-account and cross-account FK refs covered (the `resolveSameAccountName` helper, mirror of fakegcp's `resolveSameProjectName`).
3. **Cascade / dependent-delete tests** for every parent-child relationship: ON DELETE CASCADE behaviours pinned, FK-blocked deletes return ErrInUse + 409.
4. **Update-path FK tests**: PATCH that flips a referenced field re-validates the post-merge state. Mirror of fakegcp's pass-28 fix.
5. **State-machine tests** where applicable: terminal-state refusals (Secrets Manager `RestoreSecret` after the recovery window has fully elapsed returns 409 `InvalidRequestException`; EC2 terminated-instance refusal of restart; RDS deleting-instance refusal of modify), state transitions on Update.
6. **Working example through tofu** for each service in scope this phase: `terraform apply → terraform plan -detailed-exitcode (no diff) → terraform destroy`. Plan-idempotency caught wire-format drift in fakegcp; same gate here. Auto-discovered by `examples/provider_smoke_test.go` (mirror of `mockway/e2e/provider_smoke_test.go`) — adding a directory under `examples/working/` automatically registers it for the smoke test, no hand-curation per service.
7. **Misconfigured example through tofu** for every service that has cross-resource FK refs: `terraform apply` fails with the AWS-shaped error code we return. The provider must surface our 404/409 as the right Terraform error message — verifies the error-shape mapping in `awsproto`. Foundational services with no FK refs (e.g., a bare IAM user) may not need a misconfigured example; if so, the phase exit checklist explicitly notes the exemption. **Same auto-discovery contract as gate 6**: any directory under `examples/misconfigured/` automatically registers; the smoke test asserts apply fails AND the documented error code appears in the output.
8. **Updates example through tofu** for every service whose v1 surface includes a mutable field: `terraform apply -var-file=v1.tfvars → terraform apply -var-file=v2.tfvars` reaches v2 in place (no destroy/recreate unless explicitly documented like `google_service_account_key` was for fakegcp). **Same auto-discovery contract as gates 6 and 7**: any directory under `examples/updates/` containing both `v1.tfvars` and `v2.tfvars` automatically registers for the smoke test.
9. **Gated e2e in infrafactory** (`TestE2E_AWS_*` with `INFRAFACTORY_ENABLE_E2E=1`): full create→update→destroy lifecycle through `runAWSServiceScenario`, identity-preservation check on the update phase (resource `name` / `arn` fields stable across updates, no destroy+recreate), verify-callback assertion that the update mutation actually surfaced in `/mock/state`.
10. **Two consecutive codex `NOTHING_TO_IMPROVE` review passes** scoped to that phase's diff. Same loop fakegcp went through. Phase doesn't exit until both passes return clean. Prompts and findings archived under `fakeaws/docs/review-passes/passN.md`.

### Standing patterns to seed `regression_test.go` on day one

Pre-seed `handlers/regression_test.go` *before* writing each phase's handlers, drawn from the fakegcp pass-by-pass findings that translate directly to AWS:

- **Cross-account FK rejection** — `resolveSameAccountName` rejects refs whose account-id segment is wrong even when the trailing name happens to exist locally. (fakegcp pass 27.)
- **Wrong-collection FK rejection** — same helper rejects same-account paths whose collection segment doesn't match. Closes the trailing-name-collision escape hatch. (fakegcp pass 28.)
- **Relative-path wrong-collection rejection** — the rejection holds for `regions/us-east-1/subnets/x` style paths too, not just `arn:aws:` shapes. (fakegcp pass 29.)
- **Subnet/VPC pairing** — instance / cluster create that names a VPC and a subnet must verify the subnet's parent VPC matches. (fakegcp pass 27.)
- **Post-merge PATCH validation** — `UpdateXxx` validates the merged state, not the raw patch. A partial PATCH that flips only `subnetwork` cannot smuggle in a mismatched VPC. (fakegcp pass 28.)
- **Bare-name region scoping** — bare-name subnet refs scoped to the request's zone-derived region (or cluster location). (fakegcp pass 30.)
- **Region-vs-zone heuristic** — distinguish region from zone by suffix shape; don't strip a region's trailing segment as if it were a zone letter. (fakegcp pass 31.)
- **Cache-baseline lifecycle on /mock/reset** — any in-memory cache that exists in v1 (SQS message visibility timeouts in S46, Route53 change-id cache in S47, EC2 instance-status pollers if implemented) must clear and snapshot/restore alongside the SQLite repo. DynamoDB streams cursors are out of v1 scope; if added later this pattern extends to them. (fakegcp pass 18.)
- **Terminal state refuses transitions** — Secrets Manager `RestoreSecret` returns 409 `InvalidRequestException` once the recovery window has elapsed (the secret is fully destroyed and cannot be restored); EC2 terminated-instance refusal of restart; RDS deleting-instance refusal of modify. (fakegcp pass 18, ported to real AWS API surface.)
- **Distinct 409 sentinels** — `ErrInUse` (FK-blocked delete) and `ErrTerminalState` (state can't transition) carry different wire payloads. Generic `ErrConflict` is a fallback only. (fakegcp pass 20.)
- **Hosted-zone delete refused if non-empty** — Route53 zone delete checks rrset count first. (fakegcp pass 21.)
- **Tombstone semantics on parent delete** — SQS queue delete must rebadge in-flight messages, mirroring fakegcp's `_deleted-topic_` pattern for Pub/Sub. (fakegcp pass 25.)
- **Resource-existence gate on every sub-resource / child handler** — record-set under hosted-zone, item under DynamoDB table, message under SQS queue, version under secret: each handler calls a `requireParentX` helper that 404s if the parent is missing. Missing-parent must be 404 (resource not found), not 500. (fakegcp pass 22.)
- **Server-stamped fields are never trusted from the client** — `id`, `arn`, `creationDate`, etc. are written by the repo on insert; PATCH carries an explicit skip-list of immutable fields. (fakegcp pass 4.)
- **SQL-column / JSON-blob sync on UPDATE** — when an Update writes a JSON blob *and* mutates an extracted SQL column (e.g., `vpc_id`, `region`), both must be updated atomically. mockway's bug catalogue lists this as the highest-frequency category of regression: the JSON gets rewritten, the indexed column stays stale, list-by-region returns wrong results.
- **Transactional batched changes** — Route53 `ChangeResourceRecordSets` is the v1 canonical batch primitive: a batch with one bad change rejects the whole batch with no partial state. Tested with a happy-path batch and a poisoned batch in the same test fixture. (fakegcp pass 1 + cross-pollination.) DynamoDB `BatchWriteItem` and SQS `SendMessageBatch` follow the same all-or-nothing rule but are **out of scope at v1** per § "Resource coverage matrix" (DynamoDB v1 = single-item ops only; SQS v1 = single-message ops only). When either is added later, the corresponding regression test extends this pattern; until then the seed test for this pattern targets Route53 alone.

### Secret scanning from day one

A fake AWS server is the most natural place in the codebase for a real `AKIA…` access key to get pasted by accident — the test fixtures literally model AWS credentials. Secret scanning therefore is not a Phase 6 polish item; it is a Day-1 deliverable. The key constraint is that `.git/hooks/` is *not* a versioned path — git won't let you check it in, so you cannot ship a hook directly. The fakeaws design gets around this by separating "tracked policy" (reviewable, enforced) from "tracked installer" (run-once on clone) from "CI gate" (ground-truth):

- **Tracked policy** (the contract — committed). `.gitleaks.toml` allowlists exactly `examples/.*\.tf$` (placeholder Terraform credentials for misconfigured/working fixtures). Any further allowlist entry requires a justification line in the same file. Mirrored from fakegcp's `.gitleaks.toml` verbatim. This is the authoritative ruleset.
- **Tracked hook installer** (the local enforcement — committed). `.githooks/pre-commit` is a tracked, executable shell script that runs `gitleaks protect --staged --no-banner` *before* `go test ./...`. A first-commit `make install-hooks` target wires it up via `git config core.hooksPath .githooks`. The Makefile target is idempotent — re-running it is safe. README's quickstart calls it out as the second step after `go mod download`.
- **CI ground truth** (the gate that matters — committed). `.github/workflows/ci.yml` runs `gitleaks detect --redact --no-banner --source=.` on every push and PR, *independent* of whether anyone configured the local hook. Marked as a required check on the protected branch. CI is what stops a leaked credential from merging — the local hook is a fast-fail convenience, not the security boundary.
- **First-commit invariant**: `.gitleaks.toml`, `.githooks/pre-commit`, `make install-hooks`, and `.github/workflows/ci.yml` all land in the very first commit — before any handler code, before any package skeleton beyond `go.mod`. There is no commit on the timeline that contains Go code without all four gates committed.
- **Hook ordering rationale**: gitleaks runs *before* `go test ./...` because secret detection must short-circuit the commit before tests have a chance to print env vars (or fixture contents) to terminal logs. A commit blocked by the hook should not have left a `git stash`able trace of the secret in scrollback.
- **Synthetic-positive test (S48)**: Phase 6 re-runs gitleaks across the full repo history *and* injects a synthetic `AKIAIOSFODNN7EXAMPLE`-style placeholder in a temp file to verify both the local hook *and* CI still fire. If either doesn't trip, the allowlist has drifted too far and is rolled back.
- **Cross-pollination**: mockway and fakegcp currently use *local-only* hooks (`.git/hooks/pre-commit`, untracked) — fakeaws will be the first repo to ship the tracked-installer pattern. Once it's proven, the same `.githooks/` + `make install-hooks` lands back in mockway and fakegcp.

### Coverage targets and CI

- **Aggregate `handlers/...` line coverage ≥ 80%** at the end of each phase (aggregate over the combined handlers tree, not per-package — that's a deliberate simplification; per-package thresholds proved noisier than they were worth in fakegcp). The `coverage` CI job runs `go test -coverprofile=cov.out -covermode=atomic ./handlers/...` then `go tool cover -func=cov.out` and parses the `total:` line; PR fails if the percentage drops below the threshold for that phase. fakegcp's aggregate coverage hit 84% at v1 — same target.
- **Pre-commit hook** runs `gitleaks protect --staged --no-banner` then `go test ./...`. Established in the first scaffold commit (see "Secret scanning from day one"), not deferred to Phase 6.
- **GitHub Actions matrix**: `go test ./... -race` on Linux + macOS, `gitleaks detect --redact --no-banner --source=.`, `go vet`, `go build`. PRs cannot merge if any stage fails.
- **Auto-discovered examples smoke test in CI**: a single CI job boots fakeaws on a temp port, then `examples/provider_smoke_test.go` walks `examples/working/`, `examples/misconfigured/`, and `examples/updates/` and applies the right contract per directory (working: apply→plan→destroy; misconfigured: apply must fail with documented error; updates: apply v1→plan→apply v2→plan→destroy). Each directory is its own subtest. Adding a directory automatically registers it — there is no per-service smoke ticket. This single gate caught at least three wire-format bugs in fakegcp during the review loop and is the strongest single-source-of-truth for "does it actually work with the provider".

### Phase 6 (S48) is dedicated to the codex iteration loop

Slice 48 is *not* a feature slice. It exists explicitly to run the same review iteration loop that landed fakegcp's quality, scoped across the union of the prior five phases. Until two consecutive `NOTHING_TO_IMPROVE` returns, fakeaws v1.0 is not shippable.

Codex prompts for these passes follow the exact template that worked for fakegcp:
- Cite recent commit hashes since the previous pass
- Summarise what changed
- Ask for `BLOCKING:` / `SUGGEST:` / `NOTHING_TO_IMPROVE` findings
- Require `file:line` citations
- Restart the count if any pass returns BLOCKING (a single SUGGEST is OK; only NOTHING_TO_IMPROVE counts).

Budget for S48 is 20–35 passes based on fakegcp's 33-pass landing. If the count blows past 40, the gates from Phase 1–5 weren't being enforced — investigate the workflow, not the code.

### Cross-pollination back to mockway and fakegcp

If any pass-finding from fakeaws's review loop reveals a class of bug the older mocks share — and the 33-pass fakegcp loop suggests this is likely — the fix lands back in mockway/fakegcp before the relevant fakeaws phase exits. This keeps all three mocks at the same quality bar instead of forking.

Concrete instances where this is likely:
- New cross-resource FK validators discovered during the EC2 phase may translate to mockway's VPC↔private-network FK chain.
- AWS state-machine refinements (e.g., RDS modifying-state transitions) may surface gaps in mockway's RDB read-replica handling.
- Wire-format error-shape consistency tests may apply to all three mocks.

### Anti-patterns explicitly forbidden

These are the failure modes we already paid for in mockway and fakegcp; they are not allowed to recur in fakeaws:

- **No silent 200**. `UnimplementedHandler` returns 501 and logs `UNIMPLEMENTED: <method> <path>`. Callers see exactly what's missing. Mockway has 155 of these tracked; fakegcp had ~30. They are the discovery surface for "what does the next caller actually need".
- **No Moto-style fallback**. We model the resource or we 501 it. Silent partial implementations are how LocalStack accumulated multi-year drift between its custom code and Moto's state.
- **No `t.Skip()` tests**. A skipped test counts as zero coverage; either we pin the contract or we don't ship the feature. Skipped tests in fakegcp's history were always rewritten before merge.
- **No partial CRUD**. A resource is Create+Get+List+Update+Delete (the v1 contract) or it's not in scope. fakegcp had at least one ticket reopened because Update was missing on a resource that List/Get already supported.
- **No "TODO: validate later" FK checks**. If the wire format carries a reference, the handler validates it before writing to the repo. The repo's FK constraints are the second line of defence, not the first.
- **No untested error-shape mappings**. Every distinct error path through `awsproto.WriteAWSError` is exercised by at least one handler test that asserts the response body, not just the status code.

## Open questions

1. **Account namespacing.** AWS state is keyed by `(account_id, region)`. fakegcp punted on the project axis (one project per fakegcp instance) and infrafactory's GCP scenarios all use `fake-project`. Mirror that for fakeaws — one synthetic account ID `000000000000`, region as a column where it matters. Multi-account support is a v2 problem.
2. **Auth: Bearer or fake-SigV4?** The Terraform AWS provider always sends a SigV4 signature. We don't validate it but we do need to *accept* it (return 200, don't choke on the headers). Real LocalStack accepts everything; fakeaws will too. But we may want a "credentials look syntactically valid" check at v1 so a misconfigured provider block fails fast instead of getting weird "resource not found" errors.
3. ~~**ARN format.**~~ *Resolved in pass 6 — see "Resolved decisions" item 13 below. Replaced by per-service builders in `awsproto/arn.go`; the original single-format design was retracted because real AWS ARN formats vary per service (IAM omits region, S3 is bucket-scoped, Route53 is global, EC2/RDS/EKS embed region+account).*
4. ~~**terraform-provider-aws compatibility version.**~~ *Resolved (see "Resolved decisions" item 14): pinned to `~> 5.70` in the e2e harness and prompts. Bumps are explicit per-PR.*
5. **S3 object payload — really not modelled?** The trade-off is real: terraform-provider-aws's `aws_s3_object` resource expects the body to round-trip correctly, otherwise plan-after-apply diffs. Decision: at v1 we accept PutObject and store the object metadata + content hash, but discard the payload. GetObject returns 404 (the resource is "write-only" from terraform's perspective). If a scenario actually needs object content, we revisit.
6. **Where does `concepts.md` live long-term?** Probably folded into `fakeaws/PLAN.md` once the repo is fleshed out. Until then it's the load-bearing planning doc.

## Resolved decisions

The following questions had to be answered before tickets could land. Recorded here so the rationale is preserved when the relevant code is touched.

7. **Scenario contract for AWS-specific services (DynamoDB, SQS).** *Resolved:* extend `scenario.schema.json::resources` with two new resource types — `dynamodb` and `messaging` (rather than `sqs` so the slot stays cloud-neutral and Pub/Sub-style services from other clouds can fit later). Both are optional. Aws scenarios using them set `cloud: aws`. The Go-side `internal/scenario/scenario.go` mirrors the schema. Reusing existing `database` for DynamoDB was rejected — DynamoDB's NoSQL shape (PK/SK, attribute projections) doesn't fit a generic `database` envelope and would force every cloud to carry NoSQL fields they don't use. New types are cleaner.
8. **Hook installation strategy.** *Resolved:* tracked `.githooks/pre-commit` + `make install-hooks` (which sets `core.hooksPath`) + CI gitleaks step as the ground-truth gate. Untracked `.git/hooks/pre-commit` (mockway/fakegcp's current pattern) is *not* shippable as a "first-commit invariant" since git won't version it. See "Secret scanning from day one".
9. **Day-1 vs Phase-6 placement of regression seeds, FK validators, and countOrphans extensions.** *Resolved:* all three are S43 deliverables, not S48. The fakegcp loop's main lesson is that quality discovered post-hoc is what makes the codex pass count blow up; pre-seeding patterns and validators on day one is how fakeaws lands in the projected 20-pass budget instead of fakegcp's 33.
10. **Hook on `.git/hooks/`-style invariant — git-history-friendly?** *Resolved:* No. `.git/hooks/` is not versioned. Day-1 invariant is now expressed as "the four files `.gitleaks.toml`, `.githooks/pre-commit`, `Makefile` (with `install-hooks` target), `.github/workflows/ci.yml` are present in the first commit." That's verifiable from git history; the un-trackable `.git/hooks/` path is not in scope.
11. **Prompt-template layout — per-service matrix or three phase files?** *Resolved:* three phase files only — `prompts/aws/{phase1_plan_architecture,phase2_generate_hcl,phase3_self_review}.md`, mirroring the actual layout of `prompts/gcp/` and `prompts/scaleway/`. Per-service guidance lives in `pitfalls/aws.yaml` (which IS per-service and grows per phase), not in prompts. Earlier drafts of this concepts doc described a `prompts/aws/<phase>/<service>.md` matrix copied from a misread of the GCP layout; that design has been retracted.
12. **`regression_manifest.go` schema and audit semantics.** *Resolved:* the manifest is a single tracked Go file at `fakeaws/handlers/regression_manifest.go` with one exported variable `LandedServices = []string{...}` listing **service-level** ids — one short string per top-level AWS service, not subservice-scoped: `iam`, `s3`, `ec2`, `rds`, `dynamodb`, `eks`, `sqs`, `route53`, `secretsmanager`. (The earlier "kebab-case" wording was misleading since none of the actual ids use hyphens; all are single lowercase tokens.) `requireHandlerImplemented(t, id)` checks `slices.Contains(LandedServices, id)`. Both audit tests live in a **single** file `fakeaws/handlers/regression_audit_test.go` with two functions: (a) `TestRegressionSeedAuditManifestMatchesHandlers` walks the manifest and asserts every id in `LandedServices` is satisfied by **at least one** `handlers/<id>*.go` file (so `ec2` is satisfied collectively by `handlers/ec2_network.go` + `handlers/ec2_security.go` + `handlers/ec2_instance.go`) AND no service group in `handlers/` lacks a manifest entry — the audit groups files by their before-first-`_`-or-`.go` prefix and asserts every prefix is in the manifest. (b) `TestRegressionSeedAuditNoVacuousPasses` parses test bodies via `go/ast` and asserts no `requireHandlerImplemented` call coexists with `assert./require.` calls in the same `func`. (Note: the handlers package is one Go package with per-service files, not one package per service — both audits walk files, not packages. Earlier drafts referred to two separate files `regression_seed_audit_test.go` and `regression_seed_grep_test.go`; that split was retracted in favor of one file with two test funcs.)
14. **terraform-provider-aws compatibility version pin.** *Resolved:* `hashicorp/aws ~> 5.70` (or whatever 5.x version is current at S43-T1 ship time — the constraint string lands in S43-T1 and is the single source of truth referenced by every example's `required_providers` block, every prompt template, and the e2e harness's provider config). Bumps require an explicit PR that updates all three locations together. Mirror of how fakegcp pinned `hashicorp/google ~> 5.x`.

13. **ARN format — per-service builders, not a single generic format.** *Resolved (pass 6):* `awsproto/arn.go` ships per-service `BuildXxxARN(...)` helpers because real AWS ARN formats vary per service. IAM: `arn:aws:iam::<account>:role/<name>` (no region). S3 bucket: `arn:aws:s3:::<bucket>`. Route53 hosted zone: `arn:aws:route53:::hostedzone/<id>` (global, no region). EC2 instance: `arn:aws:ec2:<region>:<account>:instance/<id>`. RDS DB: `arn:aws:rds:<region>:<account>:db:<id>` (colon, not slash). EKS cluster: `arn:aws:eks:<region>:<account>:cluster/<name>`. SQS queue: `arn:aws:sqs:<region>:<account>:<name>` (no resource-type prefix). Secrets Manager: `arn:aws:secretsmanager:<region>:<account>:secret:<name>-<random>`. DynamoDB table: `arn:aws:dynamodb:<region>:<account>:table/<name>`. Each helper has a unit test asserting its output matches the format documented in the AWS reference for that service. The earlier single-builder design (one generic `arn:aws:<service>:<region>:<account>:<resource-type>/<id>` shape) is explicitly rejected — it does not match any real service uniformly.

## Anti-patterns: the mockway 14-bug catalogue

mockway's AGENTS.md captures fourteen recurring bug categories from three years of accepted-PR-rejected-improvements. Every category translated into at least one fakegcp regression test during its review loop. Pre-seed regression coverage for these in fakeaws so the same bugs cannot land:

1. **Wrong error helper on Create paths.** `writeCreateError` (FK 404) vs `writeDomainError` (mutation conflict) carry different semantics and codes. Mixing them returns 500 where 404 is expected.
2. **SQL column / JSON blob desync on Update.** Already in standing-patterns list.
3. **Payload field-name variations across provider versions.** terraform-provider-aws renames fields between major versions (e.g., `aws_route` `gateway_id` vs `transit_gateway_id`). Accept both shapes in the decoder; emit canonical form on read.
4. **Truncating multi-item lists.** Process all items in a batch, not just `[0]`. At v1 the canonical example is `ChangeResourceRecordSets` (Route53). `BatchWriteItem` and `SendMessageBatch` are out of v1 scope but follow the same rule — when they're added, this regression must be re-checked.
5. **Response-encoding mismatches.** `[]byte` payloads in JSON must be base64-encoded (DynamoDB binary attributes, SecretsManager secret values). XML responses use raw bytes inside CDATA blocks.
6. **Reset must include all tables.** Every new persistent table is added to `Reset()`'s wipe list. Forgetting one means a "reset" leaves data behind.
7. **Cross-resource state sync on create.** Creating a child often updates the parent (e.g., creating a security-group rule mutates the parent SG's `IngressRules` list). The repo writes both atomically.
8. **Multi-step writes must be atomic.** Use a SQL transaction or fail the whole operation. Half-applied writes are the worst regression to debug.
9. **Validate referenced resources on set/replace.** `PUT /role/policy` with a non-existent policy must 404, not silently succeed.
10. **Every sub-resource operation validates parent exists.** Already in standing-patterns list (resource-existence gate).
11. **Never auto-generate IDs for unvalidated inputs.** If the caller's body is malformed, fail before stamping an ID — otherwise we leak ID-space.
12. **Nested-path child ownership validation.** `/buckets/{b}/objects/{o}` — verify `o`'s stored bucket matches `b`. Cross-bucket reads via path traversal are the regression here.
13. **Cross-parent reference validation.** A subnet's stored VPC must match the VPC the caller declares on instance create. Already in standing-patterns list (subnet/VPC pairing).
14. **Reverse fidelity — don't over-correct.** If the real API silently accepts a malformed input, we accept it too. Fidelity to real API behaviour beats theoretical correctness — otherwise terraform-provider-aws hits errors against fakeaws that it never hits in production.

Each entry in this list maps to at least one regression test pre-seeded in S43-T10. AGENTS.md (S48-T5) ports the full table verbatim from mockway, adapted to AWS examples.
