# fakeaws examples

fakeaws is a local AWS API mock that catches infrastructure mistakes at apply time — mistakes that `terraform validate`, `terraform plan`, and `terraform test` all let through.

The broken configs in this directory are valid Terraform. They pass validation. They produce a clean plan. The errors only surface when the provider actually calls the API and fakeaws enforces the same FK constraints as the real AWS API.

---

## Prerequisites

- Go 1.24+
- Terraform or OpenTofu

---

## Step 1 — Install fakeaws

```bash
go install github.com/redscaresu/fakeaws/cmd/fakeaws@latest
```

Or build from a clone:

```bash
git clone https://github.com/redscaresu/fakeaws.git
cd fakeaws
make build   # produces ./fakeaws
```

---

## Step 2 — Start fakeaws

Open a dedicated terminal and leave it running:

```bash
fakeaws --port 8082
```

To confirm fakeaws is ready:

```bash
curl -s http://localhost:8082/mock/state | jq .schema_version
# 1
```

---

## Step 3 — Run an example

Each `working/` and `misconfigured/` example is self-contained: `cd` into it and run the usual Terraform workflow.

```bash
cd working/vpc_network

tofu init
tofu apply -auto-approve
tofu destroy -auto-approve
```

The `misconfigured/` examples will error during apply with an AWS-shaped error code from fakeaws. The comments at the top of each `main.tf` show the error shape and how to fix it.

The `updates/` examples are split across two `tfvars` files so the apply-then-update lifecycle is explicit:

```bash
cd updates/update_s3_bucket_versioning

tofu init
tofu apply -var-file=v1.tfvars -auto-approve
tofu apply -var-file=v2.tfvars -auto-approve   # in-place patch
tofu destroy -var-file=v2.tfvars -auto-approve
```

---

## Step 4 — Reset state between runs

fakeaws holds state in SQLite (in-memory by default). After a failed apply, partial resources may remain. Reset without restarting:

```bash
curl -s -X POST http://localhost:8082/mock/reset
```

Inspect current state at any time:

```bash
curl -s http://localhost:8082/mock/state | jq .
curl -s http://localhost:8082/mock/state/rds | jq .   # single-service slice
```

---

## Provider configuration

Each example sets up its provider block targeting fakeaws. The pattern:

```hcl
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "fake"
  secret_key                  = "fake"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    iam            = "http://127.0.0.1:8082/iam"
    ec2            = "http://127.0.0.1:8082/ec2/region/us-east-1"
    rds            = "http://127.0.0.1:8082/rds/region/us-east-1"
    eks            = "http://127.0.0.1:8082/eks/region/us-east-1"
    dynamodb       = "http://127.0.0.1:8082/dynamodb/region/us-east-1"
    sqs            = "http://127.0.0.1:8082/sqs/region/us-east-1"
    secretsmanager = "http://127.0.0.1:8082/secretsmanager/region/us-east-1"
    route53        = "http://127.0.0.1:8082/route53"
    s3             = "http://127.0.0.1:8082/s3"
  }
}
```

Only declare the endpoints the example actually uses — `examples/working/<svc>/providers.tf` shows the minimal subset per service.

---

## Examples

### working

Configs that apply, can be updated, and destroy cleanly. These show the right way to express AWS resource dependencies so that fakeaws's FK constraints — and the real API's — are satisfied.

| Example | What it demonstrates |
|---|---|
| `working/basic_instance` | EC2 instance with key pair + AMI lookup against the fixture set |
| `working/dynamodb_table` | DynamoDB table with attribute + key schema + GSI |
| `working/eks_cluster` | EKS cluster + node group with the IAM cluster + node roles (M57 wire-shape work + M61 closure makes the cluster's pre-Read flow pass) |
| `working/iam_role` | IAM role + assume-role policy + policy attachment |
| `working/rds_instance` | RDS subnet group + parameter group + Postgres DB instance (M61: full apply→plan-no-op→destroy lifecycle) |
| `working/route53` | Route53 hosted zone + record set |
| `working/s3_bucket` | S3 bucket + server-side encryption configuration (sub-resource reads use SeaweedFS in cross-repo infrafactory tests, see M59) |
| `working/secrets_manager` | Secrets Manager secret + initial version (M62: ARN-or-name SecretId, epoch timestamps, full lifecycle) |
| `working/sqs_queue` | SQS queue with visibility + retention + redrive policy |
| `working/vpc_network` | VPC + subnets + internet gateway + route table + security group (the dependency chain) |

### misconfigured

Valid Terraform that produces a clean plan, but the apply fails because fakeaws enforces the same FK constraints as the real AWS API.

| Example | What fakeaws catches |
|---|---|
| `misconfigured/eks_node_group_subnet_outside_cluster` | Node group references a subnet that isn't part of the cluster's VPC |
| `misconfigured/iam_attachment_missing_role` | Role-policy attachment references a role that doesn't exist |
| `misconfigured/instance_missing_subnet` | EC2 instance references a non-existent subnet |
| `misconfigured/rds_missing_subnet_group` | RDS instance references a DB subnet group that hasn't been declared |
| `misconfigured/route53_apex_cname` | CNAME record on the apex of a hosted zone (AWS rejects; CNAME at apex isn't valid per RFC 1034) |

### updates

Update scenarios that verify in-place resource modifications work correctly. Each directory contains `main.tf` (with variables), `v1.tfvars` (initial state), and `v2.tfvars` (updated state). The test cycle is: apply v1 → apply v2 → destroy.

| Example | What it demonstrates |
|---|---|
| `updates/update_iam_role_description` | Patch the description on an existing IAM role |
| `updates/update_rds_parameter_group` | Modify a parameter in an RDS DB parameter group |
| `updates/update_s3_bucket_versioning` | Toggle S3 bucket versioning on/off |
| `updates/update_secret_value` | Rotate a Secrets Manager secret's value via PutSecretValue (M62: AWSCURRENT→AWSPREVIOUS staging) |
| `updates/update_security_group_rules` | Add a security-group ingress rule to an existing SG |
| `updates/update_sqs_queue_visibility` | Patch an SQS queue's visibility timeout |

---

## Provider version pin

All examples use `hashicorp/aws ~> 5.70` per `concepts.md` "Resolved decisions" item 14. Provider bumps require an explicit PR updating every `required_providers` block + the prompts + the e2e harness.

---

## Auto-discovery + idempotency gate

`examples/provider_smoke_test.go` walks the three trees with `runtime.Caller` and registers each subdirectory as its own `t.Run` sub-test. Adding a directory adds a test — no per-example test wiring. Each sub-test runs:

| Tree | Contract |
|---|---|
| `working/<svc>/` | `apply → plan -detailed-exitcode 0 → destroy` — second plan MUST be a no-op |
| `misconfigured/<svc>/` | `apply` MUST fail; if `expected.txt` is present, the error output MUST contain that fragment |
| `updates/<svc>/` | `apply -var-file=v1.tfvars → plan no-op → apply -var-file=v2.tfvars → plan no-op → destroy` |

The harness assumes a fakeaws server is reachable at `FAKEAWS_URL` (default `http://127.0.0.1:8082`); the [infrafactory](https://github.com/redscaresu/infrafactory) cross-repo runner starts one via `make fakeaws-up` before running the gated AWS e2e tests.

**No allowlist** — mockway and fakegcp use an `examples/known_broken.yaml` ratchet for examples whose idempotency gate is currently expected to fail. fakeaws's S43–S48 codex review loop closed at pass 17 with zero allowlist entries, so the smoke harness enforces the working-tree contract strictly. Any new example that drifts must be fixed before merge, not allowlisted.

---

## Adding coverage for a new resource

1. Add an `examples/working/<svc>/` directory with `providers.tf` + `main.tf`.
2. Start fakeaws (`make build && ./fakeaws --port 8082`).
3. Run `INFRAFACTORY_ENABLE_E2E=1 go test ./examples/...` — auto-discovery picks it up.
4. If it drifts: fix the handler — the drift is the signal.
5. Mirror with `examples/misconfigured/<svc>/` (FK / validation paths) and `examples/updates/<svc>/` (update paths) as the service warrants.
6. Add a `TestE2E_AWS<Svc>` in [infrafactory](https://github.com/redscaresu/infrafactory)'s `internal/e2e/aws_services_test.go` so the cross-repo gate covers the scenario flow too.
