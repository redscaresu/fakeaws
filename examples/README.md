# fakeaws examples

Three trees, each driven by `provider_smoke_test.go`'s auto-discovery
loop:

- `working/<service>/` — `terraform apply → terraform plan -detailed-exitcode → terraform destroy` clean against fakeaws.
- `misconfigured/<service>/` — `terraform apply` MUST fail with the documented AWS error code (asserted by grep on the tofu output).
- `updates/<service>/` — `terraform apply -var-file=v1.tfvars → plan no-op → terraform apply -var-file=v2.tfvars → plan no-op → terraform destroy` clean.

Adding a directory to ANY of the three trees automatically registers it for the smoke gate — no per-example test ticket. Each subdirectory is its own test sub-run.

## Provider version pin

All examples use `hashicorp/aws ~> 5.70` per concepts.md "Resolved decisions" item 14. Bumps require an explicit PR updating every `required_providers` block + the prompts + the e2e harness.

## Endpoint override

Examples target fakeaws via the provider's `endpoints` block:

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
    iam = "http://127.0.0.1:8082/iam"
    s3  = "http://127.0.0.1:8082/s3"
  }
}
```

## Misconfigured exemptions

S3 has no v1 cross-resource FK refs (bucket policy ref strings are
inert at v1; no S3-to-IAM dependency we model). The `misconfigured/`
tree therefore contains only IAM examples at S43.

| service | misconfigured exemption | reason |
|---------|------------------------|--------|
| s3      | yes                    | no v1 cross-resource FK refs to violate (bucket policy refs are inert strings; FK gates land if/when ACL→IAM routing is modelled) |
