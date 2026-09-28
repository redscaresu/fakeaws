# Working: endpoints from the environment only. There is no endpoints
# block; the harness's smokeEnv (examples/smoke_env_test.go) sets
# AWS_ENDPOINT_URL_EC2 and AWS_ENDPOINT_URL_STS. Run by hand outside the
# harness, this reaches real AWS with fake keys and fails to authenticate.
#
# No skip_* flags: the provider validates credentials with STS
# GetCallerIdentity. allowed_account_ids checks the account in its Arn
# and the precondition checks its Account, so the apply fails if fakeaws
# answers any account but 000000000000 in either field.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}

provider "aws" {
  region              = "us-east-1"
  access_key          = "fake"
  secret_key          = "fake"
  allowed_account_ids = ["000000000000"]
}

data "aws_caller_identity" "current" {}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == "000000000000"
      error_message = "STS GetCallerIdentity answered another account."
    }
  }
}
