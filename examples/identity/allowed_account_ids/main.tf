# Identity: a fakeaws started with -account 123456789012 configures a
# provider that allows only that account. Outside the auto-discovered
# trees on purpose: those share one :8082 fakeaws at the default account.
# examples/identity_test.go starts its own fakeaws on a free port and
# points AWS_ENDPOINT_URL_<SVC> at it; there is no endpoints block.
#
# Against a fakeaws started without -account, the provider refuses to
# configure: "AWS account ID not allowed: 000000000000".

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
  allowed_account_ids = ["123456789012"]
}

data "aws_caller_identity" "current" {}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == "123456789012"
      error_message = "STS GetCallerIdentity answered another account."
    }
  }
}
