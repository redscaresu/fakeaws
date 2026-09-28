# Working: endpoints from the environment only. There is no endpoints
# block; the harness's smokeEnv (examples/smoke_env_test.go) sets
# AWS_ENDPOINT_URL_EC2. Run by hand outside the harness, this reaches
# real AWS with fake keys and fails to authenticate.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "fake"
  secret_key                  = "fake"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
