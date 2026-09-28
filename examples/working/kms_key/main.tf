# Working: a KMS key with a description, which DescribeKey must echo
# back so the second plan shows no drift.

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
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    kms = "http://127.0.0.1:8082/kms/region/us-east-1"
  }
}

resource "aws_kms_key" "app" {
  description             = "fakeaws example key"
  deletion_window_in_days = 7
}
