# Updates: a KMS key whose description flips between v1 and v2.
# Exercises UpdateKeyDescription and the provider's DescribeKey wait.

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

variable "description" {
  type        = string
  description = "Key description flipped between v1 and v2."
}

resource "aws_kms_key" "app" {
  description             = var.description
  deletion_window_in_days = 7
}
