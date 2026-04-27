terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
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
    iam = "http://127.0.0.1:8082/iam"
  }
}

variable "description" {
  type        = string
  description = "Role description — flipped between v1 and v2 to exercise UpdateRole"
}

resource "aws_iam_role" "app" {
  name = "fakeaws-update-example-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  description = var.description
}

output "role_arn" {
  value = aws_iam_role.app.arn
}

output "description" {
  value = aws_iam_role.app.description
}
