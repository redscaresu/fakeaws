# Working: a String and a tagged SecureString parameter, plus a read of
# the AWS public parameter for the latest Amazon Linux 2023 AMI, which
# fakeaws resolves to its AL2023 AMI fixture.

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
    ssm = "http://127.0.0.1:8082/ssm/region/us-east-1"
  }
}

resource "aws_ssm_parameter" "endpoint" {
  name        = "/fakeaws/app/endpoint"
  type        = "String"
  value       = "https://app.example.internal"
  description = "fakeaws example endpoint"
}

resource "aws_ssm_parameter" "password" {
  name  = "/fakeaws/app/db-password"
  type  = "SecureString"
  value = "changeme"
  tags = {
    env = "example"
  }
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

  lifecycle {
    postcondition {
      condition     = startswith(self.insecure_value, "ami-")
      error_message = "The AL2023 public parameter must resolve to an AMI id."
    }
  }
}

output "al2023_ami" {
  value = data.aws_ssm_parameter.al2023.insecure_value
}
