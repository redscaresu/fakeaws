# Misconfigured: two aws_ssm_parameter resources claim the same name.
# Neither sets overwrite, so each create is PutParameter Overwrite=false;
# whichever lands second is refused with ParameterAlreadyExists (400),
# as real SSM does, instead of silently clobbering the first.

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

resource "aws_ssm_parameter" "primary" {
  name  = "/fakeaws/app/log-level"
  type  = "String"
  value = "info"
}

resource "aws_ssm_parameter" "copy" {
  name  = "/fakeaws/app/log-level"
  type  = "String"
  value = "debug"
}
