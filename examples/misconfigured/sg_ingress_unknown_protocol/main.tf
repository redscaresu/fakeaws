# Misconfigured: an ingress rule with protocol "bogus". The provider
# forwards protocols it does not know unchanged, so
# AuthorizeSecurityGroupIngress refuses it with InvalidParameterValue, as
# real EC2 does.

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
    ec2 = "http://127.0.0.1:8082/ec2/region/us-east-1"
  }
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "broken" {
  name        = "broken"
  description = "broken ingress"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "bogus"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
