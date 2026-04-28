# Updates: a security group whose ingress rule shape is flipped between
# v1.tfvars (HTTPS-only) and v2.tfvars (HTTPS + SSH). Exercises
# AuthorizeSecurityGroupIngress + RevokeSecurityGroupIngress on the
# same SG without recreating it.

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
    ec2 = "http://127.0.0.1:8082/ec2/region/us-east-1"
  }
}

variable "open_ssh" {
  type        = bool
  description = "Whether to authorise SSH ingress alongside HTTPS"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "web" {
  name        = "web"
  description = "web tier"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group_rule" "https" {
  type              = "ingress"
  security_group_id = aws_security_group.web.id
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "ssh" {
  count             = var.open_ssh ? 1 : 0
  type              = "ingress"
  security_group_id = aws_security_group.web.id
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = ["10.0.0.0/8"]
}

output "sg_id" {
  value = aws_security_group.web.id
}
