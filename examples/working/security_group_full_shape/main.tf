# Working: a security group carrying the whole ip_permissions shape —
# IPv4 + IPv6 ingress, an SG-to-SG rule and allow-all egress. The
# post-apply plan is empty only if DescribeSecurityGroups echoes every
# source kind back (handlers/ec2.go).

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

resource "aws_security_group" "lb" {
  name        = "lb"
  description = "load balancer"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group" "web" {
  name        = "web"
  description = "web tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "ssh from anywhere"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    description     = "https from the load balancer"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
