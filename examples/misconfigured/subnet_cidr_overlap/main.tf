# Misconfigured: two aws_subnet resources in one VPC whose CIDRs
# overlap (10.0.1.128/25 lies inside 10.0.1.0/24). Whichever create
# lands second is refused with InvalidSubnet.Conflict (400), as real
# EC2 does. Fix: give each subnet a disjoint block, e.g. 10.0.2.0/24.

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

resource "aws_subnet" "wide" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_subnet" "inside" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.128/25"
}
