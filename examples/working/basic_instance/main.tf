# Working: VPC + subnet + SG + EC2 instance running the canonical
# Amazon Linux 2 AMI fixture. Exercises the SubnetId/SecurityGroupId
# VPC-pairing contract (both must live in the same VPC) — fakeaws
# rejects mismatched pairs with 404.

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

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "app" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_security_group" "app" {
  name        = "app"
  description = "app tier"
  vpc_id      = aws_vpc.main.id
}

resource "aws_instance" "app" {
  ami                    = "ami-0abcd1234" # canonical Amazon Linux 2 fixture
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.app.id
  vpc_security_group_ids = [aws_security_group.app.id]
}

output "instance_id" {
  value = aws_instance.app.id
}
