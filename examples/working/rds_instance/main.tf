# Working: an RDS PostgreSQL instance backed by a DBSubnetGroup
# spanning 2 subnets in the same VPC. Exercises the load-bearing
# DBSubnetGroup ↔ EC2-subnets-in-same-VPC contract (S45-T0 pitfall).

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
    rds = "http://127.0.0.1:8082/rds/region/us-east-1"
  }
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_db_subnet_group" "default" {
  name       = "fakeaws-default"
  subnet_ids = [aws_subnet.a.id, aws_subnet.b.id]
}

resource "aws_db_parameter_group" "pg15" {
  name   = "fakeaws-pg15"
  family = "postgres15"
}

resource "aws_db_instance" "app" {
  identifier             = "fakeaws-app-db"
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "appuser"
  password               = "changeme"
  db_subnet_group_name   = aws_db_subnet_group.default.name
  parameter_group_name   = aws_db_parameter_group.pg15.name
  skip_final_snapshot    = true
  deletion_protection    = false
}

output "db_arn" {
  value = aws_db_instance.app.arn
}
