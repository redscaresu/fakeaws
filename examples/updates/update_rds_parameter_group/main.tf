# Updates: an RDS instance whose parameter_group_name flips between
# v1.tfvars (postgres15-default) and v2.tfvars (postgres15-tuned).
# Exercises CreateDBParameterGroup + ModifyDBInstance without
# recreating the instance.

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

variable "parameter_group" {
  type        = string
  description = "Parameter group name flipped between v1 (default) and v2 (tuned) to exercise ModifyDBInstance."
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
  name       = "fakeaws-update-default"
  subnet_ids = [aws_subnet.a.id, aws_subnet.b.id]
}

resource "aws_db_parameter_group" "default" {
  name   = "fakeaws-update-pg15-default"
  family = "postgres15"
}

resource "aws_db_parameter_group" "tuned" {
  name   = "fakeaws-update-pg15-tuned"
  family = "postgres15"
}

resource "aws_db_instance" "app" {
  identifier           = "fakeaws-update-app"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "appuser"
  password             = "changeme"
  db_subnet_group_name = aws_db_subnet_group.default.name
  parameter_group_name = var.parameter_group
  skip_final_snapshot  = true
  deletion_protection  = false
}

output "db_id" {
  value = aws_db_instance.app.id
}
