# Working: provider-level default_tags plus one tagged resource per
# ARN-addressed service (SQS, IAM, RDS, Route53, DynamoDB, EKS). The
# plan after apply is a no-op only if every service hands back exactly
# the tags it was given, including a tag with no value and keys with
# ':' and '/'.

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
    dynamodb = "http://127.0.0.1:8082/dynamodb/region/us-east-1"
    ec2      = "http://127.0.0.1:8082/ec2/region/us-east-1"
    eks      = "http://127.0.0.1:8082/eks/region/us-east-1"
    iam      = "http://127.0.0.1:8082/iam"
    rds      = "http://127.0.0.1:8082/rds/region/us-east-1"
    route53  = "http://127.0.0.1:8082/route53"
    sqs      = "http://127.0.0.1:8082/sqs/region/us-east-1"
  }
  default_tags {
    tags = {
      "infrafactory:run-id" = "run-0001"
      "infrafactory/owner"  = "fakeaws"
    }
  }
}

locals {
  tags = {
    "kubernetes.io/cluster:demo" = "owned"
    "empty"                      = ""
  }
}

resource "aws_sqs_queue" "tagged" {
  name = "fakeaws-tagged"
  tags = local.tags
}

resource "aws_iam_role" "tagged" {
  name = "fakeaws-tagged"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_db_parameter_group" "tagged" {
  name   = "fakeaws-tagged"
  family = "postgres15"
  tags   = local.tags
}

resource "aws_route53_zone" "tagged" {
  name = "tagged.fakeaws.test"
  tags = local.tags
}

resource "aws_dynamodb_table" "tagged" {
  name         = "fakeaws-tagged"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  tags = local.tags
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

resource "aws_eks_cluster" "tagged" {
  name     = "fakeaws-tagged"
  role_arn = aws_iam_role.tagged.arn
  version  = "1.29"
  vpc_config {
    subnet_ids = [aws_subnet.a.id, aws_subnet.b.id]
  }
  tags = local.tags
}
