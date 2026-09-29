# Updates: one tagged resource per ARN-addressed service (SQS, IAM,
# RDS, Route53, DynamoDB, EKS), a Secrets Manager secret, an IAM
# instance profile, an EKS node group and addon, and an EC2 key pair. v1 → v2 changes a tag's value, removes
# one and adds one with no value, so each service's tag and untag calls
# run through the provider's own tag diffing.

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
    dynamodb       = "http://127.0.0.1:8082/dynamodb/region/us-east-1"
    ec2            = "http://127.0.0.1:8082/ec2/region/us-east-1"
    eks            = "http://127.0.0.1:8082/eks/region/us-east-1"
    iam            = "http://127.0.0.1:8082/iam"
    rds            = "http://127.0.0.1:8082/rds/region/us-east-1"
    route53        = "http://127.0.0.1:8082/route53"
    secretsmanager = "http://127.0.0.1:8082/secretsmanager/region/us-east-1"
    sqs            = "http://127.0.0.1:8082/sqs/region/us-east-1"
  }
  default_tags {
    tags = {
      "infrafactory:run-id" = "run-0001"
      "infrafactory/owner"  = "fakeaws"
    }
  }
}

variable "tags" {
  type        = map(string)
  description = "Tags on every resource. v2 changes Stage, drops the kubernetes.io key and adds an empty-valued one."
}

resource "aws_sqs_queue" "tagged" {
  name = "fakeaws-update-tagged"
  tags = var.tags
}

resource "aws_iam_role" "tagged" {
  name = "fakeaws-update-tagged"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_db_parameter_group" "tagged" {
  name   = "fakeaws-update-tagged"
  family = "postgres15"
  tags   = var.tags
}

resource "aws_route53_zone" "tagged" {
  name = "update-tagged.fakeaws.test"
  tags = var.tags
}

resource "aws_dynamodb_table" "tagged" {
  name         = "fakeaws-update-tagged"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  tags = var.tags
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
  name     = "fakeaws-update-tagged"
  role_arn = aws_iam_role.tagged.arn
  version  = "1.29"
  vpc_config {
    subnet_ids = [aws_subnet.a.id, aws_subnet.b.id]
  }
  tags = var.tags
}

resource "aws_secretsmanager_secret" "tagged" {
  name                    = "fakeaws-update-tagged"
  recovery_window_in_days = 0
  tags                    = var.tags
}

resource "aws_iam_instance_profile" "tagged" {
  name = "fakeaws-update-tagged"
  role = aws_iam_role.tagged.name
  tags = var.tags
}

resource "aws_eks_node_group" "tagged" {
  cluster_name    = aws_eks_cluster.tagged.name
  node_group_name = "fakeaws-update-tagged"
  node_role_arn   = aws_iam_role.tagged.arn
  subnet_ids      = [aws_subnet.a.id, aws_subnet.b.id]
  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }
  tags = var.tags
}

resource "aws_eks_addon" "tagged" {
  cluster_name = aws_eks_cluster.tagged.name
  addon_name   = "vpc-cni"
  tags         = var.tags
}

resource "aws_key_pair" "tagged" {
  key_name   = "fakeaws-update-tagged"
  public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForFakeawsExamples"
  tags       = var.tags
}
