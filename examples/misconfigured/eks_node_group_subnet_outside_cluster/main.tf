# Misconfigured: aws_eks_node_group references a subnet that's NOT
# in the cluster's vpc_config.subnet_ids. Per S46-T0 pitfall:
# "subnet does not belong to cluster VPC" — fakeaws rejects with 409.

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
    iam = "http://127.0.0.1:8082/iam"
    ec2 = "http://127.0.0.1:8082/ec2/region/us-east-1"
    eks = "http://127.0.0.1:8082/eks/region/us-east-1"
  }
}

resource "aws_iam_role" "cluster" {
  name = "misconfigured-eks-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Service = "eks.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "node" {
  name = "misconfigured-eks-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }

resource "aws_subnet" "a" {
  vpc_id = aws_vpc.main.id; cidr_block = "10.0.1.0/24"; availability_zone = "us-east-1a"
}

resource "aws_subnet" "outside" {
  vpc_id = aws_vpc.main.id; cidr_block = "10.0.2.0/24"; availability_zone = "us-east-1b"
}

# Cluster only has subnet "a".
resource "aws_eks_cluster" "demo" {
  name     = "misconfigured-demo"
  role_arn = aws_iam_role.cluster.arn
  vpc_config {
    subnet_ids = [aws_subnet.a.id]
  }
}

# Nodegroup uses subnet "outside" — not in cluster.
resource "aws_eks_node_group" "broken" {
  cluster_name    = aws_eks_cluster.demo.name
  node_group_name = "broken"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = [aws_subnet.outside.id]
  scaling_config { desired_size = 1; min_size = 1; max_size = 2 }
}
