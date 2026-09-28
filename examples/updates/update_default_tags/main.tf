# Updates: an Aurora cluster, its cluster parameter group and an EIP,
# tagged by the resource and by the provider's default_tags. v1 → v2
# changes a resource tag and a default_tags value, so each resource's
# tags and tags_all must follow both.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}

variable "tags" {
  type        = map(string)
  description = "Tags on every resource. v2 changes Stage."
}

variable "default_tags" {
  type        = map(string)
  description = "The provider's default_tags. v2 changes the run id."
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
  default_tags {
    tags = var.default_tags
  }
}

resource "aws_rds_cluster_parameter_group" "tagged" {
  name   = "fakeaws-tagged"
  family = "aurora-postgresql15"
  tags   = var.tags
}

resource "aws_rds_cluster" "tagged" {
  cluster_identifier              = "fakeaws-tagged"
  engine                          = "aurora-postgresql"
  engine_version                  = "15.4"
  master_username                 = "appuser"
  master_password                 = "changeme"
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.tagged.name
  port                            = 5433
  backup_retention_period         = 7
  preferred_backup_window         = "03:00-04:00"
  skip_final_snapshot             = true
  tags                            = var.tags
}

resource "aws_eip" "tagged" {
  domain = "vpc"
  tags   = var.tags
}
