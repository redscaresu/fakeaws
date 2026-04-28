# Misconfigured: aws_db_instance references a db_subnet_group_name
# that doesn't exist. fakeaws's repository.CreateDBInstance walks
# the subnet group FK first; missing surface as
# DBSubnetGroupNotFoundFault (S45-T0 pitfall).

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
    rds = "http://127.0.0.1:8082/rds/region/us-east-1"
  }
}

# Reference a subnet group that doesn't exist — RunInstances must
# reject this with 404.
resource "aws_db_instance" "broken" {
  identifier           = "fakeaws-broken"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "appuser"
  password             = "changeme"
  db_subnet_group_name = "this-subnet-group-does-not-exist"
  skip_final_snapshot  = true
}
