# Updates: a subnet whose map_public_ip_on_launch flips from false (v1)
# to true (v2). The provider sends ModifySubnetAttribute and waits for
# DescribeSubnets to echo the new value, so the flag must persist.

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

variable "map_public_ip_on_launch" {
  type        = bool
  description = "Give launches into the subnet a public IP. v1=false, v2=true."
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = var.map_public_ip_on_launch
}

output "subnet_id" {
  value = aws_subnet.public.id
}
