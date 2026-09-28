# Updates: provider default_tags plus a resource tag that changes from
# v1 to v2 on a VPC, subnet, internet gateway, route table, security
# group and instance. Create sends the tags as TagSpecification; the
# update sends CreateTags (and DeleteTags for the dropped tier tag) and
# plan reads them back from each Describe* tagSet, so both plans must
# be empty.

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
  default_tags {
    tags = {
      Project   = "fakeaws"
      ManagedBy = "tofu"
    }
  }
}

variable "tags" {
  type        = map(string)
  description = "Tags on every resource. v1 sets Stage=v1 and Tier=web; v2 sets Stage=v2 and drops Tier."
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags       = var.tags
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  tags              = var.tags
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = var.tags
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = var.tags
}

resource "aws_security_group" "web" {
  name        = "web"
  description = "web tier"
  vpc_id      = aws_vpc.main.id
  tags        = var.tags
}

resource "aws_instance" "web" {
  ami                    = "ami-0abcd1234" # canonical Amazon Linux 2 fixture
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]
  tags                   = var.tags
}

output "vpc_id" {
  value = aws_vpc.main.id
}
