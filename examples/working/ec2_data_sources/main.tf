# Working: the EC2 data sources read what fakeaws stores. Two VPCs with
# different Name tags hold a same-named security group each. The reads
# of the VPC (by tag) and the SG (by name and vpc_id) reference the
# created resources, so the first apply defers them; the AMI (owner
# amazon, AL2023 name, most_recent) and AZ (state available) reads
# resolve against the fixtures. Each read's postcondition fails the
# apply unless it resolves to the one thing it should: a tag filter
# fakeaws ignored would match both VPCs, a vpc-id filter it ignored
# both SGs.

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

resource "aws_vpc" "picked" {
  cidr_block = "10.60.0.0/16"
  tags = {
    Name = "data-sources-picked"
  }
}

resource "aws_vpc" "other" {
  cidr_block = "10.61.0.0/16"
  tags = {
    Name = "data-sources-other"
  }
}

resource "aws_security_group" "picked" {
  name        = "data-sources-app"
  description = "same name in both VPCs"
  vpc_id      = aws_vpc.picked.id
}

resource "aws_security_group" "other" {
  name        = "data-sources-app"
  description = "same name in both VPCs"
  vpc_id      = aws_vpc.other.id
}

data "aws_vpc" "by_tag" {
  tags = {
    Name = aws_vpc.picked.tags["Name"]
  }

  lifecycle {
    postcondition {
      condition     = self.id == aws_vpc.picked.id
      error_message = "data.aws_vpc by tag did not resolve to the tagged VPC."
    }
  }
}

data "aws_security_group" "by_name" {
  name   = aws_security_group.picked.name
  vpc_id = data.aws_vpc.by_tag.id

  lifecycle {
    postcondition {
      condition     = self.id == aws_security_group.picked.id
      error_message = "data.aws_security_group by name and vpc_id did not resolve to the SG in that VPC."
    }
  }
}

data "aws_ami" "al2023" {
  owners      = ["amazon"]
  most_recent = true

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  lifecycle {
    postcondition {
      condition     = self.id == "ami-0al2023x8664"
      error_message = "data.aws_ami did not resolve to the AL2023 fixture."
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"

  lifecycle {
    postcondition {
      condition     = length(self.names) == 3
      error_message = "data.aws_availability_zones did not answer three zone names."
    }
  }
}

resource "aws_subnet" "first_az" {
  vpc_id            = data.aws_vpc.by_tag.id
  cidr_block        = "10.60.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
}
