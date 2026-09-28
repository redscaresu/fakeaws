# Working: an instance with associate_public_ip_address = true. The
# provider launches it through NetworkInterface.1.* (no top-level
# SubnetId) and reads associate_public_ip_address back as "the primary
# ENI has an association"; the attribute is ForceNew, so the post-apply
# plan is empty only if DescribeInstances returns that ENI with its
# public IP. user_data reads back from DescribeInstanceAttribute.

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

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_security_group" "web" {
  name        = "web"
  description = "web tier"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group" "ssh" {
  name        = "ssh"
  description = "ssh access"
  vpc_id      = aws_vpc.main.id
}

resource "aws_instance" "web" {
  ami                         = "ami-0abcd1234" # canonical Amazon Linux 2 fixture
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id, aws_security_group.ssh.id]
  associate_public_ip_address = true
  user_data                   = "#!/bin/bash\necho hello\n"
}

output "public_ip" {
  value = aws_instance.web.public_ip
}

output "private_ip" {
  value = aws_instance.web.private_ip
}
