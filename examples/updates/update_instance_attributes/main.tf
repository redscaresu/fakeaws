# Updates: an instance whose disable_api_termination, disable_api_stop,
# instance_initiated_shutdown_behavior and source_dest_check change
# from v1 to v2. v1 sets disable_api_termination at launch
# (RunInstances); v2 sends one ModifyInstanceAttribute per attribute.
# The provider reads each back from DescribeInstanceAttribute (and
# source_dest_check from DescribeInstances), so a value fakeaws does
# not store plans a diff. v2 allows termination so destroy succeeds,
# as it must on AWS.

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

variable "disable_api_termination" {
  type        = bool
  description = "Termination protection. v1=true, v2=false."
}

variable "disable_api_stop" {
  type        = bool
  description = "Stop protection. v1=false, v2=true."
}

variable "instance_initiated_shutdown_behavior" {
  type        = string
  description = "What an OS shutdown does. v1=stop, v2=terminate."
}

variable "source_dest_check" {
  type        = bool
  description = "Source/destination checking on the primary ENI. v1=true, v2=false."
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "app" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_security_group" "app" {
  name        = "instance-attributes"
  description = "instance attribute updates"
  vpc_id      = aws_vpc.main.id
}

resource "aws_instance" "app" {
  ami                                  = "ami-0abcd1234" # canonical Amazon Linux 2 fixture
  instance_type                        = "t3.micro"
  subnet_id                            = aws_subnet.app.id
  vpc_security_group_ids               = [aws_security_group.app.id]
  disable_api_termination              = var.disable_api_termination
  disable_api_stop                     = var.disable_api_stop
  instance_initiated_shutdown_behavior = var.instance_initiated_shutdown_behavior
  source_dest_check                    = var.source_dest_check
}

output "instance_id" {
  value = aws_instance.app.id
}
