# Misconfigured: aws_instance references a subnet that doesn't exist.
# fakeaws's repository.CreateInstance validates the subnet via
# repository.GetSubnet first; a missing subnet surfaces as
# ResourceNotFoundException (404), which the AWS provider translates
# into a "tofu apply" failure containing the AWS error code.

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
    ec2 = "http://127.0.0.1:8082/ec2/region/us-east-1"
  }
}

# No aws_subnet resource — referenced subnet id is a literal that does
# not exist in fakeaws. RunInstances must reject this with 404.
resource "aws_instance" "broken" {
  ami           = "ami-0abcd1234"
  instance_type = "t3.micro"
  subnet_id     = "subnet-this-does-not-exist"
}
