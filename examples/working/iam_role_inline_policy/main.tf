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
    iam = "http://127.0.0.1:8082/iam"
  }
}

resource "aws_iam_role" "app" {
  name = "fakeaws-example-inline-policy-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# The plan after apply stays empty only if GetRolePolicy reads back the
# document PutRolePolicy stored. Destroy deletes the policy before the
# role, which DeleteRole would refuse with DeleteConflict.
resource "aws_iam_role_policy" "read_logs" {
  name = "fakeaws-example-inline-read-logs"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:GetLogEvents", "logs:DescribeLogStreams"]
      Resource = "arn:aws:logs:us-east-1:000000000000:log-group:/app/*"
    }]
  })
}
