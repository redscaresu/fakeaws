# Misconfigured: AttachRolePolicy references a role that doesn't exist.
# fakeaws's repository.AttachRolePolicy validates BOTH the role and the
# policy via repository.GetRole + a SQL count on iam_policies. A missing
# role surfaces as ResourceNotFoundException (404), which the AWS
# provider translates into a "tofu apply" failure containing
# "ResourceNotFoundException".

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
  }
}

# Create the policy but NOT the role…
resource "aws_iam_policy" "p" {
  name        = "fakeaws-misconfig-policy"
  description = "Misconfigured-example policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# …then attempt to attach it to a role that doesn't exist.
# Expected error: ResourceNotFoundException (the role lookup fails
# before fakeaws even checks the policy).
resource "aws_iam_role_policy_attachment" "broken" {
  role       = "this-role-does-not-exist"
  policy_arn = aws_iam_policy.p.arn
}
