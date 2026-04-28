# Working: a DynamoDB table with PAY_PER_REQUEST billing and a
# single hash key. GSI/LSI explicitly out of scope at v1 per
# fakeaws/concepts.md.

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
    dynamodb = "http://127.0.0.1:8082/dynamodb/region/us-east-1"
  }
}

resource "aws_dynamodb_table" "users" {
  name         = "fakeaws-users"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

output "table_arn" {
  value = aws_dynamodb_table.users.arn
}
