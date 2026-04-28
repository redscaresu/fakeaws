# Working: Secrets Manager secret + initial version. Sets
# recovery_window_in_days = 0 so destroy is immediate (S47-T0 pitfall).

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
    secretsmanager = "http://127.0.0.1:8082/secretsmanager/region/us-east-1"
  }
}

resource "aws_secretsmanager_secret" "db" {
  name                    = "fakeaws-db-creds"
  description             = "fakeaws example database credentials"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({ username = "admin", password = "changeme" })
}

output "secret_arn" {
  value = aws_secretsmanager_secret.db.arn
}
