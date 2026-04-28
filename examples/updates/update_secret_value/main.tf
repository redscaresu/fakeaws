# Updates: Secrets Manager secret whose value flips between v1 and v2.
# Exercises PutSecretValue + AWSCURRENT/AWSPREVIOUS stage label
# rotation.

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

variable "secret_value" {
  type        = string
  description = "Secret value flipped between v1 and v2."
}

resource "aws_secretsmanager_secret" "app" {
  name                    = "fakeaws-update-secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id     = aws_secretsmanager_secret.app.id
  secret_string = var.secret_value
}

output "secret_arn" {
  value = aws_secretsmanager_secret.app.arn
}
