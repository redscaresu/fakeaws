# Working: a standard SQS queue with default attributes.

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
    sqs = "http://127.0.0.1:8082/sqs/region/us-east-1"
  }
}

resource "aws_sqs_queue" "jobs" {
  name = "fakeaws-jobs"
}

output "queue_url" {
  value = aws_sqs_queue.jobs.url
}
