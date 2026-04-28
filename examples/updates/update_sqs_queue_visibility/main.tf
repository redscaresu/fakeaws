# Updates: an SQS queue whose visibility_timeout_seconds flips
# between v1 (30s default) and v2 (600s, longer for batch jobs).
# Exercises SetQueueAttributes (a no-op at v1 for fakeaws but the
# AWS provider still calls it on plan-detected drift).

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

variable "visibility_timeout" {
  type        = number
  description = "Queue visibility timeout in seconds. v1=30, v2=600."
}

resource "aws_sqs_queue" "jobs" {
  name                       = "fakeaws-update-jobs"
  visibility_timeout_seconds = var.visibility_timeout
}

output "queue_url" {
  value = aws_sqs_queue.jobs.url
}
