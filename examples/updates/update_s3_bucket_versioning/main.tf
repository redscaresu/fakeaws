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
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    s3 = "http://127.0.0.1:8082/s3"
  }
}

variable "versioning_status" {
  type        = string
  description = "Status flipped between v1 (Enabled) and v2 (Suspended) to exercise PutBucketVersioning"
  validation {
    condition     = contains(["Enabled", "Suspended"], var.versioning_status)
    error_message = "versioning_status must be 'Enabled' or 'Suspended'."
  }
}

resource "aws_s3_bucket" "example" {
  bucket        = "fakeaws-update-example-bucket"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = var.versioning_status
  }
}
