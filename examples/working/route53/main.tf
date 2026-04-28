# Working: Route53 hosted zone + an A-record under www.

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
    route53 = "http://127.0.0.1:8082/route53"
  }
}

resource "aws_route53_zone" "main" {
  name = "test.example.invalid."
  comment = "fakeaws example zone"
}

resource "aws_route53_record" "www" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "www.test.example.invalid."
  type    = "A"
  ttl     = 300
  records = ["192.0.2.1"]
}

output "zone_id" {
  value = aws_route53_zone.main.zone_id
}
