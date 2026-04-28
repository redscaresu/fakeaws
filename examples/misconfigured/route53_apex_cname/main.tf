# Misconfigured: aws_route53_record with type=CNAME at the zone apex
# (the bare zone name). AWS rejects this because CNAME at apex
# conflicts with the zone's NS/SOA records — use ALIAS for apex
# instead. Per S47-T0 pitfall.

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
  name = "broken.example.invalid."
}

# CNAME at the apex — fakeaws rejects with InvalidChangeBatch (409).
resource "aws_route53_record" "apex_cname" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "broken.example.invalid."
  type    = "CNAME"
  ttl     = 300
  records = ["target.example.com."]
}
