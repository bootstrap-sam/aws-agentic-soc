terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Every service points at Floci. Any credentials work: these are emulator placeholders.
# From the host: http://localhost:4566 (default). From the compose `terraform` service: http://floci:4566.
variable "aws_endpoint" {
  type    = string
  default = "http://localhost:4566"
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    ec2   = var.aws_endpoint
    elbv2 = var.aws_endpoint
    wafv2 = var.aws_endpoint
    iam   = var.aws_endpoint
    sts   = var.aws_endpoint
  }
}
