############################
# PROVIDER & DATA
############################
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Environment = var.environment
      Service     = "TrailAlerts"
      ManagedBy   = "Terraform"
    }
  }
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket  = "trailalert-terraform-state"
    key     = "terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}

data "aws_caller_identity" "current" {}

# Only load the existing CloudTrail bucket data if create_cloudtrail = false
data "aws_s3_bucket" "existing_cloudtrail_logs" {
  count  = var.create_cloudtrail ? 0 : 1
  bucket = var.existing_cloudtrail_bucket_name
}

############################
# LOCALS
############################
locals {
  # Make sure these paths exist on your local system
  layer_zip_path    = "../lambdas/layer/layer.zip"
  layer_name        = "trailalerts-detection-layer"
  requirements_path = "../lambdas/layer/requirements.txt"

  # If create_cloudtrail = true, use the new bucket, else the existing
  cloudtrail_bucket_id  = var.create_cloudtrail ? aws_s3_bucket.cloudtrail_logs[0].id : data.aws_s3_bucket.existing_cloudtrail_logs[0].id
  cloudtrail_bucket_arn = var.create_cloudtrail ? aws_s3_bucket.cloudtrail_logs[0].arn : data.aws_s3_bucket.existing_cloudtrail_logs[0].arn
}
