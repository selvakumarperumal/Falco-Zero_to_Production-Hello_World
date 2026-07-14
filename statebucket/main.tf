terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }

    local = {
      source  = "hashicorp/local"
      version = ">= 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}


module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "5.14.1"

  bucket = "${var.bucket_name_prefix}-${var.aws_region}-${data.aws_caller_identity.current.account_id}"
  acl    = "private"

  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  versioning = {
    enabled = true
  }
}

resource "local_file" "infra_config" {
  content  = <<EOT
bucket     = "${module.s3_bucket.s3_bucket_id}"
key        = "infra/terraform.tfstate"
region     = "${var.aws_region}"
use_lockfile = true
EOT
  filename = "${path.module}/../infra/backend.hcl"
}
