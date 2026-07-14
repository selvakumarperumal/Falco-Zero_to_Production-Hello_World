variable "aws_region" {
  type        = string
  description = "Hyderabad"
  default     = "ap-south-2"
}

variable "bucket_name_prefix" {
  type        = string
  description = "S3 Bucket Name Prefix"
  default     = "falco-tfstate-001"
}
