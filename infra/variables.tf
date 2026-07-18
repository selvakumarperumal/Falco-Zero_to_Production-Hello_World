variable "aws_region" {
  description = "AWS Region to deploy resources - Hyderabad, India"
  type        = string
  default     = "ap-south-2"
}

variable "project_name" {
  description = "Name of the Project"
  type        = string
  default     = "falco-zerotoprod"
}

variable "vpc" {
  description = "VPC Configuration"
  type = object({
    vpc_cidr_block      = string
    private_subnet_cidr = list(string)
    public_subnet_cidr  = list(string)
  })
  default = {
    vpc_cidr_block      = "10.0.0.0/16"
    private_subnet_cidr = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
    public_subnet_cidr  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
  }
}

variable "kubernetes_version" {
  description = "Kubernetes version for EKS Cluster"
  type        = string
  default     = "1.36"
}

variable "eks_managed_node_groups" {
  description = "EKS Managed Node Groups"
  type = object({
    default = object({
      instance_types = list(string)
      min_size       = number
      max_size       = number
      desired_size   = number
    })
  })
  default = {
    default = {
      instance_types = ["t3.medium"]
      min_size       = 2
      max_size       = 3
      desired_size   = 2
    }
  }
}

variable "arcocd_chart_version" {
  description = "ArgoCD Chart Version"
  type        = string
  default     = "10.1.3"
}
