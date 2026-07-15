module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.6.1"

  name = "${var.project_name}-vpc"
  cidr = var.vpc.vpc_cidr_block

  azs             = ["ap-south-2a", "ap-south-2b", "ap-south-2c"]
  private_subnets = var.vpc.private_subnet_cidr
  public_subnets  = var.vpc.public_subnet_cidr

  enable_nat_gateway = true
  single_nat_gateway = true

  create_igw = true

  enable_dns_support   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${var.project_name}-eks" = "shared"
    "kubernetes.io/role/elb"                        = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${var.project_name}-eks" = "shared"
    "kubernetes.io/role/internal-elb"               = "1"
  }
}
