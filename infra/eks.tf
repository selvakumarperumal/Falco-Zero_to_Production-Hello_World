module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = ">= 21.0"

  name               = local.cluster_name
  kubernetes_version = var.kubernetes_version

  # Cluster Networking
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Cluster Access
  endpoint_public_access                   = true
  enable_cluster_creator_admin_permissions = true

  create_cloudwatch_log_group = false

  # EKS Addons
  addons = {
    coredns = {
      most_recent = true
    }
    eks-pod-identity-agent = {
      most_recent    = true
      before_compute = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent    = true
      before_compute = true
    }
  }

  # EKS Managed Node Group(s)
  eks_managed_node_groups = {
    default = {
      instance_types = var.eks_managed_node_groups.default.instance_types
      min_size       = var.eks_managed_node_groups.default.min_size
      max_size       = var.eks_managed_node_groups.default.max_size
      desired_size   = var.eks_managed_node_groups.default.desired_size
    }
  }
}
