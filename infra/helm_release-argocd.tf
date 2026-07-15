resource "helm_release" "argocd" {
  name             = "argocd"
  namespace        = "argocd"
  create_namespace = true
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  version          = var.arcocd_chart_version

  cleanup_on_fail = true
  replace         = true
  force_update    = true
  timeout         = 600
  wait            = false

  depends_on = [module.eks]
}
