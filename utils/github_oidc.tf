provider "aws" {
  region = "us-east-1"
}

module "github-oidc" {
  source  = "github.com/terraform-module/terraform-aws-github-oidc-provider?ref=8ca02cd8c2264d1302cad85683411543d2f01bea" # v2.2.1

  role_name            = "TrailAlertsGitHubActionsRole"
  create_oidc_provider = true
  create_oidc_role     = true

  repositories              = ["adanalvarez/trailalerts-alpha"] # Change this to your GitHub repository
  oidc_role_attach_policies = ["arn:aws:iam::aws:policy/AdministratorAccess"] # Change this to the policies you want to attach
}