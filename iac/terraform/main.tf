# REFERENCE ONLY — wires the Polyphemus modules together.
#
# This root module composes the six building blocks into one coherent stack that
# mirrors docs/ARCHITECTURE.md. It is illustrative; review before any apply.

locals {
  name_prefix = var.name_prefix
}

module "documents" {
  source      = "./modules/s3_documents"
  name_prefix = local.name_prefix
}

module "audit" {
  source             = "./modules/audit"
  name_prefix        = local.name_prefix
  log_retention_days = var.log_retention_days
}

module "vector" {
  source      = "./modules/opensearch_serverless"
  name_prefix = local.name_prefix
}

module "identity" {
  source         = "./modules/cognito"
  name_prefix    = local.name_prefix
  allowed_groups = var.allowed_groups
}

module "bedrock" {
  source                 = "./modules/bedrock"
  name_prefix            = local.name_prefix
  bedrock_text_model_id  = var.bedrock_text_model_id
  bedrock_embed_model_id = var.bedrock_embed_model_id
}

module "api" {
  source               = "./modules/lambda_api"
  name_prefix          = local.name_prefix
  region               = var.region
  documents_bucket_arn = module.documents.bucket_arn
  audit_bucket_arn     = module.audit.audit_bucket_arn
  bedrock_policy_arn   = module.bedrock.invoke_policy_arn
  user_pool_id         = module.identity.user_pool_id
  user_pool_client_id  = module.identity.user_pool_client_id
  user_pool_endpoint   = module.identity.user_pool_endpoint
}
