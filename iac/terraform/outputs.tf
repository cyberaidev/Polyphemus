# REFERENCE ONLY — root outputs.
output "documents_bucket" {
  description = "Name of the encrypted documents bucket."
  value       = module.documents.bucket_name
}

output "audit_bucket" {
  description = "Name of the audit evidence bucket."
  value       = module.audit.audit_bucket_name
}

output "vector_collection_endpoint" {
  description = "OpenSearch Serverless collection endpoint."
  value       = module.vector.collection_endpoint
}

output "user_pool_id" {
  description = "Cognito user pool id."
  value       = module.identity.user_pool_id
}

output "api_endpoint" {
  description = "HTTP API base URL."
  value       = module.api.api_endpoint
}

output "lambda_role_arn" {
  description = "Execution role ARN for the pipeline Lambda (scoped, least privilege)."
  value       = module.api.lambda_role_arn
}
