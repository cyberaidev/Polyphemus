variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}

variable "documents_bucket_arn" {
  description = "ARN of the documents bucket (read access)."
  type        = string
}

variable "audit_bucket_arn" {
  description = "ARN of the audit bucket (write access)."
  type        = string
}

variable "bedrock_policy_arn" {
  description = "Scoped Bedrock invoke policy ARN to attach to the role."
  type        = string
}

variable "user_pool_id" {
  description = "Cognito user pool id."
  type        = string
}

variable "user_pool_client_id" {
  description = "Cognito app client id (JWT audience)."
  type        = string
}

variable "user_pool_endpoint" {
  description = "Cognito issuer endpoint (JWT issuer)."
  type        = string
}

variable "lambda_package_path" {
  description = "Path to the Lambda deployment package (reference-only placeholder)."
  type        = string
  default     = "build/pipeline.zip"
}
