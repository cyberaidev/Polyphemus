# REFERENCE ONLY — root input variables.
variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to all resource names."
  type        = string
  default     = "polyphemus"
}

variable "bedrock_text_model_id" {
  description = "Bedrock text model id used for generation."
  type        = string
  default     = "anthropic.claude-3-5-sonnet-20240620-v1:0"
}

variable "bedrock_embed_model_id" {
  description = "Bedrock embedding model id."
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

variable "allowed_groups" {
  description = "IdP groups provisioned in the Cognito user pool."
  type        = list(string)
  default     = ["finance", "hr", "admin", "staff"]
}

variable "log_retention_days" {
  description = "CloudWatch audit log retention in days."
  type        = number
  default     = 365
}
