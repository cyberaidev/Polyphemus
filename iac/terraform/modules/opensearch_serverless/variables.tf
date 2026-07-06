variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "vpc_endpoint_ids" {
  description = "OpenSearch Serverless VPC endpoint ids for private access."
  type        = list(string)
  default     = []
}

variable "data_access_principals" {
  description = "IAM principal ARNs granted data-access to the collection."
  type        = list(string)
  default     = []
}
