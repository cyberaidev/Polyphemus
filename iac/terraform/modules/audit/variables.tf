variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 365
}
