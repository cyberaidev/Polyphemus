variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "allowed_groups" {
  description = "RBAC groups to provision."
  type        = list(string)
  default     = ["finance", "hr", "admin", "staff"]
}
