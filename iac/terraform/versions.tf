# REFERENCE ONLY — version constraints for the Polyphemus reference stack.
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }

  # NOTE: no backend is configured on purpose. Add your own remote state backend
  # (e.g. S3 + DynamoDB lock) before using this in a real account.
}
