# REFERENCE ONLY — AWS provider configuration.
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "polyphemus"
      Reference = "true"
      ManagedBy = "terraform"
    }
  }
}
