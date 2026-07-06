# REFERENCE ONLY — Cognito user pool + groups + app client (control C1).
#
# Groups map to the RBAC groups the pipeline reads from `cognito:groups`. Custom
# attributes carry the ABAC department and clearance the pipeline maps into
# UserContext. Entra ID federation is covered in the module README.

resource "aws_cognito_user_pool" "this" {
  name = "${var.name_prefix}-users"

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  schema {
    name                = "department"
    attribute_data_type = "String"
    mutable             = true
    string_attribute_constraints {
      min_length = 1
      max_length = 64
    }
  }

  schema {
    name                = "clearance"
    attribute_data_type = "String"
    mutable             = true
    string_attribute_constraints {
      min_length = 1
      max_length = 32
    }
  }
}

resource "aws_cognito_user_group" "groups" {
  for_each     = toset(var.allowed_groups)
  name         = each.value
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "Polyphemus RBAC group: ${each.value}"
}

resource "aws_cognito_user_pool_client" "app" {
  name         = "${var.name_prefix}-app"
  user_pool_id = aws_cognito_user_pool.this.id

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  allowed_oauth_flows_user_pool_client = true
  supported_identity_providers         = ["COGNITO"]

  # No client secret is stored in this repo. Configure callback URLs per env.
  generate_secret = false
}
