# REFERENCE ONLY — Bedrock IAM + Guardrail/KB references (controls C5, C8).
#
# The invoke policy is scoped to SPECIFIC model ARNs (least privilege) rather than
# a wildcard. A Guardrail resource is referenced for PII/injection filtering; a
# Knowledge Base association is illustrative.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  model_arns = [
    "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/${var.bedrock_text_model_id}",
    "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/${var.bedrock_embed_model_id}",
  ]
}

# Guardrail for PII masking + prompt-attack filtering (managed alternative to the
# in-code defenses; complements them defense-in-depth).
resource "aws_bedrock_guardrail" "this" {
  name                      = "${var.name_prefix}-guardrail"
  blocked_input_messaging   = "This request was blocked by the Polyphemus guardrail."
  blocked_outputs_messaging = "This response was blocked by the Polyphemus guardrail."

  sensitive_information_policy_config {
    pii_entities_config {
      type   = "US_SOCIAL_SECURITY_NUMBER"
      action = "ANONYMIZE"
    }
    pii_entities_config {
      type   = "EMAIL"
      action = "ANONYMIZE"
    }
    pii_entities_config {
      type   = "CREDIT_DEBIT_CARD_NUMBER"
      action = "ANONYMIZE"
    }
  }

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
  }
}

# Least-privilege policy scoped to the specific model ARNs + guardrail.
resource "aws_iam_policy" "invoke" {
  name        = "${var.name_prefix}-bedrock-invoke"
  description = "Least-privilege Bedrock invoke for the Polyphemus pipeline."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeSpecificModels"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = local.model_arns
      },
      {
        Sid      = "ApplyGuardrail"
        Effect   = "Allow"
        Action   = ["bedrock:ApplyGuardrail"]
        Resource = [aws_bedrock_guardrail.this.guardrail_arn]
      }
    ]
  })
}
