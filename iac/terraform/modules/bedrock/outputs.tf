output "invoke_policy_arn" {
  description = "Least-privilege Bedrock invoke policy ARN."
  value       = aws_iam_policy.invoke.arn
}

output "guardrail_arn" {
  value = aws_bedrock_guardrail.this.guardrail_arn
}
