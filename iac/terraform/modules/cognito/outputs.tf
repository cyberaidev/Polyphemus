output "user_pool_id" {
  value = aws_cognito_user_pool.this.id
}

output "user_pool_client_id" {
  value = aws_cognito_user_pool_client.app.id
}

output "user_pool_endpoint" {
  description = "Issuer endpoint used by the API Gateway JWT authorizer."
  value       = "https://${aws_cognito_user_pool.this.endpoint}"
}
