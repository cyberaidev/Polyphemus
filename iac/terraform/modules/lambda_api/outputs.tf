output "api_endpoint" {
  value = aws_apigatewayv2_stage.default.invoke_url
}

output "lambda_role_arn" {
  value = aws_iam_role.lambda.arn
}

output "function_name" {
  value = aws_lambda_function.pipeline.function_name
}
