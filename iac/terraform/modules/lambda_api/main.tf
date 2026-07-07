# REFERENCE ONLY — Lambda + HTTP API + JWT authorizer (controls C1, C8).
#
# The HTTP API JWT authorizer validates Cognito/Entra tokens before the pipeline
# Lambda runs. The Lambda role is least-privilege: it attaches only the scoped
# Bedrock invoke policy plus narrowly-scoped S3/OpenSearch/logging permissions.

data "aws_caller_identity" "current" {}

# --- Execution role (least privilege) ---
resource "aws_iam_role" "lambda" {
  name = "${var.name_prefix}-pipeline-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "basic_logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Attach the scoped Bedrock invoke policy from the bedrock module.
resource "aws_iam_role_policy_attachment" "bedrock" {
  role       = aws_iam_role.lambda.name
  policy_arn = var.bedrock_policy_arn
}

# Narrowly-scoped access to documents (read) and audit (write).
resource "aws_iam_role_policy" "data_access" {
  name = "${var.name_prefix}-data-access"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadDocuments"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [var.documents_bucket_arn, "${var.documents_bucket_arn}/*"]
      },
      {
        Sid      = "WriteAudit"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${var.audit_bucket_arn}/*"]
      },
      {
        Sid      = "QueryVectors"
        Effect   = "Allow"
        Action   = ["aoss:APIAccessAll"]
        Resource = ["*"]
      }
    ]
  })
}

# --- Lambda function (placeholder package; real deploy supplies the artifact) ---
resource "aws_lambda_function" "pipeline" {
  function_name = "${var.name_prefix}-pipeline"
  role          = aws_iam_role.lambda.arn
  handler       = "api.handler.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 512

  # Reference-only: point at a real build artifact (zip/container) at deploy time.
  filename = var.lambda_package_path

  environment {
    variables = {
      POLYPHEMUS_MODE   = "aws"
      POLYPHEMUS_REGION = var.region
    }
  }
}

# --- HTTP API + JWT authorizer ---
resource "aws_apigatewayv2_api" "http" {
  name          = "${var.name_prefix}-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_authorizer" "jwt" {
  api_id           = aws_apigatewayv2_api.http.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "${var.name_prefix}-jwt"

  jwt_configuration {
    audience = [var.user_pool_client_id]
    issuer   = var.user_pool_endpoint
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.pipeline.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "ask" {
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "POST /ask"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true

  # Rate limiting / abuse control (C9). Stage-level throttling caps the sustained
  # request rate and burst so a single caller cannot exhaust the pipeline (which
  # invokes paid Bedrock models). Tune per environment.
  default_route_settings {
    throttling_rate_limit  = var.throttling_rate_limit
    throttling_burst_limit = var.throttling_burst_limit
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pipeline.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}
