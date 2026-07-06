"""API stack — Lambda + HTTP API + JWT authorizer + scoped Bedrock IAM.

Mirrors the Terraform ``lambda_api`` + ``bedrock`` modules (controls C1, C5, C8).
"""

from __future__ import annotations

from aws_cdk import Duration, Stack
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_apigatewayv2_authorizers as authz
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_s3 as s3
from constructs import Construct


class ApiStack(Stack):
    def __init__(
        self,
        scope: Construct,
        cid: str,
        *,
        name_prefix: str,
        documents_bucket: s3.IBucket,
        audit_bucket: s3.IBucket,
        user_pool: cognito.IUserPool,
        user_pool_client: cognito.IUserPoolClient,
        text_model_id: str,
        embed_model_id: str,
        **kwargs,
    ) -> None:
        super().__init__(scope, cid, **kwargs)

        # Least-privilege Bedrock invoke scoped to specific model ARNs (C8).
        model_arns = [
            f"arn:aws:bedrock:{self.region}::foundation-model/{text_model_id}",
            f"arn:aws:bedrock:{self.region}::foundation-model/{embed_model_id}",
        ]

        fn = lambda_.Function(
            self,
            "Pipeline",
            function_name=f"{name_prefix}-pipeline",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="api.handler.handler",
            timeout=Duration.seconds(30),
            memory_size=512,
            # Reference-only: supply a real build artifact at deploy time.
            code=lambda_.Code.from_inline("def handler(event, context): return {}"),
            environment={"POLYPHEMUS_MODE": "aws", "POLYPHEMUS_REGION": self.region},
        )

        fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:InvokeModel"],
                resources=model_arns,
            )
        )
        documents_bucket.grant_read(fn)
        audit_bucket.grant_put(fn)

        # HTTP API with a JWT authorizer validating Cognito tokens (C1).
        jwt_authorizer = authz.HttpJwtAuthorizer(
            "JwtAuthorizer",
            jwt_issuer=f"https://cognito-idp.{self.region}.amazonaws.com/{user_pool.user_pool_id}",
            identity_source=["$request.header.Authorization"],
            jwt_audience=[user_pool_client.user_pool_client_id],
        )

        http_api = apigwv2.HttpApi(self, "HttpApi", api_name=f"{name_prefix}-api")
        http_api.add_routes(
            path="/ask",
            methods=[apigwv2.HttpMethod.POST],
            integration=integrations.HttpLambdaIntegration("PipelineIntegration", fn),
            authorizer=jwt_authorizer,
        )

        self.api = http_api
