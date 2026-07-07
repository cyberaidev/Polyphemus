"""API stack — Lambda + HTTP API + JWT authorizer + scoped Bedrock IAM + Guardrail.

Mirrors the Terraform ``lambda_api`` + ``bedrock`` modules (controls C1, C5, C8,
C9). Includes the Bedrock Guardrail and ``ApplyGuardrail`` grant, and stage-level
API throttling, to keep parity with the Terraform primary IaC.
"""

from __future__ import annotations

from aws_cdk import Duration, Stack
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_apigatewayv2_authorizers as authz
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_bedrock as bedrock
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
        throttling_rate_limit: int = 20,
        throttling_burst_limit: int = 40,
        **kwargs,
    ) -> None:
        super().__init__(scope, cid, **kwargs)

        # Least-privilege Bedrock invoke scoped to specific model ARNs (C8).
        model_arns = [
            f"arn:aws:bedrock:{self.region}::foundation-model/{text_model_id}",
            f"arn:aws:bedrock:{self.region}::foundation-model/{embed_model_id}",
        ]

        # Bedrock Guardrail for PII masking + prompt-attack filtering (C5) — the
        # managed alternative that complements the in-code injection defense.
        # Mirrors the Terraform bedrock module's aws_bedrock_guardrail.
        guardrail = bedrock.CfnGuardrail(
            self,
            "Guardrail",
            name=f"{name_prefix}-guardrail",
            blocked_input_messaging="This request was blocked by the Polyphemus guardrail.",
            blocked_outputs_messaging="This response was blocked by the Polyphemus guardrail.",
            sensitive_information_policy_config=(
                bedrock.CfnGuardrail.SensitiveInformationPolicyConfigProperty(
                    pii_entities_config=[
                        bedrock.CfnGuardrail.PiiEntityConfigProperty(
                            type="US_SOCIAL_SECURITY_NUMBER", action="ANONYMIZE"
                        ),
                        bedrock.CfnGuardrail.PiiEntityConfigProperty(
                            type="EMAIL", action="ANONYMIZE"
                        ),
                        bedrock.CfnGuardrail.PiiEntityConfigProperty(
                            type="CREDIT_DEBIT_CARD_NUMBER", action="ANONYMIZE"
                        ),
                    ]
                )
            ),
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(
                filters_config=[
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="PROMPT_ATTACK", input_strength="HIGH", output_strength="NONE"
                    )
                ]
            ),
        )

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
        # ApplyGuardrail grant scoped to the specific guardrail ARN (C5, C8).
        fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:ApplyGuardrail"],
                resources=[guardrail.attr_guardrail_arn],
            )
        )
        # Least-privilege OpenSearch Serverless data-plane access (C2/C8), mirroring
        # the Terraform lambda_api aoss grant. The collection-level data-access
        # policy is defined in VectorStack (CfnAccessPolicy).
        fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["aoss:APIAccessAll"],
                resources=["*"],
            )
        )
        documents_bucket.grant_read(fn)
        audit_bucket.grant_put(fn)

        self.guardrail = guardrail

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

        # Rate limiting / abuse control (C9). Apply stage-level throttling to the
        # default stage so a single caller cannot exhaust the pipeline (which
        # invokes paid Bedrock models). Set via the L1 CfnStage escape hatch,
        # mirroring the Terraform lambda_api module's default_route_settings.
        default_stage = http_api.default_stage
        if default_stage is not None:
            cfn_stage = default_stage.node.default_child
            cfn_stage.default_route_settings = apigwv2.CfnStage.RouteSettingsProperty(
                throttling_rate_limit=throttling_rate_limit,
                throttling_burst_limit=throttling_burst_limit,
            )

        self.api = http_api
