"""Identity stack — Cognito pool, groups, client (mirrors cognito module)."""

from __future__ import annotations

from aws_cdk import RemovalPolicy, Stack
from aws_cdk import aws_cognito as cognito
from constructs import Construct

_GROUPS = ["finance", "hr", "admin", "staff"]


class IdentityStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, name_prefix: str, **kwargs) -> None:
        super().__init__(scope, cid, **kwargs)

        self.user_pool = cognito.UserPool(
            self,
            "UserPool",
            user_pool_name=f"{name_prefix}-users",
            self_sign_up_enabled=False,
            password_policy=cognito.PasswordPolicy(
                min_length=12,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
            ),
            custom_attributes={
                "department": cognito.StringAttribute(mutable=True, max_len=64),
                "clearance": cognito.StringAttribute(mutable=True, max_len=32),
            },
            removal_policy=RemovalPolicy.RETAIN,
        )

        for group in _GROUPS:
            cognito.CfnUserPoolGroup(
                self,
                f"Group{group.capitalize()}",
                user_pool_id=self.user_pool.user_pool_id,
                group_name=group,
                description=f"Polyphemus RBAC group: {group}",
            )

        self.user_pool_client = self.user_pool.add_client(
            "AppClient",
            user_pool_client_name=f"{name_prefix}-app",
            generate_secret=False,
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL,
                        cognito.OAuthScope.PROFILE],
            ),
        )
