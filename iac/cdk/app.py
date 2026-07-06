#!/usr/bin/env python3
"""Polyphemus CDK app (REFERENCE ONLY — mirrors the Terraform primary IaC).

Instantiates the four stacks that map 1:1 to the Terraform modules. Requires the
AWS CDK CLI (`npm i -g aws-cdk`) and `aws-cdk-lib` to synth; nothing here is
deployed automatically.
"""

from __future__ import annotations

import aws_cdk as cdk

from stacks.api_stack import ApiStack
from stacks.identity_stack import IdentityStack
from stacks.storage_stack import StorageStack
from stacks.vector_stack import VectorStack

app = cdk.App()
prefix = app.node.try_get_context("name_prefix") or "polyphemus"

storage = StorageStack(app, f"{prefix}-storage", name_prefix=prefix)
vector = VectorStack(app, f"{prefix}-vector", name_prefix=prefix)
identity = IdentityStack(app, f"{prefix}-identity", name_prefix=prefix)
ApiStack(
    app,
    f"{prefix}-api",
    name_prefix=prefix,
    documents_bucket=storage.documents_bucket,
    audit_bucket=storage.audit_bucket,
    user_pool=identity.user_pool,
    user_pool_client=identity.user_pool_client,
    text_model_id=app.node.try_get_context("bedrock_text_model_id"),
    embed_model_id=app.node.try_get_context("bedrock_embed_model_id"),
)

app.synth()
