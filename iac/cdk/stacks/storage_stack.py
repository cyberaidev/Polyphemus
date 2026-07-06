"""Storage stack — S3 documents + audit buckets (mirrors s3_documents + audit)."""

from __future__ import annotations

from aws_cdk import RemovalPolicy, Stack
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from constructs import Construct


class StorageStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, name_prefix: str, **kwargs) -> None:
        super().__init__(scope, cid, **kwargs)

        key = kms.Key(
            self, "DocumentsKey", enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Documents bucket: SSE-KMS, block public, TLS enforced, versioned (C7).
        self.documents_bucket = s3.Bucket(
            self,
            "Documents",
            bucket_name=f"{name_prefix}-documents",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Audit bucket (C6). For tamper-evidence, enable object lock at creation.
        self.audit_bucket = s3.Bucket(
            self,
            "Audit",
            bucket_name=f"{name_prefix}-audit",
            encryption=s3.BucketEncryption.KMS_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            # object_lock_enabled=True,  # enable for WORM audit records
            removal_policy=RemovalPolicy.RETAIN,
        )
