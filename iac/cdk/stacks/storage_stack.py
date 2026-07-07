"""Storage stack — S3 documents + audit buckets (mirrors s3_documents + audit)."""

from __future__ import annotations

from aws_cdk import RemovalPolicy, Stack
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from constructs import Construct


class StorageStack(Stack):
    def __init__(
        self,
        scope: Construct,
        cid: str,
        *,
        name_prefix: str,
        log_retention_days: int = 365,
        **kwargs,
    ) -> None:
        super().__init__(scope, cid, **kwargs)

        key = kms.Key(
            self,
            "DocumentsKey",
            enable_key_rotation=True,
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

        # Audit CloudWatch log group with retention (C6). Mirrors the Terraform
        # audit module's aws_cloudwatch_log_group so structured JSONL audit records
        # have a retained sink in both IaC trees.
        self.audit_log_group = logs.LogGroup(
            self,
            "AuditLogGroup",
            log_group_name=f"/{name_prefix}/audit",
            retention=_retention_for_days(log_retention_days),
            removal_policy=RemovalPolicy.RETAIN,
        )


def _retention_for_days(days: int) -> "logs.RetentionDays":
    """Map a day count to the closest CDK RetentionDays enum member.

    Terraform accepts an arbitrary integer; CDK requires an enum. We map to the
    nearest supported value at or above ``days`` so retention is never shorter
    than requested (defaults to one year).
    """
    supported = sorted(
        (int(member.value), member) for member in logs.RetentionDays if str(member.value).isdigit()
    )
    for value, member in supported:
        if value >= days:
            return member
    return logs.RetentionDays.TEN_YEARS
