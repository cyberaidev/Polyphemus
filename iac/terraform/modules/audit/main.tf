# REFERENCE ONLY — audit trail sinks (control C6).
#
# CloudWatch log group for structured JSONL records plus an S3 audit bucket.
# NOTE: enable S3 Object Lock (WORM) at bucket-creation time for tamper-evidence
# in a real deployment (shown as a note, not enabled by default here).

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/${var.name_prefix}/audit"
  retention_in_days = var.log_retention_days
}

resource "aws_s3_bucket" "audit" {
  bucket = "${var.name_prefix}-audit"

  # To make audit records immutable, create the bucket with object lock enabled:
  #   object_lock_enabled = true
  # then configure a COMPLIANCE-mode default retention below. Object lock cannot
  # be enabled after creation, so it is called out explicitly here.
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
