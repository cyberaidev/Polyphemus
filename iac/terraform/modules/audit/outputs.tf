output "audit_bucket_name" {
  value = aws_s3_bucket.audit.id
}

output "audit_bucket_arn" {
  value = aws_s3_bucket.audit.arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.audit.name
}
