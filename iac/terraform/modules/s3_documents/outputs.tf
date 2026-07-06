output "bucket_name" {
  value = aws_s3_bucket.documents.id
}

output "bucket_arn" {
  value = aws_s3_bucket.documents.arn
}

output "kms_key_arn" {
  value = aws_kms_key.documents.arn
}
