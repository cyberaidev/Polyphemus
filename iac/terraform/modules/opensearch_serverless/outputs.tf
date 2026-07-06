output "collection_name" {
  value = aws_opensearchserverless_collection.vectors.name
}

output "collection_arn" {
  value = aws_opensearchserverless_collection.vectors.arn
}

output "collection_endpoint" {
  value = aws_opensearchserverless_collection.vectors.collection_endpoint
}
