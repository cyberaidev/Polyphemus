# REFERENCE ONLY — OpenSearch Serverless vector collection (PRIMARY vector store).
#
# The collection stores chunk vectors plus ACL metadata. Query-time bool filters
# on that metadata are the primary access-control enforcement point (control C2).

locals {
  collection_name = "${var.name_prefix}-vectors"
}

# Encryption policy — AWS-owned/KMS encryption at rest.
resource "aws_opensearchserverless_security_policy" "encryption" {
  name = "${var.name_prefix}-enc"
  type = "encryption"
  policy = jsonencode({
    Rules = [
      {
        ResourceType = "collection"
        Resource     = ["collection/${local.collection_name}"]
      }
    ]
    AWSOwnedKey = true
  })
}

# Network policy — restrict to VPC/private access in a real deployment. Shown as
# private (no public access) here.
resource "aws_opensearchserverless_security_policy" "network" {
  name = "${var.name_prefix}-net"
  type = "network"
  policy = jsonencode([
    {
      Description = "Private access to the Polyphemus vector collection"
      Rules = [
        {
          ResourceType = "collection"
          Resource     = ["collection/${local.collection_name}"]
        },
        {
          ResourceType = "dashboard"
          Resource     = ["collection/${local.collection_name}"]
        }
      ]
      AllowFromPublic = false
      SourceVPCEs     = var.vpc_endpoint_ids
    }
  ])
}

# Data-access policy — grant the pipeline principal least-privilege index access.
resource "aws_opensearchserverless_access_policy" "data" {
  name = "${var.name_prefix}-data"
  type = "data"
  policy = jsonencode([
    {
      Description = "Pipeline read/write to the vector index"
      Rules = [
        {
          ResourceType = "index"
          Resource     = ["index/${local.collection_name}/*"]
          Permission = [
            "aoss:CreateIndex",
            "aoss:UpdateIndex",
            "aoss:DescribeIndex",
            "aoss:ReadDocument",
            "aoss:WriteDocument"
          ]
        }
      ]
      Principal = var.data_access_principals
    }
  ])
}

resource "aws_opensearchserverless_collection" "vectors" {
  name = local.collection_name
  type = "VECTORSEARCH"

  depends_on = [
    aws_opensearchserverless_security_policy.encryption,
    aws_opensearchserverless_security_policy.network
  ]
}
