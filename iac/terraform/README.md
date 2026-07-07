# Polyphemus — Terraform (PRIMARY IaC)

> **REFERENCE ONLY — do not `apply` as-is.** These modules illustrate how the
> Polyphemus architecture maps to AWS resources. No backend/state is configured,
> no real endpoints or secrets are committed, and several resources are
> intentionally minimal. Review, parameterize, and add a remote state backend
> before using in any real account.

## How this maps to the architecture

| Module | Architecture component | Key controls |
|---|---|---|
| `modules/s3_documents` | S3 (documents) | SSE-KMS, block public access, TLS-only bucket policy, versioning (C7) |
| `modules/opensearch_serverless` | Vector store (**primary**) | encryption/network/data-access policies; ACL metadata filtering at query time (C2) |
| `modules/cognito` | Identity provider | user pool + groups (`finance`/`hr`/`admin`), app client (C1); Entra federation notes below |
| `modules/bedrock` | Bedrock | Guardrail + Knowledge Base references, IAM scoped to specific model ARNs (C5, C8) |
| `modules/lambda_api` | API Gateway + Lambda | HTTP API with **JWT authorizer**, function role (C1, C8), **stage-level throttling** (C9) |
| `modules/audit` | Audit trail | CloudWatch log group + S3 audit bucket (object-lock note) (C6) |

## Usage (reference)

```bash
cd iac/terraform
terraform init      # add your own backend first
terraform plan -var="name_prefix=polyphemus" -var="region=us-east-1"
```

## Identity federation (Entra ID)

Cognito is the primary IdP. To federate Microsoft Entra ID, add an OIDC/SAML
identity provider to the user pool and map the `groups`, `department`, and
`clearance` claims to the Cognito custom attributes the pipeline reads
(`custom:department`, `custom:clearance`). The pipeline's `authz/identity.py`
already accepts both Cognito- and Entra-shaped claims.

## Alternate vector store — Aurora + pgvector

OpenSearch Serverless is primary. To use Aurora PostgreSQL + `pgvector` instead,
replace `modules/opensearch_serverless` with an Aurora cluster module and enforce
the same query-time filter in SQL (`WHERE allowed_groups && ARRAY[...] AND
classification_rank <= ...`). See `docs/ARCHITECTURE.md` §5 for trade-offs.
