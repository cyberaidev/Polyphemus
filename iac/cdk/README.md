# Polyphemus — AWS CDK (SECOND IaC, mirror)

> **REFERENCE ONLY — do not `deploy` as-is.** These stacks mirror the Terraform
> modules (which are the **primary** IaC). Parity is intentional: the same
> architecture, the same controls. Review and parameterize before any deploy.

## Parity with Terraform

| CDK stack | Terraform module | Component |
|---|---|---|
| `stacks/storage_stack.py` | `s3_documents` + `audit` | S3 documents + audit buckets (SSE-KMS, block public, versioning) |
| `stacks/vector_stack.py` | `opensearch_serverless` | OpenSearch Serverless collection + encryption/network/data-access policies |
| `stacks/identity_stack.py` | `cognito` | User pool, groups, app client |
| `stacks/api_stack.py` | `lambda_api` + `bedrock` | Lambda, HTTP API + JWT authorizer, scoped Bedrock IAM |

## Usage (reference)

```bash
cd iac/cdk
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cdk synth      # requires the AWS CDK CLI (npm i -g aws-cdk)
```

Terraform is the primary IaC; use CDK if your organization standardizes on it.
Both produce the same resources with the same controls.
