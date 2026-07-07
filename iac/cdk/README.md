# Polyphemus — AWS CDK (SECOND IaC, mirror)

> **REFERENCE ONLY — do not `deploy` as-is.** These stacks mirror the Terraform
> modules (which are the **primary** IaC). Parity is intentional: the same
> architecture, the same controls. Review and parameterize before any deploy.

## Parity with Terraform

The CDK stacks mirror the Terraform modules resource-for-resource on the security
controls. The table lists what each stack provisions.

| CDK stack | Terraform module | Components / controls |
|---|---|---|
| `stacks/storage_stack.py` | `s3_documents` + `audit` | S3 documents + audit buckets (SSE-KMS, block public, TLS-only, versioning, C7); audit CloudWatch **LogGroup with retention** (C6) |
| `stacks/vector_stack.py` | `opensearch_serverless` | OpenSearch Serverless collection + encryption policy, **network policy (private, dashboard rule)**, and **data-access `CfnAccessPolicy`** (C2) |
| `stacks/identity_stack.py` | `cognito` | User pool, groups (`finance`/`hr`/`admin`/`staff`), app client (C1) |
| `stacks/api_stack.py` | `lambda_api` + `bedrock` | Lambda, HTTP API + JWT authorizer (C1), **stage-level throttling** (C9), scoped `bedrock:InvokeModel` IAM (C8), **Bedrock `CfnGuardrail` + scoped `bedrock:ApplyGuardrail` grant** (C5), least-privilege `aoss:APIAccessAll` grant (C2/C8) |

### Known differences (parity caveats)

- **Data-access / VPC-endpoint principals** are wired at deploy time. The CDK
  `CfnAccessPolicy` (and the Terraform data-access policy) ship with an empty
  principal list so the reference synths/plans without a concrete account or role
  ARN. Supply the pipeline role ARN before deploying.
- The Lambda **code** is an inline placeholder in both trees; supply a real build
  artifact at deploy time.
- Neither tree enables S3 **Object Lock** by default (it cannot be turned on after
  bucket creation); it is called out as a note to enable for WORM audit records.

## Usage (reference)

```bash
cd iac/cdk
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cdk synth      # requires the AWS CDK CLI (npm i -g aws-cdk)
```

Terraform is the primary IaC; use CDK if your organization standardizes on it.
Both provision the same security controls (see the table and caveats above).
