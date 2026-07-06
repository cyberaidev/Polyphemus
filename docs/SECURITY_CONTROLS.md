# Security Controls Catalog

Each control below is implemented in code (not just documented), is observable in
the `AuditRecord`, and is exercised by the test suite. Mappings reference the
[OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
and NIST publications.

## Control catalog

| # | Control | Module(s) | Threat addressed | OWASP LLM | NIST reference |
|---|---|---|---|---|---|
| C1 | JWT/OIDC authentication | API Gateway authorizer, `authz/identity.py` | unauthenticated access, identity spoofing | LLM08 Excessive Agency (scoping identity) | SP 800-63 (digital identity) |
| C2 | Query-time authorization filter | `authz/query_filter.py`, vector store | broken access control, cross-tenant/department leakage | LLM06 Sensitive Information Disclosure | SP 800-162 (ABAC), AC-3 |
| C3 | Post-retrieval policy re-check | `authz/policy.py`, `retrieval/retriever.py` | filter misconfiguration, defense-in-depth | LLM06 | AC-3, SC-3 (defense in depth) |
| C4 | PII redaction (context + prompt) | `redaction/detectors.py`, `redaction/redactor.py` | sensitive data exposure to the model / in output | LLM06 Sensitive Information Disclosure, LLM02 Insecure Output Handling | SP 800-122 (PII) |
| C5 | Prompt-injection defense | `defense/injection.py`, `defense/system_prompt.py` | indirect prompt injection, data/instruction confusion | LLM01 Prompt Injection | SP 800-53 SI-10 (input validation) |
| C6 | Structured audit trail | `audit/logger.py`, `models.AuditRecord` | non-repudiation, incident response | (cross-cutting) | AU-2, AU-3, AU-12 |
| C7 | Encryption at rest / in transit | IaC: `s3_documents`, `audit` modules | data-at-rest/in-transit exposure | LLM06 | SC-13, SC-28 |
| C8 | Least-privilege IAM | IaC: `bedrock`, `lambda_api` modules | excessive agency, blast radius | LLM08 Excessive Agency | AC-6 (least privilege) |

## OWASP LLM Top 10 coverage summary

- **LLM01 Prompt Injection** — C5: data/instruction separation via nonce-fenced
  spotlighting, heuristic scanning (override/role-switch/exfiltration/encoded/
  zero-width), and neutralization. Demonstrated in Scenario 3, including a
  defenses-disabled contrast that shows the vulnerability the control prevents.
- **LLM02 Insecure Output Handling** — C4: PII is redacted from context and prompt
  before invocation; the hardened prompt forbids echoing the system prompt or
  embedded instructions, so injected exfiltration directives do not reach output.
- **LLM06 Sensitive Information Disclosure** — C2/C3 (access control) + C4
  (redaction) + C7 (encryption). Scenario 2 proves a denied user receives no
  cross-department content.
- **LLM08 Excessive Agency** — C1 + C8: identity is derived only from validated
  claims and the compute role is scoped to specific model ARNs and resources.

## PII redaction detail (C4)

- **Primary (offline default):** regex + validation detectors for
  `US_SSN`, `EMAIL`, `PHONE`, `CREDIT_CARD` (Luhn-validated), `IBAN`,
  `AWS_ACCESS_KEY`.
- **Enhanced (aws mode):** `ComprehendAdapter.detect` calls Amazon Comprehend
  `detect_pii_entities` for NER-grade entities (name, address, bank account),
  unioned with the structured regex detectors.
- **Managed alternative:** Amazon Bedrock Guardrails PII filters can enforce the
  same masking at the model boundary; documented here as a drop-in for C4/C5.
- **Where applied:** retrieved **context** and the **user prompt**, *before*
  Bedrock invocation. Replacements use typed placeholders (`[REDACTED_SSN]`), and
  each is recorded as a `RedactionEvent` in the audit trail.

## Prompt-injection defense detail (C5)

1. **Data/instruction separation** — the hardened system prompt declares the
   fenced CONTEXT to be untrusted data and forbids following instructions inside it.
2. **Spotlighting / delimiting** — each chunk is wrapped in a nonce-tagged fence
   with its `source_uri`; fence tokens inside content are escaped to defeat
   delimiter-escape attacks.
3. **Heuristic scanning** — flags override phrases, role hijacks, prompt/data
   exfiltration, encoded payloads, and zero-width characters (`injection_flags`).
4. **Neutralization** — zero-width stripping, unicode normalization, and defanging
   of detected control phrases before they reach the model.

## Auditability detail (C6)

Every request emits one JSONL `AuditRecord` containing: `request_id`, `timestamp`,
`user` (identity), `prompt` (original, access-controlled) and `redacted_prompt`,
`retrieved_sources`, `denied_sources`, `policy_decisions`, `redactions`,
`injection_flags`, `defenses_enabled`, `model_id`, `response`, and `latency_ms`.

The `redacted_*` fields never contain raw PII. The original `prompt` is retained as
access-controlled evidence; in aws mode the audit store is encrypted and access is
constrained by IAM, with S3 object lock for tamper-evidence.
