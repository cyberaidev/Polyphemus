# Threat Model — Polyphemus

This is a lightweight threat model for the Polyphemus secure-RAG reference. It
names the assets, the adversaries, what is in and out of scope, and the residual
risks that remain even with every control enabled. It complements
[`SECURITY_CONTROLS.md`](SECURITY_CONTROLS.md) (the control catalog) and
[`ARCHITECTURE.md`](ARCHITECTURE.md) (data flow and trust boundaries).

## Assets

| Asset | Why it matters |
|---|---|
| Department-confidential documents (finance, HR) | Cross-department leakage is the primary harm the access control prevents. |
| PII inside documents and prompts (SSN, email, IBAN, cards, …) | Must never reach the model or the response in the clear. |
| The system prompt / guardrail canary | Leakage indicates a successful prompt-injection / exfiltration. |
| The audit trail | Non-repudiation and incident response depend on its integrity and completeness. |
| The model backend (paid Bedrock invocations) | Abuse/flooding is a cost and availability risk. |

## Adversaries

- **Unauthorized caller** — a valid user of one department trying to read another
  department's documents (or an unauthenticated caller at the edge).
- **Malicious document author** — someone who can get a document indexed (e.g. a
  vendor invoice) and embeds instructions hoping the model will obey them
  (indirect prompt injection). The document may be one the *victim is authorized
  to read*, so access control alone does not stop it.
- **Curious/over-broad insider** — a highly-privileged user (e.g. `admin`) whose
  legitimate access must not be turned into a data dump by an injected payload.
- **Abusive client** — floods the API to exhaust the paid model backend.

## In scope

- Query-time access control (RBAC group intersection + ABAC clearance), enforced
  fail-closed at the vector store **and** re-checked after retrieval.
- PII redaction of context, prompt, **and** response.
- Indirect prompt-injection detection, neutralization, spotlighting, hardened
  data/instruction separation, and output-side canary validation.
- A complete, structured audit trail per request.
- Reference IaC showing encryption, least-privilege IAM, private networking, and
  rate limiting.

## Out of scope

- Live AWS deployment hardening (the `aws`-mode clients are reference stubs).
- Authentication/JWT signature verification (assumed done by the API Gateway JWT
  authorizer before the pipeline runs; `identity.py` only maps validated claims).
- The deliberately vulnerable "defenses OFF" contrast path and the intentionally
  malicious sample document — both exist to *demonstrate* risk.
- Model-level safety/alignment beyond injection resistance.

## Residual risks (known, accepted, or best-effort)

1. **Simulated injection resistance in mock mode.** The mock model's refusal to
   obey injected instructions is a deterministic `if`-statement, not a real model
   behavior. Genuine resistance in production depends on prompt hardening +
   Bedrock Guardrails (`PROMPT_ATTACK`). See
   [README → Limitations of mock mode](../README.md#limitations-of-mock-mode).
2. **Homoglyph / confusable evasion.** Neutralization applies Unicode NFKC
   normalization, which folds *compatibility* characters but does **not** map
   cross-script confusables (e.g. Cyrillic „і" → Latin „i"). A payload written in
   look-alike letters can evade the heuristic scanner. NFKC's actual scope is
   documented in `defense/injection.py`; a confusables fold would be a hardening
   improvement.
3. **Heuristic scanners are best-effort.** The injection and PII detectors are
   pattern/validation based. They will miss novel phrasings and can false-positive.
   In production, layer Bedrock Guardrails and Amazon Comprehend on top (both are
   wired in the reference).
4. **Encoded-payload heuristic is coarse.** The base64-blob rule flags long
   base64-ish runs; it can miss short or non-base64 encodings and is intentionally
   conservative to avoid flagging ordinary identifiers.
5. **Denied-evidence pass reveals existence.** The demonstration-only unfiltered
   re-query (off by default) records the *existence* of documents a user cannot
   read. It is for demos, never the production/API path — see
   `Settings.emit_denied_evidence`.
6. **Audit store integrity offline.** Offline, the audit trail is a local JSONL
   file with no tamper-evidence. Integrity depends on the IaC controls (encrypted,
   IAM-scoped, S3 Object Lock/WORM) in a real deployment.
