# Security Policy

Polyphemus is a **security reference implementation**, not a production service.
It is designed to be run offline in mock mode (`POLYPHEMUS_MODE=mock`) with no AWS
credentials. Even so, we take the correctness of the security controls seriously —
the whole point of the project is to demonstrate them faithfully.

## Reporting a vulnerability

If you discover a security issue — a flaw in one of the demonstrated controls
(access control, PII redaction, prompt-injection defense, audit trail), a
misleading claim in the docs, or an insecure pattern in the IaC references —
please report it privately:

- **Preferred:** open a [GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository ("Report a vulnerability").
- **Alternative:** open a regular issue **only** if the finding is non-sensitive
  (e.g. a documentation inaccuracy). Do not include exploit details in public
  issues for anything that could affect a downstream adopter.

Please include:

- a description of the issue and the control it affects,
- steps to reproduce (a failing test or a `run_demo.py` scenario is ideal),
- the impact you believe it has for someone adapting this reference.

## Response expectations

This is a community reference maintained on a best-effort basis. We aim to
acknowledge reports within **7 days** and to address confirmed issues in the
controls or documentation promptly. There is no bug-bounty program.

## Scope

**In scope**

- Incorrect or bypassable access-control logic (`authz/`, `retrieval/`).
- PII redaction gaps in the offline detectors (`redaction/`).
- Prompt-injection defense weaknesses (`defense/`) — but note the
  [mock-mode limitations](README.md#limitations-of-mock-mode): the mock model's
  injection resistance is simulated deterministically.
- Audit-trail integrity or completeness issues (`audit/`).
- Insecure or misleading Infrastructure-as-Code references (`iac/`).

**Out of scope**

- The deliberately vulnerable "defenses OFF" contrast path (it exists to
  demonstrate the vulnerability the control prevents).
- The intentionally malicious sample document under `data/documents/malicious/`.
- Anything requiring live AWS access — the `aws`-mode clients are reference stubs.

## Threat model

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for assets, adversaries,
in/out-of-scope boundaries, and known residual risks.
