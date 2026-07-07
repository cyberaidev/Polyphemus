#!/usr/bin/env python3
"""Polyphemus demo runner — executes all four security scenarios offline.

Runs entirely in ``POLYPHEMUS_MODE=mock`` (forced below if unset), so no AWS
account or credentials are required. For each scenario it prints the caller's
identity, the query, authorized vs denied sources, redactions, injection flags,
the final answer, and the resulting audit record. Scenario 4 prints the full
JSONL audit trail accumulated across scenarios 1-3.

Exits non-zero if any scenario's key assertion fails, so ``make demo`` doubles as
an end-to-end smoke test.

Usage:
    POLYPHEMUS_MODE=mock python scripts/run_demo.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
os.environ.setdefault("POLYPHEMUS_MODE", "mock")
# The demo turns ON the demonstration-only denied-evidence pass so scenarios 2 and
# 4 can show exactly which documents the ACL withheld. Production/API leaves it off.
os.environ.setdefault("POLYPHEMUS_EMIT_DENIED_EVIDENCE", "true")

from polyphemus.audit.logger import AuditLogger  # noqa: E402
from polyphemus.authz.identity import from_fixture  # noqa: E402
from polyphemus.authz.query_filter import describe_filter  # noqa: E402
from polyphemus.aws.mock_bedrock import SYSTEM_PROMPT_SECRET_MARKER  # noqa: E402
from polyphemus.models import AuditRecord, UserContext  # noqa: E402
from polyphemus.pipeline import SecureRAGPipeline  # noqa: E402
from seed_store import seed  # noqa: E402  (same scripts/ dir)

RULE = "=" * 78
SUB = "-" * 78

_failures: list[str] = []


def check(label: str, condition: bool) -> None:
    status = "PASS" if condition else "FAIL"
    print(f"    [{status}] {label}")
    if not condition:
        _failures.append(label)


def short(uri: str) -> str:
    return uri.replace("file://data/documents/", "")


def print_identity(user: UserContext) -> None:
    print(f"  Identity : {user.username} (sub={user.subject}, idp={user.idp})")
    print(f"  Groups   : {user.groups}   Clearance: {user.clearance}")
    print(f"  ACL filter: {describe_filter(user)}")


def print_record(record: AuditRecord, redacted_only: bool = True) -> None:
    print(f"  Authorized sources : {[short(u) for u in record.retrieved_sources] or '(none)'}")
    print(f"  Denied sources     : {[short(u) for u in record.denied_sources] or '(none)'}")
    redactions = [f"{e.entity_type}x{e.count}@{e.location}" for e in record.redactions]
    print(f"  Redactions         : {redactions or '(none)'}")
    print(f"  Injection flags    : {record.injection_flags or '(none)'}")
    print(f"  Model              : {record.model_id}")
    print(f"  Answer             : {record.response}")


def scenario_1(pipeline: SecureRAGPipeline) -> AuditRecord:
    print(RULE)
    print("SCENARIO 1 — Finance user retrieves finance docs (PII redacted)")
    print(RULE)
    user = from_fixture("finance_user")
    query = "What were the recent vendor payments this quarter?"
    print_identity(user)
    print(f"  Query    : {query!r}")
    print(SUB)
    record = pipeline.answer(user, query)
    print_record(record)
    print(SUB)
    finance_seen = any("finance/" in u for u in record.retrieved_sources)
    pii_types = {e.entity_type for e in record.redactions}
    expected_pii = {"US_SSN", "EMAIL", "PHONE", "IBAN", "CREDIT_CARD"}
    check("finance documents were retrieved", finance_seen)
    check("PII redacted (SSN present)", "US_SSN" in pii_types)
    check(
        "PII redacted (US_SSN, EMAIL, PHONE, IBAN, CREDIT_CARD)",
        expected_pii <= pii_types,
    )
    check("no HR documents retrieved", not any("hr/" in u for u in record.retrieved_sources))
    return record


def scenario_2(pipeline: SecureRAGPipeline) -> AuditRecord:
    print(RULE)
    print("SCENARIO 2 — HR user DENIED finance docs")
    print(RULE)
    user = from_fixture("hr_user")
    query = "What were the recent vendor payments this quarter?"
    print_identity(user)
    print(f"  Query    : {query!r}")
    print(SUB)
    record = pipeline.answer(user, query)
    print_record(record)
    print(SUB)
    finance_denied = any("finance/" in u for u in record.denied_sources)
    no_finance_retrieved = not any("finance/" in u for u in record.retrieved_sources)
    refused = "authorized information" in record.response.lower()
    check("finance sources appear in denied_sources", finance_denied)
    check("no finance sources retrieved", no_finance_retrieved)
    check("answer = no authorized information", refused)
    return record


def scenario_3(pipeline: SecureRAGPipeline) -> AuditRecord:
    print(RULE)
    print("SCENARIO 3 — Indirect prompt injection detected + neutralized")
    print(RULE)
    user = from_fixture("finance_user")
    query = "Summarize the Aperture vendor invoice."
    print_identity(user)
    print(f"  Query    : {query!r}")
    print(SUB)
    record = pipeline.answer(user, query)
    print_record(record)
    print(SUB)
    leaked = SYSTEM_PROMPT_SECRET_MARKER in record.response
    hr_leaked = any("hr/" in u for u in record.retrieved_sources)
    check(
        "injection detected (override_instruction flagged)",
        "override_instruction" in record.injection_flags,
    )
    check("injection detected (exfiltration flagged)", "exfiltration" in record.injection_flags)
    check("system prompt NOT leaked", not leaked)
    check("HR documents NOT exposed", not hr_leaked)
    check("no exfiltration target in answer", "attacker@evil.example" not in record.response)

    # Contrast run: defenses DISABLED to demonstrate the vulnerability.
    print()
    print("  >>> CONTROL DISABLED (for demonstration only) <<<")
    unsafe = SecureRAGPipeline(defenses_enabled=False)
    unsafe_record = unsafe.answer(from_fixture("attacker"), query)
    print(f"  Answer (defenses OFF): {unsafe_record.response[:200]}")
    would_leak = SYSTEM_PROMPT_SECRET_MARKER in unsafe_record.response
    check("with defenses OFF the payload WOULD hijack (vulnerability shown)", would_leak)
    print(SUB)
    return record


def scenario_4() -> None:
    print(RULE)
    print("SCENARIO 4 — Audit evidence (full JSONL trail, scenarios 1-3)")
    print(RULE)
    records = AuditLogger().read_all()
    # Exclude the defenses-off contrast record from the "protected" trail summary.
    protected = [r for r in records if r.defenses_enabled]
    check("audit trail has >= 3 protected records", len(protected) >= 3)
    for i, rec in enumerate(records, start=1):
        tag = "" if rec.defenses_enabled else "  (defenses DISABLED — demo contrast)"
        print(f"\n--- audit record {i}{tag} ---")
        print(json.dumps(json.loads(rec.to_jsonl()), indent=2))
    # Field-completeness check on the first protected record.
    if protected:
        rec = protected[0]
        required = [
            rec.request_id,
            rec.timestamp,
            rec.user,
            rec.prompt,
            rec.redacted_prompt,
            rec.model_id,
            rec.response,
        ]
        check("audit records carry all required fields", all(x for x in required))


def main() -> int:
    print(RULE)
    print("POLYPHEMUS — secure Bedrock RAG reference (offline demo, mode=mock)")
    print(RULE)

    # Fresh audit log + seeded store for a deterministic run.
    AuditLogger().clear()
    count = seed()
    print(f"Seeded {count} chunks into the mock vector store.\n")

    pipeline = SecureRAGPipeline()
    scenario_1(pipeline)
    print()
    scenario_2(pipeline)
    print()
    scenario_3(pipeline)
    print()
    scenario_4()

    print()
    print(RULE)
    if _failures:
        print(f"DEMO FAILED — {len(_failures)} assertion(s) did not hold:")
        for f in _failures:
            print(f"  - {f}")
        print(RULE)
        return 1
    print(
        "DEMO PASSED — all scenario assertions held. Audit trail written to "
        f"{AuditLogger().path}"
    )
    print(RULE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
