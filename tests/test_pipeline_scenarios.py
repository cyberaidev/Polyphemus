"""The four demo scenarios encoded as assertions (mirrors run_demo.py)."""

from __future__ import annotations

from polyphemus.aws.mock_bedrock import SYSTEM_PROMPT_SECRET_MARKER

FINANCE_QUERY = "What were the recent vendor payments this quarter?"
INVOICE_QUERY = "Summarize the Aperture vendor invoice."


def test_scenario_1_finance_user_gets_finance_docs_with_pii_redacted(pipeline, users):
    rec = pipeline.answer(users["finance_user"], FINANCE_QUERY)
    assert any("finance/" in u for u in rec.retrieved_sources)
    assert not any("hr/" in u for u in rec.retrieved_sources)
    pii = {e.entity_type for e in rec.redactions}
    # vendor_payments.md carries exactly these five structured PII types; pin them
    # rather than a loose count so a detector regression is caught precisely.
    assert {"US_SSN", "EMAIL", "PHONE", "IBAN", "CREDIT_CARD"} <= pii


def test_scenario_2_hr_user_denied_finance_docs(pipeline, users):
    rec = pipeline.answer(users["hr_user"], FINANCE_QUERY)
    assert not any("finance/" in u for u in rec.retrieved_sources)
    assert any("finance/" in u for u in rec.denied_sources)
    assert "authorized information" in rec.response.lower()


def test_scenario_3_injection_detected_and_neutralized(pipeline, users):
    rec = pipeline.answer(users["finance_user"], INVOICE_QUERY)
    # All six scanner rules the payload trips are flagged (matches README/DEMO).
    for flag in (
        "data_listing",
        "exfiltration",
        "override_instruction",
        "prompt_exfiltration",
        "role_hijack",
        "system_role_injection",
    ):
        assert flag in rec.injection_flags, flag
    assert SYSTEM_PROMPT_SECRET_MARKER not in rec.response
    assert "attacker@evil.example" not in rec.response
    assert not any("hr/" in u for u in rec.retrieved_sources)


def test_scenario_3_contrast_defenses_disabled_is_vulnerable(pipeline_unsafe, users):
    rec = pipeline_unsafe.answer(users["attacker"], INVOICE_QUERY)
    assert SYSTEM_PROMPT_SECRET_MARKER in rec.response
    assert rec.defenses_enabled is False


def test_scenario_4_audit_trail_complete(pipeline, users, audit_logger):
    pipeline.answer(users["finance_user"], FINANCE_QUERY)
    pipeline.answer(users["hr_user"], FINANCE_QUERY)
    pipeline.answer(users["finance_user"], INVOICE_QUERY)
    records = audit_logger.read_all()
    assert len(records) == 3
    for rec in records:
        assert rec.request_id and rec.timestamp and rec.model_id
        assert rec.user.username
    # The middle record proves the deny for the HR user.
    hr_rec = records[1]
    assert any("finance/" in u for u in hr_rec.denied_sources)
