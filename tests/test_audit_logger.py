"""Audit record schema completeness and JSONL round-trip."""

from __future__ import annotations

import json

from polyphemus.models import AuditRecord


def test_audit_record_has_required_fields(pipeline, users, audit_logger):
    rec = pipeline.answer(users["finance_user"], "vendor payments this quarter")
    for field in (
        "request_id",
        "timestamp",
        "user",
        "prompt",
        "redacted_prompt",
        "retrieved_sources",
        "denied_sources",
        "policy_decisions",
        "redactions",
        "injection_flags",
        "model_id",
        "response",
    ):
        assert hasattr(rec, field)
    assert rec.request_id
    assert rec.timestamp.endswith("+00:00") or "T" in rec.timestamp
    assert rec.model_id


def test_audit_jsonl_round_trip(pipeline, users):
    rec = pipeline.answer(users["finance_user"], "vendor payments")
    line = rec.to_jsonl()
    parsed = json.loads(line)
    assert parsed["request_id"] == rec.request_id
    restored = AuditRecord.model_validate_json(line)
    assert restored.response == rec.response
    assert restored.user.username == rec.user.username


def test_audit_written_and_readable(pipeline, users, audit_logger):
    pipeline.answer(users["finance_user"], "vendor payments")
    pipeline.answer(users["hr_user"], "PTO policy")
    records = audit_logger.read_all()
    assert len(records) == 2
    assert audit_logger.path.exists()


def test_denied_sources_recorded_for_denied_user(pipeline, users):
    rec = pipeline.answer(users["hr_user"], "vendor payments and Q3 earnings")
    assert any("finance/" in u for u in rec.denied_sources)


def test_redactions_captured_in_audit(pipeline, users):
    rec = pipeline.answer(users["finance_user"], "vendor payments this quarter")
    kinds = {e.entity_type for e in rec.redactions}
    assert "US_SSN" in kinds  # vendor_payments.md contains an SSN


def test_original_prompt_preserved_but_redacted_field_scrubbed(pipeline, users):
    rec = pipeline.answer(users["finance_user"], "my ssn is 123-45-6789 what are payments?")
    assert "123-45-6789" in rec.prompt  # original retained as access-controlled evidence
    assert "123-45-6789" not in rec.redacted_prompt  # scrubbed before model saw it
    assert "[REDACTED_US_SSN]" in rec.redacted_prompt
