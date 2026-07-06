"""Each PII entity type is detected and redacted."""

from __future__ import annotations

import pytest

from polyphemus.redaction.detectors import detect_all
from polyphemus.redaction.redactor import Redactor


@pytest.mark.parametrize(
    "text,entity",
    [
        ("SSN on file: 123-45-6789 here", "US_SSN"),
        ("reach me at jane.doe@example.com please", "EMAIL"),
        ("call +1 (415) 555-0173 today", "PHONE"),
        ("IBAN GB29 NWBK 6016 1331 9268 19 confirmed", "IBAN"),
        ("key AKIAIOSFODNN7EXAMPLE leaked", "AWS_ACCESS_KEY"),
        ("card 4111 1111 1111 1111 charged", "CREDIT_CARD"),
    ],
)
def test_detect_entity_types(text, entity):
    types = {s.entity_type for s in detect_all(text)}
    assert entity in types


def test_at_least_five_entity_types_supported():
    sample = (
        "SSN 123-45-6789, email a@b.com, phone +1 (415) 555-0173, "
        "IBAN GB29 NWBK 6016 1331 9268 19, card 4111 1111 1111 1111, "
        "key AKIAIOSFODNN7EXAMPLE"
    )
    types = {s.entity_type for s in detect_all(sample)}
    assert len(types) >= 5


def test_redactor_replaces_with_typed_placeholders():
    text = "SSN 123-45-6789 and email a@b.com"
    redacted, events = Redactor().redact(text, "context")
    assert "123-45-6789" not in redacted
    assert "a@b.com" not in redacted
    assert "[REDACTED_US_SSN]" in redacted
    assert "[REDACTED_EMAIL]" in redacted
    kinds = {e.entity_type for e in events}
    assert {"US_SSN", "EMAIL"} <= kinds
    assert all(e.location == "context" for e in events)


def test_luhn_rejects_invalid_card():
    # 4111 1111 1111 1112 fails Luhn and must NOT be flagged as a card.
    types = {s.entity_type for s in detect_all("num 4111 1111 1111 1112")}
    assert "CREDIT_CARD" not in types


def test_no_false_positive_on_clean_text():
    redacted, events = Redactor().redact("The quarterly report looks great.", "prompt")
    assert events == []
    assert redacted == "The quarterly report looks great."


def test_redaction_events_count_multiple():
    text = "emails a@b.com and c@d.com"
    _, events = Redactor().redact(text, "context")
    email_events = [e for e in events if e.entity_type == "EMAIL"]
    assert email_events and email_events[0].count == 2
