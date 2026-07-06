"""PII detectors.

Primary (offline default): regex + validation detectors for common PII entity
types. Each detector yields non-overlapping spans with an entity label. A
credit-card detector applies a Luhn check to avoid flagging arbitrary digit runs.

Enhanced (aws mode): :class:`ComprehendAdapter` calls Amazon Comprehend's
``detect_pii_entities`` for NER-grade entities. In mock mode it falls back to the
regex detectors so behavior is identical offline. Bedrock Guardrails PII
filtering is documented as the managed alternative in docs/SECURITY_CONTROLS.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from polyphemus.config import get_settings


@dataclass(frozen=True)
class Span:
    """A detected PII span."""

    start: int
    end: int
    entity_type: str
    text: str


# --- individual detectors ---------------------------------------------------
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
# Candidate 13-19 digit runs (optionally space/dash separated) — Luhn-validated.
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits if d.isdigit()]
    if len(nums) < 13:
        return False
    checksum = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def _find(regex: re.Pattern[str], text: str, label: str) -> list[Span]:
    return [Span(m.start(), m.end(), label, m.group(0)) for m in regex.finditer(text)]


def _find_credit_cards(text: str) -> list[Span]:
    spans: list[Span] = []
    for m in _CC_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        if _luhn_ok(raw):
            spans.append(Span(m.start(), m.end(), "CREDIT_CARD", raw))
    return spans


def detect_all(text: str) -> list[Span]:
    """Run every regex detector and return de-overlapped spans.

    Detection order establishes precedence when spans overlap (earlier = higher
    priority): specific structured identifiers before the greedy credit-card and
    phone matchers.
    """
    spans: list[Span] = []
    spans += _find(_SSN_RE, text, "US_SSN")
    spans += _find(_AWS_KEY_RE, text, "AWS_ACCESS_KEY")
    spans += _find(_IBAN_RE, text, "IBAN")
    spans += _find_credit_cards(text)
    spans += _find(_EMAIL_RE, text, "EMAIL")
    spans += _find(_PHONE_RE, text, "PHONE")
    return _dedupe_overlaps(spans)


def _dedupe_overlaps(spans: list[Span]) -> list[Span]:
    """Drop spans that overlap an earlier (higher-precedence) span."""
    kept: list[Span] = []
    spans_sorted = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    occupied: list[tuple[int, int]] = []
    for span in spans_sorted:
        if any(span.start < e and span.end > s for s, e in occupied):
            continue
        kept.append(span)
        occupied.append((span.start, span.end))
    return kept


class ComprehendAdapter:
    """Detect PII via Amazon Comprehend in aws mode; regex fallback in mock mode."""

    def __init__(self) -> None:
        self._settings = get_settings()

    def detect(self, text: str) -> list[Span]:
        if self._settings.is_mock:
            return detect_all(text)
        return self._detect_comprehend(text)

    def _detect_comprehend(self, text: str) -> list[Span]:  # pragma: no cover - aws only
        import boto3  # lazy import, aws mode only

        client = boto3.client("comprehend", region_name=self._settings.region)
        resp = client.detect_pii_entities(Text=text, LanguageCode="en")
        spans: list[Span] = []
        for ent in resp.get("Entities", []):
            spans.append(
                Span(
                    start=ent["BeginOffset"],
                    end=ent["EndOffset"],
                    entity_type=str(ent["Type"]),
                    text=text[ent["BeginOffset"] : ent["EndOffset"]],
                )
            )
        # Union with regex detectors for structured tokens Comprehend may miss.
        return _dedupe_overlaps(spans + detect_all(text))
