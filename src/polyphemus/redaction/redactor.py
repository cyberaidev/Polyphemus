"""Redact detected PII with typed placeholders.

Redaction is applied to the retrieved **context** and to the **user prompt**
*before* the model is invoked (see :mod:`polyphemus.pipeline`). Each replaced
entity becomes a ``[REDACTED_<TYPE>]`` placeholder, and every redaction is
recorded as a :class:`RedactionEvent` so the audit trail shows what fired.
"""

from __future__ import annotations

from collections import Counter

from polyphemus.models import RedactionEvent
from polyphemus.redaction.detectors import ComprehendAdapter


class Redactor:
    """Detects and masks PII, returning redacted text plus event records."""

    def __init__(self, adapter: ComprehendAdapter | None = None) -> None:
        self._adapter = adapter or ComprehendAdapter()

    def redact(self, text: str, location: str) -> tuple[str, list[RedactionEvent]]:
        """Return ``(redacted_text, events)`` for ``text`` at ``location``.

        Args:
            text: the input to scrub.
            location: "prompt" or "context" — recorded on each event.
        """
        spans = self._adapter.detect(text)
        if not spans:
            return text, []

        # Replace right-to-left so earlier offsets remain valid.
        spans_sorted = sorted(spans, key=lambda s: s.start, reverse=True)
        redacted = text
        counts: Counter[str] = Counter()
        for span in spans_sorted:
            placeholder = f"[REDACTED_{span.entity_type}]"
            redacted = redacted[: span.start] + placeholder + redacted[span.end :]
            counts[span.entity_type] += 1

        events = [
            RedactionEvent(entity_type=etype, count=n, location=location)
            for etype, n in sorted(counts.items())
        ]
        return redacted, events


def redact_text(text: str, location: str) -> tuple[str, list[RedactionEvent]]:
    """Convenience wrapper around :class:`Redactor`."""
    return Redactor().redact(text, location)
