"""Append-only JSONL audit trail.

Each request produces one :class:`AuditRecord` written as a single JSON line to
``<audit_dir>/<audit_file>`` (mock/local) — in aws mode this would target a
CloudWatch Logs group and/or an object-locked S3 audit bucket.

The record captures the full security story: identity, original + redacted
prompt, retrieved vs denied sources, policy decisions, redaction events,
injection flags, and the response. The redacted fields never contain raw PII;
the ``prompt`` field holds the original and is documented as access-controlled
evidence (in aws mode the audit store is encrypted and tightly scoped by IAM).
"""

from __future__ import annotations

from pathlib import Path

from polyphemus.config import Settings, get_settings
from polyphemus.models import AuditRecord


class AuditLogger:
    """Writes and reads the JSONL audit trail."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._path = Path(self._settings.audit_dir) / self._settings.audit_file

    @property
    def path(self) -> Path:
        return self._path

    def write(self, record: AuditRecord) -> None:
        """Append one audit record as a JSON line (creates the dir if needed)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(record.to_jsonl() + "\n")

    def read_all(self) -> list[AuditRecord]:
        """Read every audit record from the log (for demo evidence printing)."""
        if not self._path.exists():
            return []
        records: list[AuditRecord] = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(AuditRecord.model_validate_json(line))
        return records

    def clear(self) -> None:
        """Delete the local audit log to start a clean demo/test run.

        DEMONSTRATION/TEST ONLY. An audit trail is tamper-evident *evidence*;
        deleting it is exactly what the accountability control exists to prevent.
        This helper only touches the local JSONL file used by the offline demo and
        the test suite. In ``aws`` mode the audit sink is CloudWatch Logs + an
        object-locked (WORM) S3 bucket, which cannot and must not be cleared this
        way — never wire this into a production/aws code path.
        """
        if self._path.exists():
            self._path.unlink()
