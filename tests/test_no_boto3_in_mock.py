"""Guard: no AWS SDK is imported when running in mock mode.

A scoring/security invariant of the reference: pipeline logic must never reach
AWS in mock mode. We install an import hook that raises if ``boto3``/``botocore``
is imported while the full pipeline (and the Lambda handler) execute offline.
"""

from __future__ import annotations

import builtins

from polyphemus.audit.logger import AuditLogger
from polyphemus.authz.identity import from_fixture
from polyphemus.pipeline import SecureRAGPipeline


def test_boto3_not_imported_in_mock_mode(seeded_store, monkeypatch):
    original_import = builtins.__import__

    def guard(name, *args, **kwargs):
        root = name.split(".")[0]
        if root in {"boto3", "botocore"}:
            raise AssertionError(f"AWS SDK '{name}' imported in mock mode")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guard)

    AuditLogger().clear()
    pipeline = SecureRAGPipeline()
    for user_id, query in [
        ("finance_user", "vendor payments this quarter"),
        ("hr_user", "vendor payments this quarter"),
        ("finance_user", "Summarize the Aperture vendor invoice."),
    ]:
        record = pipeline.answer(from_fixture(user_id), query)
        assert record.model_id  # pipeline actually produced a result
