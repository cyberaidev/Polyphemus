"""Shared pytest fixtures.

Every test runs in mock mode with a freshly seeded store, an isolated audit log
(redirected to a temp directory), and cleared client/settings caches so state
never leaks between tests.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure mock mode before any polyphemus import reads settings.
os.environ["POLYPHEMUS_MODE"] = "mock"

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts"))

from polyphemus.audit.logger import AuditLogger  # noqa: E402
from polyphemus.authz.identity import from_fixture  # noqa: E402
from polyphemus.aws import clients as aws_clients  # noqa: E402
from polyphemus.config import get_settings, reset_settings_cache  # noqa: E402
from polyphemus.pipeline import SecureRAGPipeline  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Reset caches and redirect the audit log to a temp dir for each test."""
    reset_settings_cache()
    aws_clients.reset_mock_clients()
    monkeypatch.setenv("POLYPHEMUS_MODE", "mock")
    monkeypatch.setenv("POLYPHEMUS_AUDIT_DIR", str(tmp_path / "audit"))
    reset_settings_cache()
    yield
    reset_settings_cache()
    aws_clients.reset_mock_clients()


@pytest.fixture()
def settings():
    return get_settings()


@pytest.fixture()
def seeded_store():
    """Seed the mock vector store and return it."""
    from seed_store import seed  # local import so path is set

    seed()
    return aws_clients.get_vector_store()


@pytest.fixture()
def audit_logger():
    return AuditLogger()


@pytest.fixture()
def pipeline(seeded_store):
    """A pipeline over a freshly seeded store, defenses ON."""
    return SecureRAGPipeline()


@pytest.fixture()
def pipeline_unsafe(seeded_store):
    """A pipeline with injection defenses DISABLED (for contrast tests)."""
    return SecureRAGPipeline(defenses_enabled=False)


@pytest.fixture()
def users():
    """Named demo user contexts."""
    return {
        name: from_fixture(name)
        for name in ("finance_user", "hr_user", "admin", "attacker", "staff_user")
    }
