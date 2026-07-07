"""RBAC/ABAC decision-engine correctness (allow/deny matrix)."""

from __future__ import annotations

import pytest

from polyphemus.authz import policy
from polyphemus.authz.identity import from_fixture
from polyphemus.models import Chunk


def _chunk(classification: str, allowed_groups: list[str], department: str) -> Chunk:
    return Chunk(
        chunk_id="c#0",
        doc_id="d",
        text="x",
        department=department,
        classification=classification,  # type: ignore[arg-type]
        allowed_groups=allowed_groups,
        source_uri=f"file://{department}/doc.md",
    )


FINANCE = _chunk("finance_confidential", ["finance", "admin"], "finance")
HR = _chunk("hr_confidential", ["hr", "admin"], "hr")
INTERNAL = _chunk("internal", ["finance", "hr", "admin", "staff"], "general")


@pytest.mark.parametrize(
    "user_id,chunk,expected",
    [
        ("finance_user", FINANCE, True),
        ("finance_user", HR, False),
        ("finance_user", INTERNAL, True),
        ("hr_user", FINANCE, False),
        ("hr_user", HR, True),
        ("hr_user", INTERNAL, True),
        ("admin", FINANCE, True),
        ("admin", HR, True),
        ("staff_user", FINANCE, False),
        ("staff_user", HR, False),
        ("staff_user", INTERNAL, True),
    ],
)
def test_allow_deny_matrix(user_id, chunk, expected):
    user = from_fixture(user_id)
    decision = policy.evaluate(user, chunk)
    assert decision.allowed is expected


def test_deny_no_group_rule_name():
    user = from_fixture("hr_user")
    decision = policy.evaluate(user, FINANCE)
    assert decision.matched_rule == "deny_no_group"
    assert not decision.allowed


def test_allow_rule_name_and_reason():
    user = from_fixture("finance_user")
    decision = policy.evaluate(user, FINANCE)
    assert decision.matched_rule == "group_intersection"
    assert "finance" in decision.reason


def test_clearance_gate_blocks_low_clearance():
    """A staff user (internal clearance) is denied a confidential chunk even if
    the group somehow matched, via the clearance rank gate."""
    weird = _chunk("finance_confidential", ["staff"], "finance")
    user = from_fixture("staff_user")  # clearance=internal
    decision = policy.evaluate(user, weird)
    assert not decision.allowed
    assert decision.matched_rule == "clearance_lt"


def test_fail_closed_on_empty_groups():
    user = from_fixture("finance_user")
    empty = _chunk("internal", [], "general")
    # allowed_groups empty -> no intersection -> deny
    decision = policy.evaluate(user, empty)
    assert not decision.allowed
    assert decision.matched_rule == "deny_no_group"


def test_unknown_classification_fails_closed_in_policy():
    """A chunk with a classification outside the known set is DENIED by the policy
    engine even when the group intersection succeeds (shared fail-closed rank)."""
    user = from_fixture("finance_user")
    # model_construct bypasses the Literal validation to simulate corrupt data.
    corrupt = Chunk.model_construct(
        chunk_id="c#0",
        doc_id="d",
        text="x",
        department="finance",
        classification="top_secret",  # not in Classification
        allowed_groups=["finance"],  # group WOULD match — clearance must still deny
        source_uri="file://finance/corrupt.md",
    )
    decision = policy.evaluate(user, corrupt)
    assert not decision.allowed
    assert decision.matched_rule == "clearance_lt"
