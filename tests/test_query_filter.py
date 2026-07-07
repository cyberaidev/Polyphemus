"""The query-time filter built from claims excludes unauthorized metadata."""

from __future__ import annotations

from polyphemus.authz.identity import from_fixture
from polyphemus.authz.query_filter import build_filter
from polyphemus.aws.mock_vector_store import _matches_filter
from polyphemus.models import Chunk


def _chunk(classification, groups, dept) -> Chunk:
    return Chunk(
        chunk_id="c",
        doc_id="d",
        text="t",
        department=dept,
        classification=classification,
        allowed_groups=groups,
        source_uri=f"file://{dept}/d.md",
    )


def test_filter_shape():
    f = build_filter(from_fixture("finance_user"))
    assert "bool" in f and "filter" in f["bool"]
    terms = f["bool"]["filter"][0]["terms"]["allowed_groups"]
    assert terms == ["finance"]


def test_finance_filter_matches_finance_chunk():
    user = from_fixture("finance_user")
    f = build_filter(user)
    finance = _chunk("finance_confidential", ["finance", "admin"], "finance")
    assert _matches_filter(finance, f) is True


def test_finance_filter_excludes_hr_chunk():
    user = from_fixture("finance_user")
    f = build_filter(user)
    hr = _chunk("hr_confidential", ["hr", "admin"], "hr")
    assert _matches_filter(hr, f) is False


def test_hr_filter_excludes_finance_chunk():
    user = from_fixture("hr_user")
    f = build_filter(user)
    finance = _chunk("finance_confidential", ["finance", "admin"], "finance")
    assert _matches_filter(finance, f) is False


def test_staff_clearance_excludes_confidential():
    user = from_fixture("staff_user")  # clearance internal
    f = build_filter(user)
    # Even a chunk that (wrongly) lists staff is excluded by classification rank.
    confidential = _chunk("finance_confidential", ["staff"], "finance")
    assert _matches_filter(confidential, f) is False


def test_internal_chunk_visible_to_all_listed_groups():
    for uid in ("finance_user", "hr_user", "staff_user"):
        user = from_fixture(uid)
        f = build_filter(user)
        internal = _chunk("internal", ["finance", "hr", "staff", "admin"], "general")
        assert _matches_filter(internal, f) is True


def test_unknown_classification_fails_closed_in_filter():
    """A chunk whose classification is outside the known set must be EXCLUDED by
    the query-time filter for a normal user (fail-closed, not fail-open)."""
    user = from_fixture("finance_user")
    f = build_filter(user)
    # model_construct bypasses the Literal validation to simulate a corrupt/
    # unexpected classification value reaching the store.
    corrupt = Chunk.model_construct(
        chunk_id="c",
        doc_id="d",
        text="t",
        department="finance",
        classification="top_secret",  # not in Classification
        allowed_groups=["finance"],
        source_uri="file://finance/corrupt.md",
    )
    assert _matches_filter(corrupt, f) is False
