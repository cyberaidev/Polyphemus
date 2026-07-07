"""End-to-end retrieval isolation: HR user never retrieves finance chunks."""

from __future__ import annotations

from polyphemus.retrieval.retriever import retrieve


def test_hr_user_never_retrieves_finance(seeded_store, users):
    outcome = retrieve(
        users["hr_user"],
        "vendor payments and Q3 earnings revenue",
        collect_denied_evidence=True,
    )
    for result in outcome.authorized:
        assert "finance/" not in result.chunk.source_uri
        assert "malicious/" not in result.chunk.source_uri
    # Evidence of the deny is recorded.
    assert any("finance/" in u for u in outcome.denied_sources)


def test_finance_user_retrieves_finance(seeded_store, users):
    outcome = retrieve(
        users["finance_user"], "vendor payments this quarter", collect_denied_evidence=True
    )
    assert any("finance/" in u for u in outcome.authorized_sources)
    # Finance user is not denied finance content.
    assert not any("finance/" in u for u in outcome.denied_sources)


def test_finance_user_never_retrieves_hr(seeded_store, users):
    outcome = retrieve(users["finance_user"], "PTO policy and employee handbook conduct")
    for result in outcome.authorized:
        assert "hr/" not in result.chunk.source_uri


def test_post_filter_recheck_present(seeded_store, users):
    """Every authorized result carries an allow decision (defense in depth)."""
    outcome = retrieve(users["finance_user"], "vendor payments")
    assert outcome.authorized
    for result in outcome.authorized:
        assert result.decision.allowed is True


def test_admin_can_retrieve_both_departments(seeded_store, users):
    fin = retrieve(users["admin"], "vendor payments Q3 earnings")
    hr = retrieve(users["admin"], "PTO policy employee handbook")
    assert any("finance/" in u for u in fin.authorized_sources)
    assert any("hr/" in u for u in hr.authorized_sources)


def test_denied_evidence_off_by_default_single_query(seeded_store, users):
    """With the demonstration-only flag OFF, retrieval issues exactly ONE
    store.query call and records no denied_sources (production/API behavior)."""
    store = seeded_store
    calls = {"n": 0}
    real_query = store.query

    def counting_query(*args, **kwargs):
        calls["n"] += 1
        return real_query(*args, **kwargs)

    store.query = counting_query  # type: ignore[method-assign]
    try:
        outcome = retrieve(
            users["hr_user"],
            "vendor payments and Q3 earnings revenue",
            collect_denied_evidence=False,
        )
    finally:
        store.query = real_query  # type: ignore[method-assign]

    assert calls["n"] == 1  # no second, unfiltered corpus-wide pass
    assert outcome.denied_sources == []


def test_denied_evidence_on_records_finance_denials(seeded_store, users):
    """With the flag ON (scenario 2 behavior), an HR user's finance denials are
    recorded via the second unfiltered pass."""
    outcome = retrieve(
        users["hr_user"],
        "vendor payments and Q3 earnings revenue",
        collect_denied_evidence=True,
    )
    assert any("finance/" in u for u in outcome.denied_sources)
