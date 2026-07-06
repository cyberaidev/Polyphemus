"""Authorization-aware retrieval with two enforcement layers.

1. **Filter-at-query-time (primary):** the metadata filter from
   :func:`polyphemus.authz.query_filter.build_filter` is passed to the vector
   store, so unauthorized chunks are never even scored.

2. **Post-retrieval re-check (defense-in-depth):** every returned chunk is
   re-evaluated with :func:`polyphemus.authz.policy.evaluate`. Anything that
   somehow slips through (e.g. a misconfigured index filter) is dropped and its
   ``source_uri`` recorded in ``denied_sources``. This proves enforcement is not
   solely dependent on the index configuration.

The retriever additionally reports the sources it *would* have surfaced without
the filter, so the audit trail can show exactly which documents were withheld.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from polyphemus.authz import policy
from polyphemus.authz.query_filter import build_filter
from polyphemus.aws.clients import get_vector_store
from polyphemus.config import get_settings
from polyphemus.models import RetrievalResult, UserContext
from polyphemus.retrieval.embedder import embed_query


@dataclass
class RetrievalOutcome:
    """Everything retrieval produced, including evidence of denials."""

    authorized: list[RetrievalResult] = field(default_factory=list)
    denied_sources: list[str] = field(default_factory=list)

    @property
    def authorized_sources(self) -> list[str]:
        seen: list[str] = []
        for r in self.authorized:
            if r.chunk.source_uri not in seen:
                seen.append(r.chunk.source_uri)
        return seen


def retrieve(user: UserContext, query: str) -> RetrievalOutcome:
    """Retrieve chunks for ``query`` that ``user`` is authorized to read."""
    settings = get_settings()
    store = get_vector_store(settings)

    query_vec = embed_query(query)
    metadata_filter = build_filter(user)

    # Layer 1: query-time filter — unauthorized chunks are never returned.
    filtered_hits = store.query(
        query_vec,
        k=settings.top_k,
        metadata_filter=metadata_filter,
        similarity_floor=settings.similarity_floor,
    )

    outcome = RetrievalOutcome()
    for chunk, score in filtered_hits:
        # Layer 2: independent policy re-check (defense in depth).
        decision = policy.evaluate(user, chunk)
        if decision.allowed:
            outcome.authorized.append(RetrievalResult(chunk=chunk, score=score, decision=decision))
        else:
            if chunk.source_uri not in outcome.denied_sources:
                outcome.denied_sources.append(chunk.source_uri)

    # Evidence: which relevant sources were withheld purely by the ACL filter.
    # We rank the whole corpus without the filter and record any relevant source
    # the user was NOT authorized to see, so scenario 2 can prove the deny.
    unfiltered_hits = store.query(
        query_vec,
        k=settings.top_k,
        metadata_filter=None,
        similarity_floor=settings.similarity_floor,
    )
    authorized_uris = set(outcome.authorized_sources)
    for chunk, _score in unfiltered_hits:
        decision = policy.evaluate(user, chunk)
        if not decision.allowed and chunk.source_uri not in authorized_uris:
            if chunk.source_uri not in outcome.denied_sources:
                outcome.denied_sources.append(chunk.source_uri)

    return outcome
