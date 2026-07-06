"""Build the vector-store metadata filter from a user's context.

This is the *primary* access-control enforcement point: unauthorized chunks are
never returned by the vector store because the filter excludes them at query
time. The filter mirrors an OpenSearch ``bool`` query and is understood directly
by :class:`polyphemus.aws.mock_vector_store.MockVectorStore`.

Semantics (must stay consistent with :func:`polyphemus.authz.policy.evaluate`):

* ``terms(allowed_groups ∈ user.groups)`` — RBAC group intersection.
* ``classification_rank <= user_clearance_rank`` — ABAC scalar clearance.

Because the two confidential tiers share the top rank, the group intersection is
what keeps finance and HR separated even for equally-cleared users.
"""

from __future__ import annotations

from typing import Any

from polyphemus.models import CLASSIFICATION_RANK, UserContext


def build_filter(user: UserContext) -> dict[str, Any]:
    """Return an OpenSearch-style bool filter enforcing this user's access."""
    user_rank = CLASSIFICATION_RANK.get(user.clearance, 0)
    return {
        "bool": {
            "filter": [
                {"terms": {"allowed_groups": list(user.groups)}},
                {"range": {"classification_rank": {"lte": user_rank}}},
            ]
        }
    }


def describe_filter(user: UserContext) -> str:
    """Human-readable summary of the filter (for demo output / logs)."""
    user_rank = CLASSIFICATION_RANK.get(user.clearance, 0)
    return (
        f"allowed_groups ∈ {sorted(user.groups)} AND "
        f"classification_rank ≤ {user_rank} ({user.clearance})"
    )
