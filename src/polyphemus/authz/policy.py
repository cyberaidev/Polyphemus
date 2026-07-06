"""The access-control decision engine.

Model: RBAC (group intersection) + ABAC (clearance rank), evaluated fail-closed.

Rules, in order:

1. ``deny_no_group`` — if the user's groups and the chunk's ``allowed_groups``
   do not intersect, DENY. This is the primary RBAC gate.
2. ``clearance_lt`` — if the chunk's classification rank exceeds the user's
   clearance rank, DENY. This is the ABAC gate for the public/internal tiers.
   (The two confidential tiers share the top rank and are separated by group
   membership handled in rule 1.)
3. Otherwise ALLOW via ``group_intersection`` (department match noted as ABAC
   context in the rationale).

The same engine backs both enforcement layers: the query filter derives from it,
and the post-retrieval re-check calls :func:`evaluate` directly.
"""

from __future__ import annotations

from polyphemus.models import CLASSIFICATION_RANK, Chunk, PolicyDecision, UserContext


def evaluate(user: UserContext, chunk: Chunk) -> PolicyDecision:
    """Decide whether ``user`` may read ``chunk`` (fail-closed)."""
    user_groups = set(user.groups)
    chunk_groups = set(chunk.allowed_groups)

    # Rule 1: RBAC group intersection (fail closed on empty intersection).
    intersection = user_groups & chunk_groups
    if not intersection:
        return PolicyDecision(
            allowed=False,
            reason=(
                f"user groups {sorted(user_groups)} do not intersect "
                f"chunk allowed_groups {sorted(chunk_groups)}"
            ),
            matched_rule="deny_no_group",
            source_uri=chunk.source_uri,
        )

    # Rule 2: ABAC clearance rank for the scalar tiers.
    chunk_rank = CLASSIFICATION_RANK.get(chunk.classification, 99)
    user_rank = CLASSIFICATION_RANK.get(user.clearance, 0)
    if chunk_rank > user_rank:
        return PolicyDecision(
            allowed=False,
            reason=(
                f"chunk classification {chunk.classification!r} exceeds user "
                f"clearance {user.clearance!r}"
            ),
            matched_rule="clearance_lt",
            source_uri=chunk.source_uri,
        )

    # Allow. Note department match as an ABAC signal in the rationale.
    dept_note = ""
    if user.department and chunk.department:
        dept_note = (
            f"; department {'match' if user.department == chunk.department else 'cross'} "
            f"({user.department} vs {chunk.department})"
        )
    return PolicyDecision(
        allowed=True,
        reason=f"group intersection {sorted(intersection)} satisfied{dept_note}",
        matched_rule="group_intersection",
        source_uri=chunk.source_uri,
    )
