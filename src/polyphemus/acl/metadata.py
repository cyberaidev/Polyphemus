"""ACL metadata schema builder and validation.

The metadata attached to each chunk is what the query-time filter operates on.
It is deliberately small and explicit:

* ``allowed_groups`` — RBAC: IdP groups permitted to read the chunk.
* ``classification`` — ABAC: sensitivity tier.
* ``department``     — ABAC: owning department.
* ``source_uri``     — provenance for audit and citation.

Validation is fail-closed: a chunk missing ``allowed_groups`` or
``classification`` is rejected rather than treated as public.
"""

from __future__ import annotations

from typing import get_args

from polyphemus.models import Classification, Document

VALID_CLASSIFICATIONS: frozenset[str] = frozenset(get_args(Classification))


class ACLValidationError(ValueError):
    """Raised when ACL metadata is missing or invalid (fail-closed)."""


def build_chunk_metadata(doc: Document) -> dict[str, object]:
    """Extract the ACL metadata to copy onto each chunk of ``doc``."""
    metadata: dict[str, object] = {
        "department": doc.department,
        "classification": doc.classification,
        "allowed_groups": list(doc.allowed_groups),
        "source_uri": doc.source_uri,
    }
    validate_metadata(metadata)
    return metadata


def validate_metadata(metadata: dict[str, object]) -> None:
    """Fail closed if required ACL fields are absent or malformed."""
    allowed_groups = metadata.get("allowed_groups")
    if not allowed_groups or not isinstance(allowed_groups, list):
        raise ACLValidationError("allowed_groups must be a non-empty list")

    classification = metadata.get("classification")
    if classification not in VALID_CLASSIFICATIONS:
        raise ACLValidationError(
            f"classification {classification!r} not in {sorted(VALID_CLASSIFICATIONS)}"
        )

    if not metadata.get("department"):
        raise ACLValidationError("department is required")

    if not metadata.get("source_uri"):
        raise ACLValidationError("source_uri is required for provenance")
