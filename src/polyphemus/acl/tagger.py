"""Attach validated ACL metadata to chunks at ingest time.

Chunking copies most ACL fields already; the tagger re-validates every chunk so
that a chunk which somehow lost its ``allowed_groups`` or ``classification`` is
caught before it can be indexed (fail-closed).
"""

from __future__ import annotations

from polyphemus.acl.metadata import ACLValidationError, validate_metadata
from polyphemus.models import Chunk


def tag_chunks(chunks: list[Chunk]) -> list[Chunk]:
    """Validate ACL metadata on every chunk; raise if any is under-specified."""
    for chunk in chunks:
        validate_metadata(
            {
                "allowed_groups": chunk.allowed_groups,
                "classification": chunk.classification,
                "department": chunk.department,
                "source_uri": chunk.source_uri,
            }
        )
    return chunks


def assert_no_untagged(chunks: list[Chunk]) -> None:
    """Raise if any chunk is missing its access-control metadata."""
    for chunk in chunks:
        if not chunk.allowed_groups:
            raise ACLValidationError(f"chunk {chunk.chunk_id} has no allowed_groups")
