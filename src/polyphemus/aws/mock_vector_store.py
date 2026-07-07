"""In-memory vector store with query-time metadata filtering.

This fake mirrors the semantics of Amazon OpenSearch Serverless vector search:
``upsert`` stores chunks with their ACL metadata, and ``query`` ranks by cosine
similarity **after** applying a bool metadata filter. The metadata filter is the
primary access-control enforcement point — unauthorized chunks are never
returned, exactly as an OpenSearch ``bool.filter`` would exclude them.

Filter grammar (a subset that mirrors OpenSearch bool queries)::

    {
      "bool": {
        "filter": [
          {"terms": {"allowed_groups": ["finance", "admin"]}},
          {"bool": {"should": [
              {"range": {"classification_rank": {"lte": 1}}},
              {"terms": {"classification": ["finance_confidential"]}}
          ]}}
        ]
      }
    }

The mock understands ``terms`` (list intersection is non-empty) and ``range``
(numeric ``classification_rank`` comparison), combined with ``bool.filter`` (AND)
and ``bool.should`` (OR).
"""

from __future__ import annotations

import math
from typing import Any

from polyphemus.models import CLASSIFICATION_RANK, UNKNOWN_CLASSIFICATION_RANK, Chunk


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two equal-length vectors; 0.0 if either is zero."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class MockVectorStore:
    """A list-backed vector index with metadata filtering and cosine ranking."""

    def __init__(self) -> None:
        self._chunks: dict[str, Chunk] = {}

    # -- ingestion -----------------------------------------------------------
    def upsert(self, chunks: list[Chunk]) -> int:
        """Insert or replace chunks by ``chunk_id``. Returns count stored."""
        for chunk in chunks:
            self._chunks[chunk.chunk_id] = chunk
        return len(self._chunks)

    def count(self) -> int:
        return len(self._chunks)

    def all_source_uris(self) -> set[str]:
        return {c.source_uri for c in self._chunks.values()}

    # -- query ---------------------------------------------------------------
    def query(
        self,
        vector: list[float],
        k: int,
        metadata_filter: dict[str, Any] | None = None,
        similarity_floor: float = 0.0,
    ) -> list[tuple[Chunk, float]]:
        """Return up to ``k`` (chunk, score) pairs that pass the metadata filter.

        The metadata filter is applied *before* ranking so unauthorized chunks
        are never scored or returned — this is the enforced query-time control.
        """
        candidates: list[tuple[Chunk, float]] = []
        for chunk in self._chunks.values():
            if metadata_filter and not _matches_filter(chunk, metadata_filter):
                continue
            score = cosine_similarity(vector, chunk.embedding or [])
            if score < similarity_floor:
                continue
            candidates.append((chunk, score))
        candidates.sort(key=lambda pair: pair[1], reverse=True)
        return candidates[:k]

    def query_unfiltered(
        self, vector: list[float], k: int, similarity_floor: float = 0.0
    ) -> list[tuple[Chunk, float]]:
        """Rank without any ACL filter — used only to demonstrate the control's value."""
        return self.query(vector, k, metadata_filter=None, similarity_floor=similarity_floor)


# --- filter evaluation ------------------------------------------------------
def _chunk_field(chunk: Chunk, field: str) -> Any:
    """Resolve a filter field name against a chunk (incl. synthetic fields)."""
    if field == "classification_rank":
        # Fail closed: an unknown classification is ranked above every real tier
        # so a `range { lte: user_rank }` filter can never admit it. (Using 0 here
        # would fail OPEN and leak corrupt chunks to any user.)
        return CLASSIFICATION_RANK.get(chunk.classification, UNKNOWN_CLASSIFICATION_RANK)
    return getattr(chunk, field, None)


def _matches_filter(chunk: Chunk, node: dict[str, Any]) -> bool:
    """Recursively evaluate a bool/terms/range filter node against a chunk."""
    if "bool" in node:
        b = node["bool"]
        if "filter" in b:  # all must match (AND)
            if not all(_matches_filter(chunk, sub) for sub in b["filter"]):
                return False
        if "must" in b:
            if not all(_matches_filter(chunk, sub) for sub in b["must"]):
                return False
        if "should" in b:  # at least one must match (OR)
            if not any(_matches_filter(chunk, sub) for sub in b["should"]):
                return False
        if "must_not" in b:
            if any(_matches_filter(chunk, sub) for sub in b["must_not"]):
                return False
        return True

    if "terms" in node:
        ((field, wanted),) = node["terms"].items()
        actual = _chunk_field(chunk, field)
        if isinstance(actual, list):
            return bool(set(actual) & set(wanted))
        return actual in set(wanted)

    if "term" in node:
        ((field, wanted),) = node["term"].items()
        return _chunk_field(chunk, field) == wanted

    if "range" in node:
        ((field, bounds),) = node["range"].items()
        value = _chunk_field(chunk, field)
        if value is None:
            return False
        if "lte" in bounds and not value <= bounds["lte"]:
            return False
        if "gte" in bounds and not value >= bounds["gte"]:
            return False
        if "lt" in bounds and not value < bounds["lt"]:
            return False
        if "gt" in bounds and not value > bounds["gt"]:
            return False
        return True

    # Unknown node types fail closed (deny) rather than silently matching.
    return False
