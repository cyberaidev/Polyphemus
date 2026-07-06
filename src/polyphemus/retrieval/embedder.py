"""Embed text via Bedrock (or the deterministic mock).

The embedder only knows the abstract Bedrock interface (``embed``) obtained from
:mod:`polyphemus.aws.clients`; it does not care whether the backend is real or
mocked. Vectors are used directly by the vector store's cosine ranking.
"""

from __future__ import annotations

from polyphemus.aws.clients import get_bedrock
from polyphemus.config import get_settings


def embed_query(text: str) -> list[float]:
    """Return the embedding vector for a query string."""
    bedrock = get_bedrock(get_settings())
    return bedrock.embed(text)


def embed_chunks(texts: list[str]) -> list[list[float]]:
    """Embed a batch of chunk texts (used during seeding)."""
    bedrock = get_bedrock(get_settings())
    return [bedrock.embed(t) for t in texts]
