#!/usr/bin/env python3
"""Seed the (mock) vector store from the sample corpus.

Steps: upload sample docs to (mock) S3 -> load Documents -> chunk (copying ACL
metadata) -> validate ACL tagging (fail closed) -> embed -> upsert into the
vector store. Runs fully offline in mock mode.

Usage:
    POLYPHEMUS_MODE=mock python scripts/seed_store.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make ``src`` importable when run directly from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

os.environ.setdefault("POLYPHEMUS_MODE", "mock")

from polyphemus.acl.tagger import assert_no_untagged, tag_chunks  # noqa: E402
from polyphemus.aws.clients import get_vector_store  # noqa: E402
from polyphemus.chunking.chunker import chunk_documents  # noqa: E402
from polyphemus.config import get_settings  # noqa: E402
from polyphemus.ingestion.uploader import upload_sample_documents  # noqa: E402
from polyphemus.retrieval.embedder import embed_chunks  # noqa: E402


def seed(include_malicious: bool = True) -> int:
    """Seed the vector store and return the number of chunks indexed."""
    settings = get_settings()

    documents = upload_sample_documents(include_malicious=include_malicious)
    chunks = chunk_documents(documents, size=settings.chunk_size, overlap=settings.chunk_overlap)

    # Fail closed: every chunk must carry ACL metadata before indexing.
    tag_chunks(chunks)
    assert_no_untagged(chunks)

    embeddings = embed_chunks([c.text for c in chunks])
    for chunk, vec in zip(chunks, embeddings, strict=True):
        chunk.embedding = vec

    store = get_vector_store(settings)
    store.upsert(chunks)
    return store.count()


def main() -> int:
    count = seed()
    print(
        f"[seed] indexed {count} chunks into '{get_settings().index_name}' "
        f"(mode={get_settings().mode})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
