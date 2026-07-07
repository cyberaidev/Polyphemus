"""Character-window chunking with overlap.

Each chunk copies the parent document's ACL fields (``allowed_groups``,
``classification``, ``department``, ``source_uri``). This copy-down is what makes
query-time metadata filtering possible: the vector store filters on chunk
metadata, never re-reading the source document. Chunk ids are deterministic
(``<doc_id>#<index>``) so seeding and tests are stable.
"""

from __future__ import annotations

from polyphemus.acl.metadata import build_chunk_metadata
from polyphemus.models import Chunk, Document

# Defaults mirror Settings.chunk_size / Settings.chunk_overlap (see config.py). The
# seeding path passes the resolved settings values explicitly; these constants are
# the fallback for direct callers and tests, so the 600/80 magic numbers live in
# exactly one place per layer.
DEFAULT_CHUNK_SIZE = 600
DEFAULT_CHUNK_OVERLAP = 80


def chunk_document(
    doc: Document, size: int = DEFAULT_CHUNK_SIZE, overlap: int = DEFAULT_CHUNK_OVERLAP
) -> list[Chunk]:
    """Split a document into overlapping character windows.

    Args:
        doc: the source document.
        size: window size in characters.
        overlap: number of characters shared between consecutive windows.
    """
    if size <= 0:
        raise ValueError("chunk size must be positive")
    if overlap < 0 or overlap >= size:
        raise ValueError("overlap must be >= 0 and < size")

    metadata = build_chunk_metadata(doc)
    text = doc.text
    step = size - overlap
    chunks: list[Chunk] = []
    index = 0
    start = 0
    while start < len(text):
        window = text[start : start + size]
        if window.strip():
            chunks.append(
                Chunk(
                    chunk_id=f"{doc.doc_id}#{index}",
                    doc_id=doc.doc_id,
                    text=window,
                    department=str(metadata["department"]),
                    classification=doc.classification,
                    allowed_groups=list(doc.allowed_groups),
                    source_uri=doc.source_uri,
                )
            )
            index += 1
        start += step
    # Guarantee at least one chunk even for very short documents.
    if not chunks and text.strip():
        chunks.append(
            Chunk(
                chunk_id=f"{doc.doc_id}#0",
                doc_id=doc.doc_id,
                text=text,
                department=doc.department,
                classification=doc.classification,
                allowed_groups=list(doc.allowed_groups),
                source_uri=doc.source_uri,
            )
        )
    return chunks


def chunk_documents(
    docs: list[Document], size: int = DEFAULT_CHUNK_SIZE, overlap: int = DEFAULT_CHUNK_OVERLAP
) -> list[Chunk]:
    """Chunk a list of documents into a single flat list of chunks."""
    out: list[Chunk] = []
    for doc in docs:
        out.extend(chunk_document(doc, size=size, overlap=overlap))
    return out
