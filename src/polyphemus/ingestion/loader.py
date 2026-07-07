"""Load :class:`Document` objects from local files (or mock S3) + ACL sidecar.

The document *body* comes from ``data/documents/**`` and the access-control
metadata comes from ``data/acls/document_acls.json``. Joining them here keeps the
sample content readable while making the ACLs explicit and auditable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from polyphemus.models import Classification, Document

# Repo root = three levels up from this file (src/polyphemus/ingestion/loader.py).
_REPO_ROOT = Path(__file__).resolve().parents[3]
_DATA_DIR = _REPO_ROOT / "data"
_DOCS_DIR = _DATA_DIR / "documents"
_ACL_FILE = _DATA_DIR / "acls" / "document_acls.json"


def _read_acls() -> list[dict[str, Any]]:
    with _ACL_FILE.open("r", encoding="utf-8") as fh:
        documents: list[dict[str, Any]] = json.load(fh)["documents"]
        return documents


def load_documents(include_malicious: bool = True) -> list[Document]:
    """Load all sample documents joined with their ACL metadata.

    Args:
        include_malicious: include the injection-payload document (used for the
            prompt-injection scenario). Set False to load only benign corpus.
    """
    documents: list[Document] = []
    for entry in _read_acls():
        rel = entry["relative_path"]
        if not include_malicious and rel.startswith("malicious/"):
            continue
        body_path = _DOCS_DIR / rel
        text = body_path.read_text(encoding="utf-8")
        classification: Classification = entry["classification"]
        documents.append(
            Document(
                doc_id=entry["doc_id"],
                source_uri=f"file://data/documents/{rel}",
                department=entry["department"],
                classification=classification,
                allowed_groups=list(entry["allowed_groups"]),
                owner=entry["owner"],
                text=text,
            )
        )
    return documents


def load_document_by_id(doc_id: str) -> Document:
    """Load a single document by its ``doc_id``."""
    for doc in load_documents():
        if doc.doc_id == doc_id:
            return doc
    raise KeyError(f"unknown doc_id: {doc_id}")
