"""Polyphemus — a secure Amazon Bedrock RAG reference implementation.

The package demonstrates four security controls as first-class, observable
outputs of a retrieval-augmented-generation pipeline:

1. Query-time access control (RBAC group intersection + ABAC clearance),
   enforced both at the vector-store filter and via a post-retrieval re-check.
2. PII redaction applied to retrieved context and the user prompt before the
   model is ever invoked.
3. Indirect prompt-injection defense (data/instruction separation, spotlighting,
   heuristic scanning, neutralization).
4. A structured JSONL audit trail capturing identity, prompt, retrieved and
   denied sources, policy decisions, redactions, injection flags, and response.

Everything runs offline in ``mock`` mode; all AWS access is funneled through
``polyphemus.aws.clients`` so pipeline logic never imports boto3 directly.
"""

from __future__ import annotations

__version__ = "0.1.0"

from polyphemus.config import Settings, get_settings
from polyphemus.models import (
    AuditRecord,
    Chunk,
    Document,
    PolicyDecision,
    RedactionEvent,
    RetrievalResult,
    UserContext,
)
from polyphemus.pipeline import SecureRAGPipeline

__all__ = [
    "__version__",
    "Settings",
    "get_settings",
    "Document",
    "Chunk",
    "UserContext",
    "PolicyDecision",
    "RetrievalResult",
    "RedactionEvent",
    "AuditRecord",
    "SecureRAGPipeline",
]
