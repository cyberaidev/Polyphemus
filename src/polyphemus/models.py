"""Core data models shared across the Polyphemus pipeline.

All models are pydantic v2 so audit records serialize cleanly to JSON. The ACL
fields (``allowed_groups``, ``classification``, ``department``, ``source_uri``)
are deliberately mirrored from :class:`Document` down onto every :class:`Chunk`
because the query-time access-control filter operates on chunk metadata.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# Ascending sensitivity. The two "*_confidential" tiers are siblings: they are
# gated by group membership / department rather than by a single scalar rank.
Classification = Literal[
    "public",
    "internal",
    "hr_confidential",
    "finance_confidential",
]

# Rank used only for the public/internal scalar clearance check. Confidential
# tiers share the top rank; separation between them is enforced by group ACLs.
CLASSIFICATION_RANK: dict[str, int] = {
    "public": 0,
    "internal": 1,
    "hr_confidential": 2,
    "finance_confidential": 2,
}

CONFIDENTIAL_TIERS: frozenset[str] = frozenset({"hr_confidential", "finance_confidential"})


class Document(BaseModel):
    """A source document with its access-control metadata."""

    doc_id: str
    source_uri: str  # s3://bucket/key or file://path
    department: str  # "finance" | "hr" | "general"
    classification: Classification
    allowed_groups: list[str]  # IdP groups permitted to read, e.g. ["finance", "admin"]
    owner: str
    text: str
    tags: dict[str, str] = Field(default_factory=dict)


class Chunk(BaseModel):
    """A retrievable chunk carrying a copy of its document's ACL metadata."""

    chunk_id: str
    doc_id: str
    text: str
    embedding: list[float] | None = None

    # ACL metadata copied down from the parent Document (the filter target):
    department: str
    classification: Classification
    allowed_groups: list[str]
    source_uri: str


class UserContext(BaseModel):
    """The authenticated caller, derived from validated IdP claims."""

    subject: str  # OIDC "sub"
    username: str
    groups: list[str]  # from cognito:groups / Entra groups claim
    department: str | None = None
    clearance: Classification = "public"  # max scalar classification the user may read
    idp: str = "cognito"  # "cognito" | "entra"


class PolicyDecision(BaseModel):
    """The result of evaluating a UserContext against a chunk's ACL."""

    allowed: bool
    reason: str  # human-readable rationale
    matched_rule: str  # "group_intersection" | "clearance_gte" | "deny_no_group" | ...
    source_uri: str | None = None  # which resource this decision was about


class RetrievalResult(BaseModel):
    """A chunk returned by retrieval together with its authorization decision."""

    chunk: Chunk
    score: float
    decision: PolicyDecision


class RedactionEvent(BaseModel):
    """A record that PII of a given type was redacted."""

    entity_type: str
    count: int
    location: str  # "prompt" | "context"


class AuditRecord(BaseModel):
    """The immutable evidence trail for a single request."""

    request_id: str
    timestamp: str  # ISO-8601 UTC
    user: UserContext
    prompt: str  # ORIGINAL prompt — treated as access-controlled evidence
    redacted_prompt: str
    retrieved_sources: list[str] = Field(default_factory=list)  # source_uris that passed authz
    denied_sources: list[str] = Field(default_factory=list)  # source_uris filtered out
    policy_decisions: list[PolicyDecision] = Field(default_factory=list)
    redactions: list[RedactionEvent] = Field(default_factory=list)
    injection_flags: list[str] = Field(default_factory=list)  # rule names that fired
    defenses_enabled: bool = True
    model_id: str = ""
    response: str = ""
    latency_ms: int = 0

    def to_jsonl(self) -> str:
        """Serialize to a single JSON line for the audit log."""
        return self.model_dump_json()
