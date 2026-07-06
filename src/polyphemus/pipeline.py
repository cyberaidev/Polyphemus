"""The secure RAG orchestrator.

Ties every control together for a single request::

    identity -> retrieve(authz filter + re-check) -> injection scan
             -> neutralize + spotlight -> PII redaction (context + prompt)
             -> hardened system prompt -> Bedrock -> audit

The pipeline returns the :class:`AuditRecord` it wrote, so callers (the demo and
tests) can assert on every control's observable output.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from polyphemus.audit.logger import AuditLogger
from polyphemus.config import Settings, get_settings
from polyphemus.defense import injection
from polyphemus.defense.system_prompt import build_system_prompt
from polyphemus.generation.bedrock_client import generate
from polyphemus.models import AuditRecord, UserContext
from polyphemus.redaction.redactor import Redactor
from polyphemus.retrieval.retriever import retrieve


class SecureRAGPipeline:
    """Executes the secure RAG flow and emits an audit record per request."""

    def __init__(
        self,
        settings: Settings | None = None,
        audit_logger: AuditLogger | None = None,
        redactor: Redactor | None = None,
        defenses_enabled: bool = True,
    ) -> None:
        self.settings = settings or get_settings()
        self.audit = audit_logger or AuditLogger(self.settings)
        self.redactor = redactor or Redactor()
        # When False, injection defenses are bypassed to demonstrate the
        # vulnerability the control prevents (contrast test only).
        self.defenses_enabled = defenses_enabled

    def answer(self, user: UserContext, question: str) -> AuditRecord:
        """Run the full pipeline for ``question`` as ``user`` and audit it."""
        started = time.perf_counter()
        request_id = str(uuid.uuid4())

        # 1. Authorization-aware retrieval (query filter + post-filter re-check).
        outcome = retrieve(user, question)
        authorized_chunks = [r.chunk for r in outcome.authorized]
        policy_decisions = [r.decision for r in outcome.authorized]

        # 2. Injection scanning on retrieved (untrusted) context.
        injection_flags: list[str] = []
        if self.defenses_enabled:
            injection_flags = injection.scan_chunks(authorized_chunks)

        # 3. Redact PII in the user prompt (before the model sees it).
        redacted_prompt, prompt_redactions = self.redactor.redact(question, "prompt")

        # 4. Build the spotlighted, neutralized context, then redact it.
        nonce = injection.new_nonce()
        if authorized_chunks:
            spotlighted = injection.spotlight_context(
                authorized_chunks, nonce, neutralized=self.defenses_enabled
            )
        else:
            spotlighted = f"<<CONTEXT nonce={nonce}>>\n(no authorized documents)\n<<END_CONTEXT nonce={nonce}>>"

        redacted_context, context_redactions = self.redactor.redact(spotlighted, "context")

        # 5. Hardened system prompt (data/instruction separation).
        system_prompt = build_system_prompt(nonce, defenses_enabled=self.defenses_enabled)

        # 6. Generate the grounded answer.
        response, model_id = generate(system_prompt, redacted_prompt, redacted_context)

        latency_ms = int((time.perf_counter() - started) * 1000)

        # 7. Assemble and persist the audit record.
        record = AuditRecord(
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user=user,
            prompt=question,
            redacted_prompt=redacted_prompt,
            retrieved_sources=outcome.authorized_sources,
            denied_sources=outcome.denied_sources,
            policy_decisions=policy_decisions,
            redactions=prompt_redactions + context_redactions,
            injection_flags=injection_flags,
            defenses_enabled=self.defenses_enabled,
            model_id=model_id,
            response=response,
            latency_ms=latency_ms,
        )
        self.audit.write(record)
        return record
