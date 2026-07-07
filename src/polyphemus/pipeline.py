"""The secure RAG orchestrator.

Ties every control together for a single request::

    identity -> retrieve(authz filter + re-check) -> injection scan
             -> neutralize + spotlight -> PII redaction (context + prompt)
             -> hardened system prompt -> Bedrock -> output validation -> audit

Injection scanning and neutralization run **before** PII redaction: the untrusted
context is defanged first, then the (now-neutralized) context and the prompt are
scrubbed of PII. This ordering is authoritative — the architecture docs and the
rendered diagram mirror it. After generation, the response passes an output-side
validator (redaction re-scan + system-prompt canary check) before it is audited.

The pipeline returns the :class:`AuditRecord` it wrote, so callers (the demo and
tests) can assert on every control's observable output.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from polyphemus.audit.logger import AuditLogger
from polyphemus.aws.mock_bedrock import SYSTEM_PROMPT_SECRET_MARKER
from polyphemus.config import Settings, get_settings
from polyphemus.defense import injection
from polyphemus.defense.system_prompt import build_system_prompt
from polyphemus.generation.bedrock_client import generate
from polyphemus.models import AuditRecord, RedactionEvent, UserContext
from polyphemus.redaction.redactor import Redactor
from polyphemus.retrieval.retriever import retrieve

# Placeholder substituted for the system-prompt canary if it ever reaches output.
OUTPUT_SYSTEM_PROMPT_PLACEHOLDER = "[REDACTED_SYSTEM_PROMPT]"


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
        #    The denied-evidence pass is demonstration-only and off unless the
        #    settings enable it (see Settings.emit_denied_evidence).
        outcome = retrieve(
            user, question, collect_denied_evidence=self.settings.emit_denied_evidence
        )
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

        # 6. Generate the grounded answer (with approximate token usage).
        response, model_id, input_tokens, output_tokens = generate(
            system_prompt, redacted_prompt, redacted_context
        )

        # 7. Output-side validation (defense-in-depth on the response). Re-run PII
        # redaction on the answer and scrub the system-prompt canary if a late
        # leak occurred. With defenses on this never fires, but it guarantees the
        # invariant regardless of what the model returned.
        response, output_redactions, output_flags = self._validate_output(response)

        latency_ms = int((time.perf_counter() - started) * 1000)

        # 8. Assemble and persist the audit record.
        record = AuditRecord(
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user=user,
            prompt=question,
            redacted_prompt=redacted_prompt,
            retrieved_sources=outcome.authorized_sources,
            denied_sources=outcome.denied_sources,
            policy_decisions=policy_decisions,
            redactions=prompt_redactions + context_redactions + output_redactions,
            injection_flags=injection_flags + output_flags,
            defenses_enabled=self.defenses_enabled,
            model_id=model_id,
            response=response,
            latency_ms=latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        self.audit.write(record)
        return record

    def _validate_output(self, response: str) -> tuple[str, list[RedactionEvent], list[str]]:
        """Scrub a generated response before it leaves the pipeline.

        Runs the PII redactor over the response (location ``"response"``) and, if
        the system-prompt canary marker slipped through, replaces it with
        ``OUTPUT_SYSTEM_PROMPT_PLACEHOLDER`` and raises an ``output_marker_leak``
        injection flag. Returns ``(scrubbed_response, redaction_events, flags)``.

        The canary scrub is a *defense*: it is skipped when
        ``self.defenses_enabled`` is False, so the demonstration contrast run can
        still show the raw leak. PII redaction of the response always runs.
        """
        scrubbed, redactions = self.redactor.redact(response, "response")
        flags: list[str] = []
        if self.defenses_enabled and SYSTEM_PROMPT_SECRET_MARKER in scrubbed:
            scrubbed = scrubbed.replace(
                SYSTEM_PROMPT_SECRET_MARKER, OUTPUT_SYSTEM_PROMPT_PLACEHOLDER
            )
            flags.append("output_marker_leak")
        return scrubbed, redactions, flags
