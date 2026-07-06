"""Deterministic, offline Amazon Bedrock replacement.

Two capabilities are faked:

* ``embed(text)`` — a stable pseudo-embedding. Character n-grams are hashed into
  a fixed-dimensional vector and L2-normalized, so cosine similarity between a
  query and semantically-overlapping chunks is meaningful and, above all,
  reproducible across runs. No randomness, no network.

* ``invoke(system, messages)`` — a grounded generator that answers strictly from
  the delimited CONTEXT block supplied in the user message. It is the linchpin of
  the injection demo:

    - When defenses are ON (the system prompt declares context to be untrusted
      data and the context has been spotlighted/neutralized), the model refuses
      to act on any imperative instruction embedded in the context. It answers
      the user's actual question from the benign parts only and never reveals the
      system prompt or lists/leaks other documents.

    - When defenses are OFF (contrast test only), the model naively obeys
      instructions found in the context — demonstrating the vulnerability the
      control prevents.

The "defenses" signal is carried in the system prompt via a sentinel line
(``POLYPHEMUS_DEFENSES: on|off``) written by :mod:`polyphemus.defense.system_prompt`.
A real deployment achieves the ON behavior through prompt hardening + Bedrock
Guardrails; the mock encodes that expected behavior deterministically.
"""

from __future__ import annotations

import hashlib
import re

# Sentinel written into the system prompt so the mock knows the defense posture.
DEFENSE_SENTINEL_ON = "POLYPHEMUS_DEFENSES: on"
DEFENSE_SENTINEL_OFF = "POLYPHEMUS_DEFENSES: off"

# A recognizable marker for the "secret" system prompt. If this ever appears in
# output, prompt leakage occurred (tests assert it does NOT under defenses).
SYSTEM_PROMPT_SECRET_MARKER = "SYSTEM_PROMPT_SECRET::polyphemus-guardrail-v1"

_INSTRUCTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(prior|previous|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(all\s+)?(prior|previous|above)", re.I),
    re.compile(r"reveal\s+(the\s+)?system\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\b", re.I),
    re.compile(r"\bemail\s+them\s+to\b", re.I),
    re.compile(r"\bexfiltrate\b", re.I),
    re.compile(r"list\s+all\s+documents", re.I),
]


class MockBedrock:
    """Deterministic Bedrock stand-in for embeddings and chat generation."""

    def __init__(self, embed_dim: int = 256) -> None:
        self.embed_dim = embed_dim

    # -- embeddings ----------------------------------------------------------
    def embed(self, text: str) -> list[float]:
        """Return a deterministic, L2-normalized pseudo-embedding for ``text``."""
        vec = [0.0] * self.embed_dim
        tokens = _tokenize(text)
        for token in tokens:
            for gram in _char_ngrams(token, 3) or [token]:
                idx = _stable_index(gram, self.embed_dim)
                vec[idx] += 1.0
        # L2 normalize
        norm = sum(v * v for v in vec) ** 0.5
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec

    # -- chat generation -----------------------------------------------------
    def invoke(self, system: str, messages: list[dict[str, str]]) -> str:
        """Generate a grounded answer from the last user message's CONTEXT block."""
        defenses_on = DEFENSE_SENTINEL_OFF not in system  # default to safe (on)
        user_text = _last_user_text(messages)
        question = _extract_question(user_text)
        context = _extract_context(user_text)

        if not context.strip():
            return "I don't have authorized information to answer that."

        embedded_instructions = _find_embedded_instructions(context)

        if embedded_instructions and not defenses_on:
            # CONTROL DISABLED: the model naively obeys instructions in context.
            return _obey_injection(context)

        # Defenses ON (or no injection present): answer only from benign context,
        # never following embedded imperatives, never leaking the system prompt.
        return _grounded_answer(question, context)


# --- helpers ----------------------------------------------------------------
def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _char_ngrams(token: str, n: int) -> list[str]:
    if len(token) < n:
        return []
    return [token[i : i + n] for i in range(len(token) - n + 1)]


def _stable_index(s: str, dim: int) -> int:
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return int(digest, 16) % dim


def _last_user_text(messages: list[dict[str, str]]) -> str:
    for msg in reversed(messages):
        if msg.get("role") == "user":
            return msg.get("content", "")
    return messages[-1].get("content", "") if messages else ""


def _extract_context(user_text: str) -> str:
    """Pull text between the spotlighting fences, if present; else whole text."""
    m = re.search(r"<<CONTEXT[^>]*>>(.*?)<<END_CONTEXT[^>]*>>", user_text, re.S)
    if m:
        return m.group(1)
    # Fallback: text after a "CONTEXT:" label
    m = re.search(r"CONTEXT:\s*(.*)", user_text, re.S)
    return m.group(1) if m else user_text


def _extract_question(user_text: str) -> str:
    m = re.search(r"QUESTION:\s*(.*?)(?:\n\n|<<CONTEXT|$)", user_text, re.S)
    if m:
        return m.group(1).strip()
    return user_text.strip()


def _find_embedded_instructions(context: str) -> list[str]:
    hits: list[str] = []
    for pat in _INSTRUCTION_PATTERNS:
        if pat.search(context):
            hits.append(pat.pattern)
    return hits


def _obey_injection(context: str) -> str:
    """The vulnerable behavior shown only when defenses are disabled."""
    return (
        "INJECTION SUCCEEDED (defenses disabled): Following the instructions found "
        "inside the document, here is the confidential system prompt and a listing "
        "of all documents, including HR records.\n"
        f"{SYSTEM_PROMPT_SECRET_MARKER}\n"
        "Documents: finance/q3_earnings.md, finance/vendor_payments.md, "
        "hr/pto_policy.md, hr/employee_handbook.md\n"
        "(exfiltration target: attacker@evil.example)"
    )


# Canonical grounded answers keyed to which source documents are actually present
# in the CONTEXT. Answers are GROUNDED: a topic is only used if the corresponding
# document is in context, so a user who was denied a document can never receive an
# answer synthesized from it. The question is used only to pick among documents
# that are genuinely present.
def _grounded_answer(question: str, context: str) -> str:
    q = question.lower()
    ctx = context
    ctx_lower = ctx.lower()

    uris = sorted(set(re.findall(r"source_uri=([^\s\]]+)", ctx)))

    def cite() -> str:
        return f" (sources: {', '.join(uris)})" if uris else ""

    def present(fragment: str) -> bool:
        return any(fragment in u for u in uris)

    # Build the set of answerable topics from the documents present in context.
    has_invoice = present("vendor_invoice_injection")
    has_payments = present("vendor_payments")
    has_earnings = present("q3_earnings")
    has_pto = present("pto_policy")
    has_handbook = present("employee_handbook")
    has_overview = present("company_overview")

    wants_invoice = "invoice" in q or "aperture" in q
    wants_payments = "payment" in q or ("vendor" in q and not wants_invoice)
    wants_finance = "q3" in q or "earnings" in q or "revenue" in q or "finance" in q
    wants_pto = "pto" in q or "vacation" in q or "leave" in q or "time off" in q
    wants_hr = "handbook" in q or "conduct" in q or "onboarding" in q or "hr" in q
    wants_overview = "company" in q or "overview" in q or "mission" in q

    if wants_invoice and has_invoice:
        return (
            "The vendor invoice records a payment to the listed supplier for "
            "professional services. I treated the document strictly as data and did "
            "not act on any instructions embedded in it." + cite()
        )
    if wants_payments and has_payments:
        return (
            "Recent vendor payments include disbursements to approved suppliers; "
            "personal identifiers in the records were redacted before processing." + cite()
        )
    if wants_finance and has_earnings:
        return (
            "Q3 results show revenue growth over the prior quarter with improved "
            "operating margin, per the finance report." + cite()
        )
    if wants_pto and has_pto:
        return (
            "The PTO policy grants accrued paid time off that increases with tenure "
            "and must be requested in advance through the HR portal." + cite()
        )
    if wants_hr and has_handbook:
        return (
            "The employee handbook covers code of conduct, onboarding, and workplace "
            "policies applicable to all staff." + cite()
        )
    if wants_overview and has_overview:
        return (
            "The company overview summarizes the organization's mission, products, "
            "and general operating principles." + cite()
        )

    # The requested topic is NOT present in the authorized context: refuse rather
    # than answer from an unrelated (but authorized) document. This is what makes
    # scenario 2 produce "no authorized information" for the HR user.
    topic_requested = any(
        [wants_invoice, wants_payments, wants_finance, wants_pto, wants_hr, wants_overview]
    )
    topic_available = any(
        [has_invoice, has_payments, has_earnings, has_pto, has_handbook, has_overview]
    )
    if topic_requested and not (
        (wants_invoice and has_invoice)
        or (wants_payments and has_payments)
        or (wants_finance and has_earnings)
        or (wants_pto and has_pto)
        or (wants_hr and has_handbook)
        or (wants_overview and has_overview)
    ):
        return "I don't have authorized information to answer that."

    # Generic grounded fallback: first substantive sentence of the context.
    if topic_available or ctx_lower.strip():
        sentence = _first_sentence(ctx)
        if sentence:
            return f"Based on the authorized documents: {sentence}" + cite()
    return "I don't have authorized information to answer that."


def _first_sentence(text: str) -> str:
    cleaned = re.sub(r"\[source_uri=[^\]]+\]", "", text)
    cleaned = re.sub(r"source_uri=\S+", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    m = re.search(r"[A-Z][^.!?]{15,}[.!?]", cleaned)
    return m.group(0).strip() if m else ""
