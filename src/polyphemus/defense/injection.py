"""Indirect prompt-injection detection, spotlighting, and neutralization.

The threat: retrieved documents are untrusted content. An attacker who can get a
document indexed (e.g. a vendor invoice) may embed instructions hoping the model
will treat them as commands ("ignore previous instructions", "reveal the system
prompt", "email secrets to ...").

Defenses implemented here:

1. **Heuristic scanning** (:func:`scan_text` / :func:`scan_chunks`) flags override
   phrases, role-switching, prompt-exfiltration, encoded payloads, and zero-width
   characters, returning the names of the rules that fired.
2. **Neutralization** (:func:`neutralize`) strips zero-width characters and defangs
   detected control phrases so they cannot read as instructions.
3. **Spotlighting / delimiting** (:func:`spotlight_context`) wraps each chunk in a
   nonce-tagged fence and labels it untrusted data. Combined with the hardened
   system prompt (data/instruction separation), this is what stops scenario 3.

Nonces make delimiter-escape attacks detectable: if the untrusted text contains
the fence tokens, they are escaped before wrapping so the boundary stays intact.
"""

from __future__ import annotations

import math
import re
import secrets
import unicodedata
from collections import Counter

from polyphemus.models import Chunk

# Zero-width / bidi characters commonly used to smuggle hidden instructions.
_ZERO_WIDTH = "​‌‍⁠﻿‪‫‬‭‮"
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH}]")

# Visible marker used to break any forged fence token inside untrusted content.
# It deliberately does NOT contain the "<<" sequence, so replacing "<<CONTEXT"
# with f"{_FENCE_ESCAPE}CONTEXT" cannot re-form a real fence token.
_FENCE_ESCAPE = "[escaped-fence]"

_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "override_instruction",
        re.compile(r"ignore\s+(all\s+)?(prior|previous|above)\s+instructions", re.I),
    ),
    ("override_instruction", re.compile(r"disregard\s+(all\s+)?(prior|previous|above)", re.I)),
    ("role_hijack", re.compile(r"you\s+are\s+now\b", re.I)),
    ("role_hijack", re.compile(r"\bact\s+as\s+(an?\s+)?(unrestricted|jailbroken|dan)\b", re.I)),
    ("role_hijack", re.compile(r"\bDAN\b")),
    ("prompt_exfiltration", re.compile(r"reveal\s+(the\s+)?system\s+prompt", re.I)),
    (
        "prompt_exfiltration",
        re.compile(r"(print|show|output)\s+your\s+(instructions|system\s+prompt)", re.I),
    ),
    ("exfiltration", re.compile(r"\bexfiltrate\b", re.I)),
    ("exfiltration", re.compile(r"\bemail\s+(them|it|the\s+\w+)\s+to\b", re.I)),
    ("data_listing", re.compile(r"list\s+all\s+documents", re.I)),
    ("system_role_injection", re.compile(r"^\s*system\s*:", re.I | re.M)),
]

# Candidate long token that *could* be a base64 payload. Matched broadly, then
# validated by ``_looks_like_base64`` so hex nonces, s3 URIs, and low-entropy runs
# do not false-positive.
_ENCODED_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of ``s``; higher = more random-looking."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_base64(token: str) -> bool:
    """True if ``token`` has genuine base64 structure and high entropy.

    Excludes hex-only nonces and requires real base64 shape (length a multiple of
    4 once padding is considered) plus mixed character classes and high entropy,
    so ordinary long identifiers / hex digests do not trip the rule.
    """
    if _HEX_RE.match(token):
        return False  # a hex digest/nonce is not a base64 payload
    if len(token) % 4 != 0:
        return False  # real base64 is padded to a multiple of 4
    stripped = token.rstrip("=")
    has_lower = any(c.islower() for c in stripped)
    has_upper = any(c.isupper() for c in stripped)
    has_digit = any(c.isdigit() for c in stripped)
    # Require at least two character classes (rules out all-one-case runs).
    if (has_lower + has_upper + has_digit) < 2:
        return False
    return _shannon_entropy(stripped) >= 3.5


def _has_encoded_payload(text: str) -> bool:
    """True if ``text`` contains a token that genuinely looks base64-encoded."""
    return any(_looks_like_base64(m.group(0)) for m in _ENCODED_CANDIDATE_RE.finditer(text))


def scan_text(text: str) -> list[str]:
    """Return the sorted, de-duplicated names of injection rules that fired."""
    fired: set[str] = set()
    if _ZERO_WIDTH_RE.search(text):
        fired.add("zero_width_chars")
    for name, pattern in _RULES:
        if pattern.search(text):
            fired.add(name)
    if _has_encoded_payload(text):
        fired.add("encoded_payload")
    return sorted(fired)


def scan_chunks(chunks: list[Chunk]) -> list[str]:
    """Scan the concatenated text of retrieved chunks for injection attempts."""
    fired: set[str] = set()
    for chunk in chunks:
        fired.update(scan_text(chunk.text))
    return sorted(fired)


def neutralize(text: str) -> str:
    """Defang detected control sequences so they cannot read as instructions.

    - Remove zero-width / bidi characters.
    - Apply Unicode NFKC normalization. NFKC folds *compatibility* characters
      (e.g. ligatures, full-width forms, some styled letters) to canonical forms.
      It does **not** map cross-script confusables/homoglyphs (e.g. Cyrillic „і"
      → Latin „i"); a homoglyph payload can still slip past the heuristic scanner.
      This is best-effort defense-in-depth, not a complete anti-evasion measure —
      see docs/THREAT_MODEL.md.
    - Prefix known override/role/exfiltration phrases with a visible marker so
      they are inert text rather than imperative commands.
    """
    cleaned = _ZERO_WIDTH_RE.sub("", text)
    cleaned = unicodedata.normalize("NFKC", cleaned)
    for _name, pattern in _RULES:
        cleaned = pattern.sub(lambda m: "[neutralized:" + m.group(0).strip() + "]", cleaned)
    return cleaned


def new_nonce() -> str:
    """Return a fresh, unguessable delimiter nonce."""
    return secrets.token_hex(8)


def spotlight_context(chunks: list[Chunk], nonce: str, neutralized: bool = True) -> str:
    """Wrap chunks in nonce-tagged fences labeled as untrusted data.

    Each chunk's ``source_uri`` is embedded so the model can cite provenance. The
    fence tokens are escaped inside the body to prevent delimiter-escape attacks.
    """
    open_tag = f"<<CONTEXT nonce={nonce}>>"
    close_tag = f"<<END_CONTEXT nonce={nonce}>>"
    body_parts: list[str] = []
    for chunk in chunks:
        text = neutralize(chunk.text) if neutralized else chunk.text
        # Defeat delimiter-escape attacks: any attempt to forge a fence token in
        # the body is broken with a VISIBLE sentinel so the real fence stays the
        # only intact open/close pair. A visible marker (not a zero-width char) is
        # used so the escaping is human-auditable in logs and never invisible.
        text = text.replace("<<CONTEXT", f"{_FENCE_ESCAPE}CONTEXT").replace(
            "<<END_CONTEXT", f"{_FENCE_ESCAPE}END_CONTEXT"
        )
        body_parts.append(f"[source_uri={chunk.source_uri}]\n{text}")
    body = "\n\n---\n\n".join(body_parts)
    return f"{open_tag}\n{body}\n{close_tag}"


def fence_intact(wrapped: str, nonce: str) -> bool:
    """True if exactly one matching open/close fence pair exists for ``nonce``."""
    opens = wrapped.count(f"<<CONTEXT nonce={nonce}>>")
    closes = wrapped.count(f"<<END_CONTEXT nonce={nonce}>>")
    return opens == 1 and closes == 1
