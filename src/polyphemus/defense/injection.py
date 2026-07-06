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

import re
import secrets
import unicodedata

from polyphemus.models import Chunk

# Zero-width / bidi characters commonly used to smuggle hidden instructions.
_ZERO_WIDTH = "​‌‍⁠﻿‪‫‬‭‮"
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH}]")

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
    ("encoded_payload", re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")),  # long base64-ish blob
]


def scan_text(text: str) -> list[str]:
    """Return the sorted, de-duplicated names of injection rules that fired."""
    fired: set[str] = set()
    if _ZERO_WIDTH_RE.search(text):
        fired.add("zero_width_chars")
    for name, pattern in _RULES:
        if pattern.search(text):
            fired.add(name)
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
    - Normalize unicode (collapse look-alike homoglyph tricks).
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
        # Escape any attempt to forge the fence tokens.
        text = text.replace("<<CONTEXT", "<​<CONTEXT").replace("<<END_CONTEXT", "<​<END_CONTEXT")
        # (then strip zero-width we just used purely for escaping in display)
        body_parts.append(f"[source_uri={chunk.source_uri}]\n{text}")
    body = "\n\n---\n\n".join(body_parts)
    return f"{open_tag}\n{body}\n{close_tag}"


def fence_intact(wrapped: str, nonce: str) -> bool:
    """True if exactly one matching open/close fence pair exists for ``nonce``."""
    opens = wrapped.count(f"<<CONTEXT nonce={nonce}>>")
    closes = wrapped.count(f"<<END_CONTEXT nonce={nonce}>>")
    return opens == 1 and closes == 1
