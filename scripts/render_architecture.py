#!/usr/bin/env python3
"""Render docs/architecture.svg from an internal diagram spec.

Pure Python — builds the SVG as a string with no network access and no binary or
third-party dependencies, so ``make render-diagram`` reproduces the committed
file byte-for-byte on any machine.

The diagram shows the request data flow across trust boundaries, with the
retrieved-document content wrapped in a dashed "untrusted content" boundary (the
reason the injection defense exists), plus a legend of the six control classes.
"""

from __future__ import annotations

import sys
from pathlib import Path
from xml.sax.saxutils import escape

_OUT = Path(__file__).resolve().parents[1] / "docs" / "architecture.svg"

# Palette (kept deliberately simple / colorblind-friendly).
COL_BG = "#ffffff"
COL_EDGE = "#334155"
COL_CLIENT = "#e0f2fe"
COL_EDGE_SVC = "#dbeafe"
COL_COMPUTE = "#dcfce7"
COL_DATA = "#fef9c3"
COL_MODEL = "#f3e8ff"
COL_AUDIT = "#fee2e2"
COL_TRUST = "#b91c1c"
COL_TEXT = "#0f172a"

W, H = 1180, 760

CONTROL_LEGEND = [
    ("#1d4ed8", "Authentication — JWT / OIDC validation"),
    ("#059669", "Authorization — query-time filter + post-retrieval re-check"),
    ("#ca8a04", "Confidentiality — SSE-KMS + PII redaction"),
    ("#b91c1c", "Integrity — prompt-injection defense (untrusted content boundary)"),
    ("#7c3aed", "Accountability — structured audit trail"),
    ("#0f766e", "Least privilege — scoped IAM roles"),
]


def _box(
    x: float,
    y: float,
    w: float,
    h: float,
    fill: str,
    title: str,
    subtitle: str = "",
    rx: int = 10,
) -> str:
    parts = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" ry="{rx}" '
        f'fill="{fill}" stroke="{COL_EDGE}" stroke-width="1.5"/>',
        f'<text x="{x + w / 2}" y="{y + (18 if subtitle else h / 2 + 4)}" '
        f'text-anchor="middle" font-family="Helvetica,Arial,sans-serif" '
        f'font-size="13" font-weight="600" fill="{COL_TEXT}">{escape(title)}</text>',
    ]
    if subtitle:
        parts.append(
            f'<text x="{x + w / 2}" y="{y + 36}" text-anchor="middle" '
            f'font-family="Helvetica,Arial,sans-serif" font-size="10.5" '
            f'fill="#475569">{escape(subtitle)}</text>'
        )
    return "\n".join(parts)


def _arrow(x1: float, y1: float, x2: float, y2: float, label: str = "", dash: bool = False) -> str:
    style = f'stroke="{COL_EDGE}" stroke-width="1.6"'
    if dash:
        style += ' stroke-dasharray="5,4"'
    line = f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" {style} marker-end="url(#arrow)"/>'
    text = ""
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 6
        text = (
            f'<text x="{mx}" y="{my}" text-anchor="middle" '
            f'font-family="Helvetica,Arial,sans-serif" font-size="10" '
            f'fill="#475569">{escape(label)}</text>'
        )
    return line + "\n" + text


def build_svg() -> str:
    s: list[str] = []
    s.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        f'width="{W}" height="{H}" role="img" '
        f'aria-label="Polyphemus secure Bedrock RAG architecture">'
    )
    s.append(
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-end">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{COL_EDGE}"/></marker></defs>'
    )
    s.append(f'<rect x="0" y="0" width="{W}" height="{H}" fill="{COL_BG}"/>')
    s.append(
        f'<text x="{W / 2}" y="30" text-anchor="middle" '
        f'font-family="Helvetica,Arial,sans-serif" font-size="20" '
        f'font-weight="700" fill="{COL_TEXT}">Polyphemus — Secure Bedrock RAG Reference Architecture</text>'
    )

    # Row 1: client -> API GW (JWT) -> Lambda
    _box_client = _box(
        40, 70, 180, 60, COL_CLIENT, "Client / Caller", "bearer JWT (Cognito / Entra)"
    )
    _box_apigw = _box(
        300, 70, 200, 60, COL_EDGE_SVC, "API Gateway (HTTP API)", "JWT authorizer — authN"
    )
    _box_lambda = _box(
        580, 70, 200, 60, COL_COMPUTE, "Lambda: pipeline", "orchestrator, scoped IAM"
    )
    _box_idp = _box(300, 165, 200, 50, COL_EDGE_SVC, "Cognito / Entra ID", "identity provider")
    s += [_box_client, _box_apigw, _box_lambda, _box_idp]

    s.append(_arrow(220, 100, 300, 100, "request"))
    s.append(_arrow(500, 100, 580, 100, "claims"))
    s.append(_arrow(400, 165, 400, 130, "verify token"))

    # Pipeline stages (vertical inside compute zone)
    stage_x = 580
    stages = [
        ("1. identity -> UserContext", COL_COMPUTE),
        ("2. build authz filter (RBAC+ABAC)", COL_COMPUTE),
        ("3. vector query (FILTERED)", COL_COMPUTE),
        ("4. post-retrieval re-check", COL_COMPUTE),
        ("5. injection scan + neutralize", COL_COMPUTE),
        ("6. PII redaction (ctx + prompt)", COL_COMPUTE),
        ("7. hardened prompt assembly", COL_COMPUTE),
    ]
    y = 165
    prev_y = 130
    for label, fill in stages:
        s.append(_box(stage_x, y, 260, 34, fill, label, rx=6))
        s.append(_arrow(stage_x + 130, prev_y, stage_x + 130, y))
        prev_y = y + 34
        y += 48

    # Data services (left column)
    _box_s3 = _box(40, 320, 220, 60, COL_DATA, "S3 (documents)", "SSE-KMS, block public, TLS-only")
    _box_os = _box(
        40,
        410,
        220,
        70,
        COL_DATA,
        "OpenSearch Serverless",
        "vector index + ACL metadata (alt: Aurora+pgvector)",
    )
    _box_comp = _box(
        40, 510, 220, 55, COL_DATA, "Comprehend (aws mode)", "PII NER — regex fallback offline"
    )
    s += [_box_s3, _box_os, _box_comp]

    # Bedrock + Guardrails (right)
    _box_bedrock = _box(
        900, 320, 230, 70, COL_MODEL, "Amazon Bedrock", "embeddings + text model + Guardrails"
    )
    s.append(_box_bedrock)

    # Audit (bottom right)
    _box_audit = _box(
        900, 470, 230, 70, COL_AUDIT, "Audit trail", "CloudWatch Logs + S3 (object lock)"
    )
    s.append(_box_audit)

    # Arrows between compute and services
    s.append(_arrow(300, 445, 578, 261, "filtered retrieval"))  # OS -> stage 3
    s.append(_arrow(260, 350, 578, 200, "ingest (seed)", dash=True))  # S3 -> compute
    s.append(_arrow(578, 430, 262, 535, "redaction NER"))  # compute -> comprehend
    s.append(_arrow(840, 200, 900, 350, "invoke (embed/generate)"))  # compute -> bedrock
    s.append(_arrow(900, 355, 842, 235, "grounded answer"))  # bedrock -> compute
    s.append(_arrow(780, 470, 900, 500, "write record"))  # compute -> audit

    # Untrusted-content trust boundary (dashed) around retrieved doc text.
    s.append(
        f'<rect x="20" y="300" width="260" height="285" rx="14" ry="14" '
        f'fill="none" stroke="{COL_TRUST}" stroke-width="2.2" stroke-dasharray="8,5"/>'
    )
    s.append(
        f'<text x="150" y="600" text-anchor="middle" '
        f'font-family="Helvetica,Arial,sans-serif" font-size="11" '
        f'font-weight="700" fill="{COL_TRUST}">UNTRUSTED CONTENT BOUNDARY</text>'
    )
    s.append(
        f'<text x="150" y="616" text-anchor="middle" '
        f'font-family="Helvetica,Arial,sans-serif" font-size="9.5" '
        f'fill="{COL_TRUST}">retrieved document text — never trusted as instructions</text>'
    )

    # Network trust boundary (internet vs VPC/service perimeter).
    s.append(
        '<rect x="285" y="55" width="855" height="545" rx="16" ry="16" '
        'fill="none" stroke="#94a3b8" stroke-width="1.6" stroke-dasharray="3,4"/>'
    )
    s.append(
        '<text x="292" y="72" font-family="Helvetica,Arial,sans-serif" '
        'font-size="10" fill="#64748b">AWS account / service perimeter (internet boundary at API Gateway)</text>'
    )

    # Legend
    ly = 640
    s.append(
        f'<text x="40" y="{ly}" font-family="Helvetica,Arial,sans-serif" '
        f'font-size="13" font-weight="700" fill="{COL_TEXT}">Security control classes</text>'
    )
    ly += 16
    for i, (color, label) in enumerate(CONTROL_LEGEND):
        col = i % 2
        row = i // 2
        lx = 40 + col * 560
        yy = ly + row * 22
        s.append(f'<rect x="{lx}" y="{yy - 10}" width="14" height="14" rx="3" fill="{color}"/>')
        s.append(
            f'<text x="{lx + 22}" y="{yy + 1}" font-family="Helvetica,Arial,sans-serif" '
            f'font-size="11.5" fill="{COL_TEXT}">{escape(label)}</text>'
        )

    s.append("</svg>")
    return "\n".join(s) + "\n"


def main() -> int:
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    _OUT.write_text(build_svg(), encoding="utf-8")
    print(f"[render] wrote {_OUT.relative_to(_OUT.parents[1])} " f"({_OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
