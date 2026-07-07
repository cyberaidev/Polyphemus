"""AWS Lambda entrypoint for Polyphemus behind an API Gateway HTTP API.

The API Gateway **JWT authorizer** validates the caller's token *before* this
handler runs, so the verified claims arrive in
``event["requestContext"]["authorizer"]["jwt"]["claims"]``. This handler maps
those claims to a :class:`UserContext`, runs the secure RAG pipeline, and returns
a sanitized response. The full evidence is written to the audit trail; only the
answer and non-sensitive metadata are returned to the caller.

This module imports only ``polyphemus`` (never boto3 directly). It runs unchanged
in mock mode, which is why ``tests``/local invocation can exercise it offline.
"""

from __future__ import annotations

import json
from typing import Any

from polyphemus.authz.identity import from_claims
from polyphemus.models import UserContext
from polyphemus.pipeline import SecureRAGPipeline

# Reuse a single pipeline across warm invocations.
_PIPELINE: SecureRAGPipeline | None = None


def _pipeline() -> SecureRAGPipeline:
    global _PIPELINE
    if _PIPELINE is None:
        _PIPELINE = SecureRAGPipeline()
    return _PIPELINE


def _extract_claims(event: dict[str, Any]) -> dict[str, Any]:
    """Pull JWT claims placed by the API Gateway authorizer (fail-closed)."""
    ctx = event.get("requestContext", {})
    authorizer = ctx.get("authorizer", {})
    jwt = authorizer.get("jwt", {})
    claims = jwt.get("claims")
    if claims:
        # Copy before normalizing so the caller's / fixture's dict is never mutated.
        claims = dict(claims)
        # Some group claims arrive as JSON-encoded strings; normalize.
        if isinstance(claims.get("cognito:groups"), str) and claims["cognito:groups"].startswith(
            "["
        ):
            try:
                claims["cognito:groups"] = json.loads(claims["cognito:groups"])
            except json.JSONDecodeError:
                pass
        return claims
    # Fallback for local testing: claims passed directly in the event.
    if "claims" in event:
        return event["claims"]
    raise PermissionError("no validated JWT claims present on the request")


def _extract_question(event: dict[str, Any]) -> str:
    body = event.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body = {}
    body = body or {}
    question = body.get("question") or event.get("question")
    if not question:
        raise ValueError("request body must include a 'question' field")
    return str(question)


def _response(status: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(payload),
    }


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Lambda handler: API Gateway event -> pipeline -> sanitized JSON response."""
    try:
        claims = _extract_claims(event)
        question = _extract_question(event)
    except PermissionError as exc:
        return _response(401, {"error": str(exc)})
    except ValueError as exc:
        return _response(400, {"error": str(exc)})

    user: UserContext = from_claims(claims)
    record = _pipeline().answer(user, question)

    # Return only non-sensitive fields; full evidence lives in the audit trail.
    return _response(
        200,
        {
            "request_id": record.request_id,
            "answer": record.response,
            "authorized_sources": record.retrieved_sources,
            "denied_source_count": len(record.denied_sources),
            "redaction_count": sum(e.count for e in record.redactions),
            "injection_flags": record.injection_flags,
            "model_id": record.model_id,
        },
    )
