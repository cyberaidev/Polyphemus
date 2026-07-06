"""Translate validated IdP claims into a :class:`UserContext`.

Supports both Amazon Cognito and Microsoft Entra ID claim shapes. In a real
deployment these claims arrive already validated by the API Gateway JWT
authorizer; this module only maps them — it does not verify signatures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from polyphemus.models import Classification, UserContext

_REPO_ROOT = Path(__file__).resolve().parents[3]
_USERS_FIXTURE = _REPO_ROOT / "data" / "fixtures" / "users.json"

_VALID_CLEARANCE = {"public", "internal", "hr_confidential", "finance_confidential"}


def from_claims(claims: dict) -> UserContext:
    """Build a UserContext from Cognito- or Entra-shaped claims (fail-closed)."""
    subject = claims.get("sub") or claims.get("oid") or "unknown"

    username = (
        claims.get("cognito:username")
        or claims.get("preferred_username")
        or claims.get("upn")
        or claims.get("email")
        or subject
    )

    # Groups: Cognito uses "cognito:groups"; Entra uses "groups" (or "roles").
    groups = claims.get("cognito:groups") or claims.get("groups") or claims.get("roles") or []
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]

    department = claims.get("custom:department") or claims.get("department") or None

    raw_clearance = claims.get("custom:clearance") or claims.get("clearance") or "public"
    # Fail closed: any unrecognized clearance collapses to "public".
    clearance: Classification = (
        cast(Classification, raw_clearance) if raw_clearance in _VALID_CLEARANCE else "public"
    )

    idp = claims.get("idp") or ("entra" if ("oid" in claims or "upn" in claims) else "cognito")

    return UserContext(
        subject=subject,
        username=str(username),
        groups=list(groups),
        department=department,
        clearance=clearance,
        idp=idp,
    )


def from_fixture(user_id: str) -> UserContext:
    """Build a UserContext for a named demo user from the fixture file."""
    with _USERS_FIXTURE.open("r", encoding="utf-8") as fh:
        users = json.load(fh)["users"]
    if user_id not in users:
        raise KeyError(f"unknown fixture user: {user_id}")
    return from_claims(users[user_id]["claims"])
