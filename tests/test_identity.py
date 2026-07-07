"""identity.from_claims: Cognito/Entra claim mapping, fail-closed defaults."""

from __future__ import annotations

from polyphemus.authz.identity import from_claims


def test_unknown_clearance_fails_closed_to_public():
    user = from_claims(
        {"sub": "u1", "cognito:groups": ["finance"], "custom:clearance": "cosmic_top_secret"}
    )
    assert user.clearance == "public"


def test_entra_shape_sets_idp_and_username_from_upn():
    user = from_claims(
        {
            "oid": "entra-oid-123",
            "upn": "jane@corp.example",
            "groups": ["hr"],
            "clearance": "hr_confidential",
        }
    )
    assert user.idp == "entra"
    assert user.username == "jane@corp.example"
    assert user.subject == "entra-oid-123"
    assert user.groups == ["hr"]
    assert user.clearance == "hr_confidential"


def test_comma_string_groups_are_split_into_list():
    user = from_claims({"sub": "u2", "groups": "finance, admin ,staff"})
    assert user.groups == ["finance", "admin", "staff"]


def test_empty_claims_fail_closed():
    user = from_claims({})
    assert user.subject == "unknown"
    assert user.clearance == "public"
    assert user.groups == []
    # No Entra markers -> defaults to cognito.
    assert user.idp == "cognito"


def test_roles_claim_used_as_group_fallback():
    user = from_claims({"sub": "u3", "roles": ["admin"]})
    assert user.groups == ["admin"]


def test_cognito_username_and_department_mapping():
    user = from_claims(
        {
            "sub": "u4",
            "cognito:username": "fiona.finance",
            "cognito:groups": ["finance"],
            "custom:department": "finance",
            "custom:clearance": "finance_confidential",
        }
    )
    assert user.username == "fiona.finance"
    assert user.department == "finance"
    assert user.idp == "cognito"
    assert user.clearance == "finance_confidential"
