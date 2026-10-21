from integration_hub.hr import evaluate_identity_checks, parse_hr_csv
from integration_hub.idp import normalize_entra_users, normalize_okta_users


def test_entra_and_hr_joiner_checks() -> None:
    users = normalize_entra_users(
        {
            "value": [
                {
                    "id": "u1",
                    "mail": "admin@example.com",
                    "displayName": "Shared Admin",
                    "accountEnabled": True,
                    "isMfaRegistered": False,
                    "roles": ["Global Administrator"],
                },
                {
                    "id": "u2",
                    "mail": "alice@example.com",
                    "displayName": "Alice",
                    "accountEnabled": True,
                    "isMfaRegistered": True,
                    "roles": ["user"],
                },
            ]
        }
    )
    hr = parse_hr_csv(
        "employee_id,email,status,manager\n"
        "e1,alice@example.com,active,bob\n"
        "e2,bob@example.com,active,carol\n"
        "e3,old@example.com,terminated,carol\n"
    )
    # mark old user still active in IdP
    users.append(
        {
            "user_id": "u3",
            "email": "old@example.com",
            "display_name": "Old",
            "active": True,
            "mfa_registered": True,
            "roles": [],
            "source": "entra",
        }
    )
    findings = evaluate_identity_checks(users, hr)
    ids = {f["check_id"] for f in findings}
    assert "identity.privileged-without-mfa" in ids
    assert "identity.terminated-still-active" in ids
    assert "identity.joiner-missing-idp" in ids


def test_okta_provider_does_not_claim_factor_enrollment() -> None:
    users = normalize_okta_users([{
        "id": "okta-user-1",
        "status": "ACTIVE",
        "credentials": {"provider": "OKTA"},
        "profile": {
            "email": "admin@example.com",
            "displayName": "Admin",
        },
        "roles": ["Global Administrator"],
    }])
    assert users[0]["mfa_registered"] is None
    assert users[0]["mfa_evidence_status"] == "unknown"
    findings = evaluate_identity_checks(users, [])
    by_id = {item["check_id"]: item for item in findings}
    assert by_id["identity.privileged-mfa-status-unknown"]["status"] == "unknown"
    assert "identity.privileged-without-mfa" not in by_id


def test_okta_verified_factor_enrollment_is_preserved() -> None:
    users = normalize_okta_users([{
        "id": "okta-user-2",
        "status": "ACTIVE",
        "credentials": {"provider": "OKTA"},
        "factor_enrollment": {"verified": True, "mfa_registered": False},
        "profile": {"email": "admin@example.com"},
        "roles": ["admin"],
    }])
    assert users[0]["mfa_registered"] is False
    assert users[0]["mfa_evidence_status"] == "verified"
    assert evaluate_identity_checks(users, [])[0]["check_id"] == "identity.privileged-without-mfa"
