"""IdP connector parsers (Entra / Okta-shaped JSON)."""

from __future__ import annotations

from typing import Any


def normalize_entra_users(payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    rows = payload.get("value") if isinstance(payload, dict) else payload
    out: list[dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "user_id": str(row.get("id") or row.get("userPrincipalName") or ""),
                "email": str(row.get("mail") or row.get("userPrincipalName") or ""),
                "display_name": str(row.get("displayName") or ""),
                "active": bool(row.get("accountEnabled", True)),
                "mfa_registered": bool(
                    row.get("isMfaRegistered")
                    or row.get("mfaRegistered")
                    or (row.get("strongAuthenticationMethods") or [])
                ),
                "roles": list(row.get("roles") or row.get("assignedRoles") or []),
                "last_sign_in": row.get("lastSignInDateTime") or row.get("last_sign_in"),
                "source": "entra",
            }
        )
    return [u for u in out if u["user_id"] or u["email"]]


def normalize_okta_users(payload: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    rows = payload if isinstance(payload, list) else payload.get("users") or payload.get("value") or []
    out: list[dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        profile = row.get("profile") if isinstance(row.get("profile"), dict) else {}
        factor_evidence = row.get("factor_enrollment")
        if not isinstance(factor_evidence, dict):
            factor_evidence = {}
        explicit_mfa = row.get("mfa_registered")
        verified_mfa = (
            explicit_mfa
            if isinstance(explicit_mfa, bool) and row.get("mfa_evidence_verified") is True
            else factor_evidence.get("mfa_registered")
            if isinstance(factor_evidence.get("mfa_registered"), bool)
            and factor_evidence.get("verified") is True
            else None
        )
        out.append(
            {
                "user_id": str(row.get("id") or profile.get("login") or ""),
                "email": str(profile.get("email") or profile.get("login") or ""),
                "display_name": str(
                    profile.get("displayName")
                    or f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip()
                ),
                "active": str(row.get("status") or "").upper() in {"ACTIVE", "PROVISIONED", ""},
                # The core Users API's credential provider identifies the
                # sign-in mechanism, not factor enrollment. Enrollment is
                # unknown unless a verified factor/status surface supplied it.
                "mfa_registered": verified_mfa,
                "mfa_evidence_status": "verified" if verified_mfa is not None else "unknown",
                "roles": list(row.get("roles") or []),
                "last_sign_in": row.get("lastLogin") or row.get("last_sign_in"),
                "source": "okta",
            }
        )
    return [u for u in out if u["user_id"] or u["email"]]
