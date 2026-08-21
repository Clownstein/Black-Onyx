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
        out.append(
            {
                "user_id": str(row.get("id") or profile.get("login") or ""),
                "email": str(profile.get("email") or profile.get("login") or ""),
                "display_name": str(
                    profile.get("displayName")
                    or f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip()
                ),
                "active": str(row.get("status") or "").upper() in {"ACTIVE", "PROVISIONED", ""},
                "mfa_registered": bool(row.get("mfa_registered") or row.get("credentials", {}).get("provider") == "OKTA"),
                "roles": list(row.get("roles") or []),
                "last_sign_in": row.get("lastLogin") or row.get("last_sign_in"),
                "source": "okta",
            }
        )
    return [u for u in out if u["user_id"] or u["email"]]
