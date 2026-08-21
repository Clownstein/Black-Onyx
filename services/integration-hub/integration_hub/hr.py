"""HR / joiner-mover-leaver CSV and webhook parsers."""

from __future__ import annotations

import csv
import io
from typing import Any


def parse_hr_csv(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    out: list[dict[str, Any]] = []
    for row in reader:
        status = str(row.get("status") or row.get("employment_status") or "active").lower()
        out.append(
            {
                "employee_id": str(row.get("employee_id") or row.get("id") or "").strip(),
                "email": str(row.get("email") or "").strip().lower(),
                "manager": str(row.get("manager") or "").strip(),
                "status": status,
                "terminated": status in {"terminated", "inactive", "leave"},
                "start_date": row.get("start_date"),
                "end_date": row.get("end_date"),
            }
        )
    return [r for r in out if r["employee_id"] or r["email"]]


def parse_hr_webhook(payload: dict[str, Any]) -> list[dict[str, Any]]:
    employees = payload.get("employees") or payload.get("value") or [payload]
    out: list[dict[str, Any]] = []
    for row in employees:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "active").lower()
        out.append(
            {
                "employee_id": str(row.get("employee_id") or row.get("id") or ""),
                "email": str(row.get("email") or "").lower(),
                "manager": str(row.get("manager") or ""),
                "status": status,
                "terminated": status in {"terminated", "inactive", "leave"},
                "start_date": row.get("start_date"),
                "end_date": row.get("end_date"),
            }
        )
    return [r for r in out if r["employee_id"] or r["email"]]


def evaluate_identity_checks(
    idp_users: list[dict[str, Any]],
    hr_employees: list[dict[str, Any]],
    *,
    mfa_required_roles: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Produce check findings for MFA gaps, terminated-but-active, shared admins."""
    mfa_required_roles = [
        r.lower() for r in (mfa_required_roles or ["admin", "global administrator"])
    ]
    hr_by_email = {e["email"]: e for e in hr_employees if e.get("email")}
    findings: list[dict[str, Any]] = []

    def _fail(check_id: str, email: str, detail: str, pack_checks: list[str]) -> None:
        findings.append(
            {
                "check_id": check_id,
                "status": "fail",
                "email": email,
                "detail": detail,
                "compliance": {
                    "profile_pack_ids": ["surface-identity"],
                    "check_ids": [check_id, *pack_checks],
                    "surfaces": ["identity"],
                    "automation": "auto",
                },
            }
        )

    for user in idp_users:
        email = (user.get("email") or "").lower()
        roles = [str(r).lower() for r in (user.get("roles") or [])]
        privileged = any(r in mfa_required_roles or "admin" in r for r in roles)
        if privileged and not user.get("mfa_registered"):
            _fail(
                "identity.privileged-without-mfa",
                email,
                "privileged role without MFA registration",
                ["nist.csf.protect.mfa", "surface.identity.mfa-gaps"],
            )
        hr = hr_by_email.get(email)
        if hr and hr.get("terminated") and user.get("active"):
            _fail(
                "identity.terminated-still-active",
                email,
                "HR terminated but IdP account still active",
                ["surface.identity.joiner-mover"],
            )
        display = (user.get("display_name") or "").lower()
        if user.get("active") and (
            email.startswith("admin@")
            or "shared" in display
            or email.startswith("noreply")
        ):
            _fail(
                "identity.shared-admin-usage",
                email,
                "shared/generic admin account appears active",
                ["surface.identity.shared-accounts"],
            )

    idp_emails = {(u.get("email") or "").lower() for u in idp_users}
    for emp in hr_employees:
        if emp.get("terminated"):
            continue
        email = (emp.get("email") or "").lower()
        if email and email not in idp_emails:
            _fail(
                "identity.joiner-missing-idp",
                email,
                "active HR employee missing IdP account / MFA onboarding",
                ["surface.identity.joiner-mover"],
            )
    return findings
