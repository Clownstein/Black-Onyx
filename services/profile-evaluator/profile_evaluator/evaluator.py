from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from profile_evaluator.client import IncidentApiClient
from profile_evaluator.config import Settings
from profile_evaluator.novelty import vector_novelty_contributor
from profile_evaluator.probe import probe_targets

_SEVERITY_SCORE = {"info": 0.1, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 0.9}

# Checks bound to tls_probe_weak in profiles/bindings/detector_map.yaml
_TLS_PROBE_CHECK_IDS = (
    "nist.csf.protect.tls",
    "pci.4.tls-chd",
    "surface.webapp.headers",
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _probe_passed(result: dict[str, Any]) -> bool:
    if not result.get("reachable"):
        return False
    if not result.get("tls"):
        return False
    missing = result.get("missing_security_headers") or []
    # Require HSTS + at least half of the security headers.
    present = result.get("present_security_headers") or []
    return "strict-transport-security" in present and len(missing) <= 2


class ProfileEvaluator:
    """Evaluate active security profiles and emit synthetic regression findings.

    A synthetic finding is posted to incident-api when a check transitions from
    ``pass`` to ``fail`` between evaluation cycles. Probe results emit
    ``probe_ok`` / failure findings that drive coverage without silent passes.
    """

    def __init__(self, settings: Settings, client: IncidentApiClient) -> None:
        self._settings = settings
        self._client = client
        # (profile_id, check_id) -> last observed status
        self._previous_status: dict[tuple[str, str], str] = {}

    def _build_finding(
        self,
        profile_id: str,
        check: dict[str, Any],
        *,
        finding_type: str = "compliance_regression",
    ) -> dict[str, Any]:
        check_id = str(check.get("check_id"))
        severity = str(check.get("severity_default") or "medium")
        surfaces = [s for s in (check.get("surfaces") or []) if isinstance(s, str)] or ["code"]
        automation = check.get("automation")
        if automation not in ("auto", "manual", "hybrid"):
            automation = "auto"
        compliance = {
            "profile_pack_ids": list(check.get("pack_ids") or []),
            "check_ids": [check_id],
            "surfaces": surfaces,
            "automation": automation,
        }
        now = _now_iso()
        contributors = [
            {
                "name": "profile_check_regression"
                if finding_type == "compliance_regression"
                else finding_type,
                "check_id": check_id,
                "value": 1.0 if finding_type != "probe_ok" else 0.0,
                "weight": 1.0 if finding_type != "probe_ok" else 0.0,
            },
            vector_novelty_contributor(
                self._settings.vector_novelty_enabled,
                text=f"{profile_id}:{check_id}",
                qdrant_url=self._settings.qdrant_url,
                tenant_id=self._settings.tenant_id,
            ),
        ]
        return {
            "finding_id": f"profile-eval-{profile_id}-{check_id}",
            "finding_type": finding_type,
            "asset_id": profile_id,
            "model_name": "profile-evaluator",
            "model_version": "0.1.0",
            "raw_score": 0.0 if finding_type == "probe_ok" else 1.0,
            "calibrated_score": 0.0
            if finding_type == "probe_ok"
            else _SEVERITY_SCORE.get(severity, 0.5),
            "severity_hint": (
                None
                if finding_type == "probe_ok"
                else (severity if severity in ("low", "medium", "high", "critical") else None)
            ),
            "window": {"start": now, "end": now},
            "contributors": contributors,
            "category": ["compliance"],
            "compliance": compliance,
            "context": {
                "profile_id": profile_id,
                "check_id": check_id,
                "reason": check.get("reason") or finding_type,
                "title": check.get("title"),
                "compliance": compliance,
            },
        }

    def _emit_probe_findings(self, profile_id: str) -> list[str]:
        urls = self._settings.probe_url_list()
        if not urls:
            return []
        with httpx.Client(timeout=self._settings.probe_timeout_sec) as http:
            results = probe_targets(
                urls, client=http, timeout=self._settings.probe_timeout_sec
            )
        emitted: list[str] = []
        any_pass = any(_probe_passed(r) for r in results)
        any_fail = any(not _probe_passed(r) for r in results)
        for check_id in _TLS_PROBE_CHECK_IDS:
            if any_fail:
                finding = self._build_finding(
                    profile_id,
                    {
                        "check_id": check_id,
                        "title": check_id,
                        "severity_default": "medium",
                        "surfaces": ["webapp"],
                        "automation": "auto",
                        "pack_ids": [],
                        "reason": "tls_probe_weak",
                    },
                    finding_type="compliance_regression",
                )
            elif any_pass:
                finding = self._build_finding(
                    profile_id,
                    {
                        "check_id": check_id,
                        "title": check_id,
                        "severity_default": "info",
                        "surfaces": ["webapp"],
                        "automation": "auto",
                        "pack_ids": [],
                        "reason": "probe_ok",
                    },
                    finding_type="probe_ok",
                )
            else:
                continue
            self._client.create_finding(finding)
            emitted.append(finding["finding_id"])
        return emitted

    def evaluate_once(self) -> dict[str, Any]:
        profiles = self._client.list_profiles()
        active = [p for p in profiles if p.get("active")]
        evaluated: list[str] = []
        emitted: list[str] = []
        for profile in active:
            profile_id = str(profile.get("profile_id"))
            if not profile_id:
                continue
            emitted.extend(self._emit_probe_findings(profile_id))
            result = self._client.evaluate_profile(profile_id)
            evaluated.append(profile_id)
            for check in result.get("coverage") or []:
                check_id = str(check.get("check_id"))
                status = str(check.get("status"))
                key = (profile_id, check_id)
                previous = self._previous_status.get(key)
                if previous == "pass" and status == "fail":
                    finding = self._build_finding(profile_id, check)
                    self._client.create_finding(finding)
                    emitted.append(finding["finding_id"])
                self._previous_status[key] = status
        return {
            "evaluated_profiles": evaluated,
            "active_count": len(active),
            "emitted_findings": emitted,
            "evaluated_at": _now_iso(),
        }
