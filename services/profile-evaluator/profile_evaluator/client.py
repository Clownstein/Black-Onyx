from __future__ import annotations

from typing import Any

import httpx

from profile_evaluator.config import Settings


class IncidentApiClient:
    """Thin HTTP client for the incident-api security-profile endpoints."""

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self._settings = settings
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=settings.http_timeout_sec)

    def _headers(self) -> dict[str, str]:
        headers = {
            "X-Tenant-Id": self._settings.tenant_id,
            "X-Role": self._settings.role,
        }
        if self._settings.incident_api_service_key:
            headers["X-Service-Key"] = self._settings.incident_api_service_key
        return headers

    def _url(self, path: str) -> str:
        return f"{self._settings.incident_api_url.rstrip('/')}{path}"

    def list_profiles(self) -> list[dict[str, Any]]:
        resp = self._client.get(
            self._url("/api/v1/security-profiles"), headers=self._headers()
        )
        resp.raise_for_status()
        data = resp.json()
        return list(data.get("items") or [])

    def evaluate_profile(self, profile_id: str) -> dict[str, Any]:
        resp = self._client.post(
            self._url(f"/api/v1/security-profiles/{profile_id}/evaluate"),
            headers=self._headers(),
        )
        resp.raise_for_status()
        return dict(resp.json())

    def create_finding(self, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._client.post(
            self._url("/api/v1/findings"), headers=self._headers(), json=body
        )
        resp.raise_for_status()
        return dict(resp.json())

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
