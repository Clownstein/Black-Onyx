"""Compatibility client for the response-orchestrator ownership boundary."""

from __future__ import annotations

from typing import Any

import httpx

from integration_hub.config import settings


def _headers(tenant_id: str | None = None) -> dict[str, str]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if settings.response_orchestrator_api_key:
        headers["X-API-Key"] = settings.response_orchestrator_api_key
    if tenant_id:
        headers["X-Tenant-Id"] = tenant_id
    return headers


def _request(
    method: str,
    path: str,
    *,
    tenant_id: str | None = None,
    json: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base = settings.response_orchestrator_url.rstrip("/")
    with httpx.Client(timeout=settings.response_orchestrator_timeout_seconds) as client:
        response = client.request(
            method,
            f"{base}{path}",
            headers=_headers(tenant_id),
            json=json,
            params=params,
        )
        response.raise_for_status()
        return response.json()


def create_request(payload: dict[str, Any]) -> dict[str, Any]:
    return _request(
        "POST",
        "/api/v1/response/request",
        tenant_id=str(payload["tenant_id"]),
        json=payload,
    )


def approve_request(
    request_id: str,
    *,
    tenant_id: str,
    actor: str,
    dry_run: bool | None,
) -> dict[str, Any]:
    return _request(
        "POST",
        f"/api/v1/response/{request_id}/approve",
        tenant_id=tenant_id,
        json={"actor": actor, "dry_run": dry_run},
    )


def list_audit(tenant_id: str, limit: int) -> dict[str, Any]:
    return _request(
        "GET",
        "/api/v1/response/audit",
        tenant_id=tenant_id,
        params={"limit": limit},
    )
