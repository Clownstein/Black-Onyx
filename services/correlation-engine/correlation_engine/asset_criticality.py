"""Tenant-scoped asset criticality lookup used by incident risk scoring."""

from __future__ import annotations

import math
import time
from urllib.parse import quote

import httpx

from correlation_engine.config import settings

_CACHE_TTL_SECONDS = 15.0
_CACHE_MAX_ENTRIES = 4096
_cache: dict[tuple[str, str], tuple[float, float]] = {}


async def resolve_asset_criticality(tenant_id: str, asset_id: str) -> float | None:
    """Return registry criticality for this tenant and asset.

    ``None`` preserves the local/offline configured default. In production the
    dependency is required, so missing credentials, an unregistered asset, or
    an invalid response prevents risk scoring from silently using a global
    value.
    """
    base_url = (settings.asset_registry_url or "").strip().rstrip("/")
    service_key = (settings.asset_registry_service_key or "").strip()
    if not base_url or not service_key:
        if settings.asset_registry_required:
            raise RuntimeError("tenant asset criticality requires an asset-registry URL and service key")
        return None

    tenant = tenant_id.strip()
    asset = asset_id.strip()
    if not tenant or not asset:
        raise ValueError("tenant_id and asset_id are required for asset criticality lookup")
    cache_key = (tenant, asset)
    now = time.monotonic()
    cached = _cache.get(cache_key)
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    url = f"{base_url}/api/v1/assets/{quote(asset, safe='')}"
    try:
        async with httpx.AsyncClient(
            timeout=3.0, trust_env=False, follow_redirects=False,
        ) as client:
            response = await client.get(
                url,
                headers={"X-Tenant-Id": tenant, "X-Service-Key": service_key},
            )
        if response.status_code == 404:
            raise RuntimeError("asset is not registered for the finding tenant")
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or body.get("tenant_id") != tenant or body.get("asset_id") != asset:
            raise ValueError("asset-registry returned a different tenant or asset")
        criticality = body.get("criticality")
        if (
            isinstance(criticality, bool)
            or not isinstance(criticality, (int, float))
            or not math.isfinite(float(criticality))
            or not 0.0 <= float(criticality) <= 1.0
        ):
            raise ValueError("asset-registry returned invalid criticality")
    except Exception as exc:
        if settings.asset_registry_required:
            raise RuntimeError("tenant asset criticality lookup failed") from exc
        return None

    if len(_cache) >= _CACHE_MAX_ENTRIES:
        expired = [key for key, (created, _) in _cache.items() if now - created >= _CACHE_TTL_SECONDS]
        for key in expired[: max(1, len(_cache) // 4)]:
            _cache.pop(key, None)
        if len(_cache) >= _CACHE_MAX_ENTRIES:
            _cache.pop(next(iter(_cache)))
    _cache[cache_key] = (now, float(criticality))
    return float(criticality)
