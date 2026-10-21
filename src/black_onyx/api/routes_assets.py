"""Asset CMDB API CRUD, CSV import, case links, posture board."""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from black_onyx.api.service import get_service
from black_onyx.auth.dependencies import current_principal, require_analyst
from black_onyx.auth.service import Principal
from black_onyx.detection_auth import mint_detection_token

logger = logging.getLogger(__name__)

assets_router = APIRouter(tags=["assets"])


class AssetRegistryUnavailable(RuntimeError):
    """The authoritative registry could not answer a request."""


def _get_service():
    return get_service()


def _registry_base() -> str:
    return os.environ.get("BLACK_ONYX_ASSET_REGISTRY_URL", "http://asset-registry:8081").rstrip("/")


def _incident_base() -> str:
    return os.environ.get("BLACK_ONYX_INCIDENT_API_URL", "http://incident-api:8083").rstrip("/")


def _registry_headers(user: Principal | None = None) -> dict[str, str]:
    """Headers for asset-registry. Prefer session-minted JWT so audit subject is human."""
    tenant = os.environ.get("BLACK_ONYX_DETECTION_TENANT", "").strip()
    if not tenant:
        raise HTTPException(status_code=503, detail="Detection tenant is not configured")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Tenant-Id": tenant,
    }
    if user is not None:
        token = mint_detection_token(
            subject=user.email or user.user_id,
            role=user.role.value,
            tenant_id=tenant,
        )
        headers["Authorization"] = f"Bearer {token}"
        headers["X-Role"] = user.role.value
        return headers
    key = (
        os.environ.get("ASSET_REGISTRY_SERVICE_KEY")
        or os.environ.get("INCIDENT_API_SERVICE_KEY")
        or ""
    ).strip()
    if key:
        headers["X-Service-Key"] = key
        headers["Authorization"] = f"Bearer {key}"
    return headers


_CRIT_MAP = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


def _registry_payload_from_tip(row: dict[str, Any]) -> dict[str, Any]:
    hostname = str(row.get("hostname") or row.get("name") or row.get("asset_id") or "").strip()
    asset_id = str(row.get("asset_id") or hostname).strip().lower().replace(" ", "-")
    tags = row.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    return {
        "asset_id": asset_id,
        "name": hostname or asset_id,
        "asset_type": str(row.get("asset_type") or "host"),
        "criticality": float(_CRIT_MAP.get(str(row.get("criticality") or "medium").lower(), 0.5)),
        "owner_team": str(row.get("owner") or "") or None,
        "ip_address": str(row.get("ip_address") or "") or None,
        "notes": str(row.get("notes") or "") or None,
        "tags": {str(t): "true" for t in tags},
        "active": True,
    }


def _normalize_registry_row(row: dict[str, Any]) -> dict[str, Any]:
    tags = row.get("tags") or {}
    if isinstance(tags, dict):
        tag_list = list(tags.keys())
    elif isinstance(tags, list):
        tag_list = tags
    else:
        tag_list = []
    crit = row.get("criticality")
    if isinstance(crit, (int, float)):
        crit_label = (
            "critical" if crit >= 0.9 else
            "high" if crit >= 0.7 else
            "medium" if crit >= 0.4 else
            "low"
        )
    else:
        crit_label = str(crit or "medium")
    return {
        "asset_id": row.get("asset_id") or row.get("id"),
        "hostname": row.get("name") or row.get("hostname") or row.get("asset_id"),
        "asset_type": row.get("asset_type") or row.get("kind") or "host",
        "criticality": crit_label,
        "owner": row.get("owner_team") or row.get("owner") or "",
        "ip_address": row.get("ip_address") or "",
        "notes": row.get("notes") or "",
        "tags": tag_list,
        "last_seen": row.get("updated_at") or row.get("last_seen") or row.get("created_at"),
        "source": "asset-registry",
        "raw": row,
    }


def _normalize_tip_asset(row: dict[str, Any]) -> dict[str, Any]:
    tags = row.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    return {
        "asset_id": row.get("asset_id") or row.get("id"),
        "hostname": row.get("hostname") or row.get("name") or row.get("asset_id"),
        "asset_type": row.get("asset_type") or row.get("type") or "host",
        "criticality": row.get("criticality") or "medium",
        "owner": row.get("owner") or "",
        "ip_address": row.get("ip_address") or "",
        "notes": row.get("notes") or "",
        "tags": tags,
        "last_seen": row.get("last_seen") or row.get("updated_at"),
        "source": "tip_sqlite",
    }


def _resolve_tip_asset(service: Any, asset_id: str) -> dict[str, Any] | None:
    tip = service.asset_manager.get_asset(asset_id)
    if tip:
        return _normalize_tip_asset(tip)
    needle = asset_id.strip().lower()
    for row in service.asset_manager.list_assets(limit=5000):
        if not isinstance(row, dict):
            continue
        candidates = {
            str(row.get("asset_id") or "").strip().lower(),
            str(row.get("hostname") or "").strip().lower(),
            str(row.get("name") or "").strip().lower(),
        }
        if needle and needle in candidates:
            return _normalize_tip_asset(row)
    return None


async def _fetch_registry_asset(asset_id: str, user: Principal | None = None) -> dict[str, Any] | None:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{_registry_base()}/api/v1/assets/{asset_id}",
                headers=_registry_headers(user),
            )
            if resp.status_code == 404:
                return None
            if resp.status_code >= 400:
                raise AssetRegistryUnavailable(
                    f"asset registry returned HTTP {resp.status_code}"
                )
            body = resp.json() if resp.content else None
            return body if isinstance(body, dict) else None
    except AssetRegistryUnavailable:
        raise
    except Exception as exc:
        raise AssetRegistryUnavailable("asset registry unavailable") from exc


async def _upsert_registry_asset(payload: dict[str, Any], user: Principal | None = None) -> bool:
    asset_id = str(payload.get("asset_id") or "")
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.put(
                f"{_registry_base()}/api/v1/assets/{asset_id}",
                json={key: value for key, value in payload.items() if key != "asset_id"},
                headers=_registry_headers(user),
            )
            if resp.status_code in (200, 201):
                return True
    except Exception:
        return False
    return False


async def _list_registry_assets(user: Principal | None = None) -> list[dict[str, Any]]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{_registry_base()}/api/v1/assets",
                headers=_registry_headers(user),
                params={"active": True},
            )
            if resp.status_code >= 400:
                raise AssetRegistryUnavailable(
                    f"asset registry returned HTTP {resp.status_code}"
                )
            body = resp.json() if resp.content else []
            rows = body if isinstance(body, list) else (body.get("items") or body.get("assets") or [])
            return [
                _normalize_registry_row(row)
                for row in rows
                if isinstance(row, dict)
            ]
    except AssetRegistryUnavailable:
        raise
    except Exception as exc:
        raise AssetRegistryUnavailable("asset registry unavailable") from exc


class AssetCreateRequest(BaseModel):
    hostname: str = Field(default="", max_length=255)
    ip_address: str = Field(default="", max_length=64)
    asset_type: str = Field(default="host", max_length=64)
    owner: str = Field(default="", max_length=200)
    criticality: str = Field(default="medium", max_length=32)
    tags: list[str] = Field(default_factory=list, max_length=100)
    notes: str = Field(default="", max_length=10_000)


class AssetUpdateRequest(BaseModel):
    hostname: Optional[str] = Field(default=None, max_length=255)
    ip_address: Optional[str] = Field(default=None, max_length=64)
    asset_type: Optional[str] = Field(default=None, max_length=64)
    owner: Optional[str] = Field(default=None, max_length=200)
    criticality: Optional[str] = Field(default=None, max_length=32)
    tags: Optional[list[str]] = Field(default=None, max_length=100)
    notes: Optional[str] = Field(default=None, max_length=10_000)


class AssetCsvImportRequest(BaseModel):
    csv: str = Field(min_length=1, max_length=5_000_000)


class AssetCaseLinkRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=64)


class FindingCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    asset_id: Optional[str] = Field(default=None, max_length=64)
    severity: str = Field(default="medium", max_length=32)
    status: str = Field(default="open", max_length=32)
    category: str = Field(default="misconfiguration", max_length=64)
    description: str = Field(default="", max_length=10_000)
    source: str = Field(default="", max_length=200)


class FindingUpdateRequest(BaseModel):
    title: Optional[str] = Field(default=None, max_length=500)
    asset_id: Optional[str] = Field(default=None, max_length=64)
    severity: Optional[str] = Field(default=None, max_length=32)
    status: Optional[str] = Field(default=None, max_length=32)
    category: Optional[str] = Field(default=None, max_length=64)
    description: Optional[str] = Field(default=None, max_length=10_000)
    source: Optional[str] = Field(default=None, max_length=200)


@assets_router.get("/api/v1/assets")
async def list_assets(
    limit: int = 200,
    user: Principal = Depends(current_principal),
) -> dict[str, Any]:
    """Return authoritative Postgres asset-registry inventory plus TIP assets not yet in the registry."""
    limit = max(1, min(limit, 1000))
    try:
        normalized = await _list_registry_assets(user)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Asset registry unavailable") from exc
    registry_ids = {
        str(row.get("asset_id") or "").strip().lower()
        for row in normalized
        if str(row.get("asset_id") or "").strip()
    }
    registry_hostnames = {
        str(row.get("hostname") or row.get("name") or "").strip().lower()
        for row in normalized
        if str(row.get("hostname") or row.get("name") or "").strip()
    }
    legacy_candidates: list[dict[str, Any]] = []
    for tip_row in _get_service().asset_manager.list_assets(limit=5000):
        if not isinstance(tip_row, dict):
            continue
        asset_id = str(tip_row.get("asset_id") or "").strip().lower()
        hostname = str(tip_row.get("hostname") or tip_row.get("name") or "").strip().lower()
        if asset_id and asset_id in registry_ids:
            continue
        if hostname and hostname in registry_hostnames:
            continue
        legacy_candidates.append(_normalize_tip_asset(tip_row))
    return {
        "assets": normalized[:limit],
        "n": len(normalized[:limit]),
        "sor": "asset_registry",
        "legacy_candidates": legacy_candidates[:limit],
        "legacy_n": len(legacy_candidates),
    }


@assets_router.post("/api/v1/assets/migrate")
async def migrate_assets_to_registry(
    user: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Copy TIP SQLite assets into Postgres asset-registry (detection SoR)."""
    tip_assets = _get_service().asset_manager.list_assets(limit=5000)
    migrated = 0
    skipped = 0
    errors: list[str] = []
    for row in tip_assets:
        hostname = str(row.get("hostname") or row.get("name") or "").strip()
        asset_id = str(row.get("asset_id") or hostname).strip()
        if not hostname and not asset_id:
            skipped += 1
            continue
        payload = _registry_payload_from_tip(row)
        ok = await _upsert_registry_asset(payload, user)
        if ok:
            migrated += 1
        else:
            errors.append(f"{payload.get('asset_id')}: registry upsert failed")
    return {
        "status": "ok",
        "migrated": migrated,
        "skipped": skipped,
        "errors": errors[:20],
        "tip_total": len(tip_assets),
    }


@assets_router.post("/api/v1/assets")
async def create_asset(
    req: AssetCreateRequest,
    user: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Create in Postgres asset-registry (SoR). TIP SQLite is not dual-written."""
    if not req.hostname and not req.ip_address:
        raise HTTPException(status_code=422, detail="hostname or ip_address is required")
    tip_shaped = {
        "hostname": req.hostname or req.ip_address,
        "asset_id": (req.hostname or req.ip_address).lower().replace(" ", "-"),
        "asset_type": req.asset_type,
        "owner": req.owner,
        "criticality": req.criticality,
        "tags": req.tags,
        "ip_address": req.ip_address,
        "notes": req.notes,
    }
    payload = _registry_payload_from_tip(tip_shaped)
    ok = await _upsert_registry_asset(payload, user)
    if not ok:
        raise HTTPException(status_code=502, detail="Asset registry unavailable")
    refreshed = await _fetch_registry_asset(str(payload["asset_id"]), user)
    return {
        **_normalize_registry_row(refreshed or payload),
        "sor": "asset_registry",
        "registry": True,
    }


@assets_router.get("/api/v1/assets/posture/board")
async def posture_board(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    return _get_service().asset_manager.posture_board()


@assets_router.post("/api/v1/assets/import/csv")
async def import_assets_csv(
    req: AssetCsvImportRequest,
    user: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Import into Postgres asset-registry SoR only (no TIP SQLite dual-write)."""
    import csv
    import io

    created = 0
    skipped = 0
    errors: list[str] = []
    reader = csv.DictReader(io.StringIO(req.csv))
    for i, row in enumerate(reader, start=1):
        hostname = (row.get("hostname") or row.get("host") or "").strip()
        ip_address = (row.get("ip_address") or row.get("ip") or "").strip()
        if not hostname and not ip_address:
            skipped += 1
            errors.append(f"row {i}: missing hostname and ip")
            continue
        tip_shaped = {
            "asset_id": (hostname or ip_address).lower().replace(" ", "-"),
            "hostname": hostname or ip_address,
            "asset_type": (row.get("asset_type") or "host").strip(),
            "owner": (row.get("owner") or "").strip(),
            "criticality": (row.get("criticality") or "medium").strip(),
            "tags": [t.strip() for t in (row.get("tags") or "").split(",") if t.strip()],
            "ip_address": ip_address,
            "notes": (row.get("notes") or "").strip(),
        }
        ok = await _upsert_registry_asset(_registry_payload_from_tip(tip_shaped), user)
        if ok:
            created += 1
        else:
            skipped += 1
            errors.append(f"row {i}: registry upsert failed")
    return {
        "status": "ok",
        "created": created,
        "skipped": skipped,
        "errors": errors[:50],
        "registry_created": created,
        "sor": "asset_registry",
    }


@assets_router.get("/api/v1/assets/findings")
async def list_findings(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 200,
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    findings = _get_service().asset_manager.list_findings(
        status=status, severity=severity, limit=max(1, min(limit, 1000)),
    )
    return {"findings": findings, "n": len(findings)}


@assets_router.post("/api/v1/assets/findings")
async def create_finding(
    req: FindingCreateRequest,
    user: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    if req.asset_id and not _get_service().asset_manager.get_asset(req.asset_id):
        registry = await _fetch_registry_asset(req.asset_id, user)
        if not registry:
            raise HTTPException(status_code=404, detail="Asset not found")
    return _get_service().asset_manager.create_finding(**req.model_dump())


@assets_router.patch("/api/v1/assets/findings/{finding_id}")
async def update_finding(
    finding_id: str,
    req: FindingUpdateRequest,
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    if not _get_service().asset_manager.get_finding(finding_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    return _get_service().asset_manager.update_finding(finding_id, **updates)  # type: ignore[return-value]


def _asset_needles(asset: dict[str, Any]) -> set[str]:
    needles: set[str] = set()
    asset_id = str(asset.get("asset_id") or "").strip().lower()
    if asset_id:
        needles.add(asset_id)
    for key in ("hostname", "ip_address", "name"):
        value = str(asset.get(key) or "").strip().lower()
        if value:
            needles.add(value)
            if value.startswith("user:"):
                needles.add(value[5:])
    tags = asset.get("tags") or []
    tag_items: list[str] = []
    if isinstance(tags, dict):
        tag_items.extend(str(k) for k in tags.keys())
        for key in ("wazuh_agent_id", "wazuh:agent_id", "agent_id"):
            agent = tags.get(key)
            if agent:
                tag_items.append(f"wazuh:{agent}")
    elif isinstance(tags, list):
        tag_items.extend(str(t) for t in tags)
    for tag in tag_items:
        text = tag.strip().lower()
        if not text:
            continue
        needles.add(text)
        if text.startswith("wazuh:"):
            needles.add(text)
        elif text.isdigit() or (len(text) <= 8 and text.replace("-", "").isalnum()):
            needles.add(f"wazuh:{text}")
    raw = asset.get("raw") if isinstance(asset.get("raw"), dict) else {}
    for key in ("wazuh_agent_id", "agent_id"):
        agent = raw.get(key)
        if agent:
            needles.add(f"wazuh:{str(agent).strip().lower()}")
    return needles


def _finding_matches_asset(finding: dict[str, Any], asset_id: str, needles: set[str]) -> bool:
    fid = str(finding.get("asset_id") or "").strip()
    if not fid:
        return False
    if fid == asset_id:
        return True
    lowered = fid.lower()
    if lowered in needles:
        return True
    if lowered.startswith("wazuh:") and lowered in needles:
        return True
    return any(lowered == n or (n.startswith("wazuh:") and lowered == n) for n in needles)


async def _fetch_related_incidents(
    asset_id: str,
    needles: set[str],
    user: Principal,
) -> tuple[list[dict[str, Any]], str | None]:
    """Incidents whose assets intersect the asset's ids/aliases.

    Returns (incidents, error). ``error`` is set when incident-api could not be
    queried so the UI can say "unavailable" instead of "no incidents".
    """
    keys = sorted({asset_id.strip().lower(), *(n.strip().lower() for n in needles if n)} - {""})[:50]
    if not keys:
        return [], None
    headers = _registry_headers(user)
    url = f"{_incident_base()}/api/v1/incidents"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers, params=[("asset", k) for k in keys])
    except httpx.HTTPError as exc:
        logger.warning("incident-api unreachable for asset %s: %s", asset_id, exc)
        return [], "incident-api unreachable"
    if resp.status_code >= 400:
        logger.warning("incident-api returned HTTP %s for asset %s", resp.status_code, asset_id)
        return [], f"incident-api returned HTTP {resp.status_code}"
    try:
        body = resp.json() if resp.content else {}
    except ValueError:
        return [], "incident-api returned invalid JSON"
    rows = body if isinstance(body, list) else (body.get("items") or [])
    key_set = set(keys)
    related: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        # Defence in depth: keep only rows that really touch this asset.
        if not key_set.intersection(str(a).lower() for a in (row.get("assets") or [])):
            continue
        related.append({
            "incident_id": row.get("incident_id"),
            "title": row.get("title") or row.get("summary"),
            "severity": row.get("severity"),
            "status": row.get("status"),
            "updated_at": row.get("updated_at") or row.get("last_seen"),
            "created_at": row.get("created_at") or row.get("first_seen"),
        })
    return related[:50], None


def _detection_matches_asset(det: dict[str, Any], needles: set[str], asset_id: str) -> bool:
    det_asset = str(det.get("asset_id") or "").strip().lower()
    enrichment = det.get("enrichment_data")
    if isinstance(enrichment, dict):
        nested_asset = str(enrichment.get("asset_id") or "").strip().lower()
        if nested_asset == asset_id.strip().lower() or nested_asset in needles:
            return True
    if asset_id and det_asset == asset_id.strip().lower():
        return True
    if det_asset and det_asset in needles:
        return True
    host = str(det.get("hostname") or "").strip().lower()
    user = str(det.get("username") or "").strip().lower()
    if host in needles or user in needles:
        return True
    return any(n and (n in host or n in user) for n in needles)


def _related_intel_for_asset(service: Any, asset: dict[str, Any]) -> dict[str, Any]:
    """Best-effort related alerts/detections/IOCs keyed by hostname or IP."""
    needles = _asset_needles(asset)
    related_alerts: list[dict[str, Any]] = []
    related_iocs: list[dict[str, str]] = []
    seen_iocs: set[str] = set()
    if needles and getattr(service, "watchlist_manager", None):
        try:
            for alert in service.watchlist_manager.get_alerts(limit=300):
                value = str(alert.get("ioc_value") or "").strip().lower()
                if not value:
                    continue
                if value not in needles and not any(n and n in value for n in needles):
                    continue
                related_alerts.append({
                    "alert_id": alert.get("alert_id") or alert.get("id"),
                    "ioc_type": alert.get("ioc_type"),
                    "ioc_value": alert.get("ioc_value"),
                    "watchlist_name": alert.get("watchlist_name"),
                    "disposition": alert.get("disposition"),
                    "triggered_at": alert.get("triggered_at"),
                    "acknowledged": alert.get("acknowledged"),
                })
                ioc_key = f"{alert.get('ioc_type')}:{value}"
                if ioc_key not in seen_iocs:
                    seen_iocs.add(ioc_key)
                    related_iocs.append({
                        "ioc_type": str(alert.get("ioc_type") or ""),
                        "ioc_value": str(alert.get("ioc_value") or ""),
                    })
        except Exception:
            pass
    related_detections: list[dict[str, Any]] = []
    asset_id = str(asset.get("asset_id") or "")
    if needles and getattr(service, "connector_manager", None) and getattr(service, "qdrant_store", None):
        try:
            for det in service.connector_manager.list_recent_detections(service.qdrant_store, limit=200):
                if not _detection_matches_asset(det, needles, asset_id):
                    continue
                related_detections.append({
                        "title": det.get("title"),
                        "detection_key": det.get("detection_key") or det.get("source_file"),
                        "connector": det.get("connector"),
                        "severity": det.get("severity"),
                        "hostname": det.get("hostname"),
                        "event_time": det.get("event_time") or det.get("indexed_at"),
                        "disposition": det.get("disposition"),
                    })
        except Exception:
            pass
    return {
        "related_alerts": related_alerts[:50],
        "related_detections": related_detections[:50],
        "related_iocs": related_iocs[:50],
    }


@assets_router.get("/api/v1/assets/{asset_id}")
async def get_asset(
    asset_id: str,
    user: Principal = Depends(current_principal),
) -> dict[str, Any]:
    service = _get_service()
    sor = "asset_registry"
    try:
        registry = await _fetch_registry_asset(asset_id, user)
    except AssetRegistryUnavailable as exc:
        raise HTTPException(status_code=502, detail="Asset registry unavailable") from exc
    if registry:
        asset = _normalize_registry_row(registry)
    else:
        tip_asset = _resolve_tip_asset(service, asset_id)
        if not tip_asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        asset = tip_asset
        sor = "tip_legacy_read"
    needles = _asset_needles(asset)
    resolved_id = str(asset.get("asset_id") or asset_id)
    links = service.asset_manager.list_case_links(asset_id=resolved_id)
    findings = [
        f for f in service.asset_manager.list_findings(limit=500)
        if _finding_matches_asset(f, resolved_id, needles)
    ]
    related = _related_intel_for_asset(service, asset)
    related_incidents, related_incidents_error = await _fetch_related_incidents(
        resolved_id, needles, user
    )
    return {
        **asset,
        "case_links": links,
        "findings": findings,
        **related,
        "related_incidents": related_incidents,
        "related_incidents_error": related_incidents_error,
        "sor": sor,
    }


@assets_router.patch("/api/v1/assets/{asset_id}")
async def update_asset(
    asset_id: str,
    req: AssetUpdateRequest,
    user: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Update only the authoritative asset registry."""
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    try:
        registry = await _fetch_registry_asset(asset_id, user)
    except AssetRegistryUnavailable as exc:
        raise HTTPException(status_code=502, detail="Asset registry unavailable") from exc
    if not registry:
        raise HTTPException(status_code=404, detail="Asset not found")
    merged = {**_normalize_registry_row(registry), **updates}
    ok = await _upsert_registry_asset(_registry_payload_from_tip(merged), user)
    if not ok:
        raise HTTPException(status_code=502, detail="Failed to update asset registry")
    refreshed = await _fetch_registry_asset(asset_id, user)
    return {**_normalize_registry_row(refreshed or merged), "sor": "asset_registry"}


@assets_router.delete("/api/v1/assets/{asset_id}")
async def delete_asset(
    asset_id: str,
    user: Principal = Depends(require_analyst),
) -> dict[str, str]:
    # Soft-deactivate in the authoritative registry before local helper cleanup.
    try:
        registry = await _fetch_registry_asset(asset_id, user)
        if not registry:
            raise HTTPException(status_code=404, detail="Asset not found")
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.patch(
                f"{_registry_base()}/api/v1/assets/{asset_id}",
                json={"active": False},
                headers=_registry_headers(user),
            )
            if response.status_code >= 400:
                raise AssetRegistryUnavailable(
                    f"asset registry returned HTTP {response.status_code}"
                )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Failed to update asset registry") from exc
    _get_service().asset_manager.delete_asset(asset_id)
    return {"status": "ok"}


@assets_router.post("/api/v1/assets/{asset_id}/cases")
async def link_asset_to_case(
    asset_id: str,
    req: AssetCaseLinkRequest,
    user: Principal = Depends(require_analyst),
) -> dict[str, str]:
    if not _get_service().case_manager.get_case(req.case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    tip = _get_service().asset_manager.get_asset(asset_id)
    if not tip:
        registry = await _fetch_registry_asset(asset_id, user)
        if not registry:
            raise HTTPException(status_code=404, detail="Asset not found")
        norm = _normalize_registry_row(registry)
        _get_service().asset_manager.create_asset(
            asset_id=asset_id,
            hostname=str(norm.get("hostname") or asset_id),
            asset_type=str(norm.get("asset_type") or "host"),
            owner=str(norm.get("owner") or ""),
            criticality=str(norm.get("criticality") or "medium"),
            tags=list(norm.get("tags") or []),
        )
    try:
        _get_service().asset_manager.link_to_case(asset_id, req.case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Asset not found") from exc
    return {"status": "ok"}


@assets_router.delete("/api/v1/assets/{asset_id}/cases/{case_id}")
async def unlink_asset_from_case(
    asset_id: str,
    case_id: str,
    _: Principal = Depends(require_analyst),
) -> dict[str, str]:
    _get_service().asset_manager.unlink_from_case(asset_id, case_id)
    return {"status": "ok"}
