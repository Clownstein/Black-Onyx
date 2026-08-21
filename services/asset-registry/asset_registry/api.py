from datetime import UTC, datetime, timedelta
from math import ceil

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from asset_registry.db import get_db
from asset_registry.config import settings
from asset_registry.models import Asset
from asset_registry.schemas import (
    AssetCreate,
    AssetRead,
    AssetUpdate,
    AssetUpsert,
    BaselineResponse,
    BaselineStats,
    TopologyEdge,
    TopologyNode,
    TopologyResponse,
)
from asset_registry.tenant import Principal, require_role, require_tenant

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


def _get_asset_or_404(db: Session, tenant_id: str, asset_id: str) -> Asset:
    asset = db.scalar(select(Asset).where(Asset.tenant_id == tenant_id, Asset.asset_id == asset_id))
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    return asset


def _load_retained_scores(tenant_id: str, asset_id: str, start: datetime) -> list[float]:
    headers = {"X-Tenant-Id": tenant_id}
    if settings.incident_api_service_key:
        headers["X-Service-Key"] = settings.incident_api_service_key
    with httpx.Client(timeout=settings.dependency_timeout_seconds) as client:
        response = client.get(
            f"{settings.incident_api_url.rstrip('/')}/api/v1/findings",
            headers=headers,
            params={"asset": asset_id, "start": start.isoformat()},
        )
        response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("items"), list):
        raise ValueError("incident API returned an invalid findings response")
    scores: list[float] = []
    for item in body["items"]:
        if not isinstance(item, dict):
            continue
        value = item.get("calibrated_score")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            scores.append(float(value))
    return scores


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, ceil(percentile * len(ordered)) - 1))
    return ordered[index]


@router.get("", response_model=list[AssetRead])
def list_assets(
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    active: bool | None = None,
) -> list[Asset]:
    stmt = select(Asset).where(Asset.tenant_id == tenant_id)
    if active is not None:
        stmt = stmt.where(Asset.active.is_(active))
    return list(db.scalars(stmt).all())


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("analyst")),
) -> Asset:
    existing = db.scalar(
        select(Asset).where(Asset.tenant_id == tenant_id, Asset.asset_id == payload.asset_id)
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail="asset_id already exists for tenant")
    asset = Asset(tenant_id=tenant_id, **payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.put("/{asset_id}", response_model=AssetRead)
def upsert_asset(
    asset_id: str,
    payload: AssetUpsert,
    response: Response,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("analyst")),
) -> Asset:
    """Idempotently create or update an asset.

    Self-enrolling collectors call this on every boot, so it must succeed whether
    or not the asset already exists. `POST ""` keeps its strict create-only 409
    contract for operator-driven registration.
    """
    asset = db.scalar(
        select(Asset).where(Asset.tenant_id == tenant_id, Asset.asset_id == asset_id)
    )
    if asset is None:
        asset = Asset(tenant_id=tenant_id, asset_id=asset_id, **payload.model_dump())
        db.add(asset)
        response.status_code = status.HTTP_201_CREATED
    else:
        for key, value in payload.model_dump().items():
            setattr(asset, key, value)
        response.status_code = status.HTTP_200_OK
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{asset_id}/topology", response_model=TopologyResponse)
def get_topology(
    asset_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> TopologyResponse:
    asset = _get_asset_or_404(db, tenant_id, asset_id)
    nodes = [
        TopologyNode(id=asset.asset_id, kind="asset", label=asset.name),
    ]
    edges: list[TopologyEdge] = []
    for peer in asset.expected_peers or []:
        nodes.append(TopologyNode(id=peer, kind="peer", label=peer))
        edges.append(TopologyEdge(source=asset.asset_id, target=peer, relation="expected_peer"))
    return TopologyResponse(asset_id=asset.asset_id, nodes=nodes, edges=edges)


@router.get("/{asset_id}/baseline", response_model=BaselineResponse)
def get_baseline(
    asset_id: str,
    window_days: int = Query(default=7, ge=1, le=90),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> BaselineResponse:
    asset = _get_asset_or_404(db, tenant_id, asset_id)
    start = datetime.now(UTC) - timedelta(days=window_days)
    try:
        scores = _load_retained_scores(tenant_id, asset.asset_id, start)
    except (httpx.HTTPError, ValueError) as exc:
        return BaselineResponse(
            asset_id=asset.asset_id,
            window_days=window_days,
            stats=BaselineStats(
                status="degraded",
                reason=f"retained findings unavailable: {exc}",
                retry_after_seconds=30,
            ),
        )
    if not scores:
        return BaselineResponse(
            asset_id=asset.asset_id,
            window_days=window_days,
            stats=BaselineStats(
                status="empty",
                reason="no retained findings exist in the requested window",
            ),
        )
    return BaselineResponse(
        asset_id=asset.asset_id,
        window_days=window_days,
        stats=BaselineStats(
            sample_count=len(scores),
            mean_score=sum(scores) / len(scores),
            p95_score=_percentile(scores, 0.95),
        ),
    )


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(
    asset_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
) -> Asset:
    return _get_asset_or_404(db, tenant_id, asset_id)


@router.patch("/{asset_id}", response_model=AssetRead)
def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("analyst")),
) -> Asset:
    asset = db.scalar(select(Asset).where(Asset.tenant_id == tenant_id, Asset.asset_id == asset_id))
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, key, value)
    db.commit()
    db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("analyst")),
) -> None:
    asset = db.scalar(select(Asset).where(Asset.tenant_id == tenant_id, Asset.asset_id == asset_id))
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    db.delete(asset)
    db.commit()
