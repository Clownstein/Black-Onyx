"""TAXII 2.1 read-only server endpoints for published STIX collections."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

TAXII_MEDIA = "application/taxii+json;version=2.1"

taxii_router = APIRouter(tags=["taxii"])


def _get_service():
    from black_onyx.api.service import get_service
    return get_service()


def _taxii_json(payload: dict[str, Any], status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        content=payload,
        status_code=status_code,
        media_type=TAXII_MEDIA,
        headers={"Content-Type": TAXII_MEDIA},
    )


def _authenticate(request: Request) -> dict[str, Any]:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = auth[7:].strip()
    mgr = _get_service().taxii_manager
    principal = mgr.authenticate_key(token)
    if principal is None:
        raise HTTPException(status_code=401, detail="Invalid TAXII API key")
    mgr.audit_log(principal["key_id"], "auth.ok", request.url.path)
    return principal


@taxii_router.get("/taxii2/")
async def taxii_discovery(
    request: Request,
    _: dict[str, Any] = Depends(_authenticate),
) -> JSONResponse:
    """TAXII 2.1 server discovery."""
    base = str(request.base_url).rstrip("/")
    root = f"{base}/taxii2/"
    return _taxii_json({
        "title": "Black Onyx TAXII 2.1",
        "description": "Outbound STIX collections published from Black Onyx",
        "default": root,
        "api_roots": [root],
    })


@taxii_router.get("/taxii2/collections/")
async def taxii_list_collections(
    _: dict[str, Any] = Depends(_authenticate),
) -> JSONResponse:
    mgr = _get_service().taxii_manager
    collections = []
    for coll in mgr.list_collections(enabled_only=True):
        collections.append({
            "id": coll["collection_id"],
            "title": coll["title"],
            "description": coll["description"],
            "can_read": True,
            "can_write": False,
            "media_types": ["application/stix+json;version=2.1"],
        })
    return _taxii_json({"collections": collections})


@taxii_router.get("/taxii2/collections/{collection_id}/")
async def taxii_get_collection(
    collection_id: str,
    _: dict[str, Any] = Depends(_authenticate),
) -> JSONResponse:
    mgr = _get_service().taxii_manager
    coll = mgr.get_collection(collection_id)
    if coll is None or not coll["enabled"]:
        raise HTTPException(status_code=404, detail="Collection not found")
    return _taxii_json({
        "id": coll["collection_id"],
        "title": coll["title"],
        "description": coll["description"],
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    })


@taxii_router.get("/taxii2/collections/{collection_id}/objects/")
async def taxii_list_objects(
    collection_id: str,
    _: dict[str, Any] = Depends(_authenticate),
    limit: int = Query(default=100, ge=1, le=1000),
    added_after: str | None = Query(default=None),
) -> JSONResponse:
    mgr = _get_service().taxii_manager
    coll = mgr.get_collection(collection_id)
    if coll is None or not coll["enabled"]:
        raise HTTPException(status_code=404, detail="Collection not found")
    objects = mgr.list_objects(collection_id, limit=limit, added_after=added_after)
    return _taxii_json({
        "more": False,
        "objects": objects,
    })
