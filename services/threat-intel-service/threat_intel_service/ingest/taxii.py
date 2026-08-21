"""Checkpointed TAXII 2.1 collection synchronization."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import httpx
from sqlalchemy.orm import Session

from threat_intel_service.config import settings
from threat_intel_service.ingest.stix_upload import ingest_stix_bundle
from threat_intel_service.store import get_feed_checkpoint, record_feed_health, update_feed_checkpoint

SOURCE = "taxii"


async def sync_taxii(
    session: Session,
    *,
    base_url: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Poll TAXII 2.1 collections and persist a per-collection watermark."""
    url = (base_url if base_url is not None else settings.taxii_url) or ""
    url = url.strip()
    if not url:
        record_feed_health(session, SOURCE, status="disabled", error=None, indicator_count=0)
        session.commit()
        return {
            "source": SOURCE,
            "status": "disabled",
            "capability": "taxii_sync",
            "reason": "taxii_url unset",
            "upserted": 0,
        }

    own_client = client is None
    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
    }
    if settings.taxii_token:
        headers["Authorization"] = f"Bearer {settings.taxii_token}"
    auth = None
    if settings.taxii_username:
        auth = httpx.BasicAuth(settings.taxii_username, settings.taxii_password or "")
    client = client or httpx.AsyncClient(timeout=60.0)
    upserted = 0
    pages = 0
    sync_started = datetime.now(timezone.utc).isoformat()
    try:
        root = url if url.endswith("/") else url + "/"
        collections_url = urljoin(root, "collections/")
        collections: list[dict[str, Any]] = []
        collection_next: str | None = None
        while True:
            params = {"limit": settings.taxii_page_limit}
            if collection_next:
                params["next"] = collection_next
            coll_resp = await client.get(
                collections_url, params=params, headers=headers, auth=auth
            )
            coll_resp.raise_for_status()
            coll_payload = coll_resp.json()
            chunk = coll_payload.get("collections") if isinstance(coll_payload, dict) else None
            if not isinstance(chunk, list):
                raise ValueError("TAXII collections response missing collections list")
            collections.extend(item for item in chunk if isinstance(item, dict))
            if not coll_payload.get("more"):
                break
            collection_next = str(coll_payload.get("next") or "").strip() or None
            if collection_next is None:
                raise ValueError("TAXII collections response set more without next")

        for coll in collections:
            coll_id = str(coll.get("id") or "").strip()
            if not coll_id:
                continue
            objects_url = urljoin(root, f"collections/{coll_id}/objects/")
            checkpoint_name = f"{SOURCE}:{coll_id}"
            checkpoint = get_feed_checkpoint(session, checkpoint_name)
            added_after = checkpoint.cursor if checkpoint else None
            next_token: str | None = None
            collection_pages = 0
            while True:
                if collection_pages >= settings.taxii_max_pages:
                    raise RuntimeError(
                        f"TAXII collection {coll_id} exceeded max page limit"
                    )
                params = {"limit": settings.taxii_page_limit}
                if added_after:
                    params["added_after"] = added_after
                if next_token:
                    params["next"] = next_token
                obj_resp = await client.get(
                    objects_url, params=params, headers=headers, auth=auth
                )
                obj_resp.raise_for_status()
                objects_payload = obj_resp.json()
                if not isinstance(objects_payload, dict):
                    raise ValueError("TAXII objects response must be an object")
                objects = objects_payload.get("objects")
                if not isinstance(objects, list):
                    if objects_payload.get("type") == "bundle":
                        objects = objects_payload.get("objects")
                    if not isinstance(objects, list):
                        raise ValueError("TAXII objects response missing objects list")
                bundle = {"type": "bundle", "objects": objects}
                result = ingest_stix_bundle(session, bundle, default_source=SOURCE)
                upserted += int(result.get("upserted") or 0)
                pages += 1
                collection_pages += 1
                if not objects_payload.get("more"):
                    break
                next_token = str(objects_payload.get("next") or "").strip() or None
                if next_token is None:
                    raise ValueError("TAXII objects response set more without next")
            update_feed_checkpoint(
                session,
                checkpoint_name,
                cursor=sync_started,
                etag=obj_resp.headers.get("etag"),
                last_modified=obj_resp.headers.get("last-modified"),
            )

        record_feed_health(session, SOURCE, status="ok", error=None, indicator_count=upserted)
        session.commit()
        return {
            "source": SOURCE,
            "status": "ready",
            "capability": "taxii_sync",
            "upserted": upserted,
            "pages": pages,
            "checkpoint": sync_started,
        }
    except Exception as exc:
        record_feed_health(session, SOURCE, status="error", error=str(exc), indicator_count=upserted)
        session.commit()
        raise
    finally:
        if own_client:
            await client.aclose()
