"""Checkpointed MISP REST attribute synchronization."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx
from sqlalchemy.orm import Session
from ulid import ULID

from threat_intel_service.config import settings
from threat_intel_service.store import (
    get_feed_checkpoint,
    record_feed_health,
    update_feed_checkpoint,
    upsert_indicator,
)

SOURCE = "misp"

_MISP_TYPE_MAP = {
    "ip-dst": "ipv4",
    "ip-src": "ipv4",
    "ip-dst|port": "ipv4",
    "ip-src|port": "ipv4",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "md5": "file_hash",
    "sha1": "file_hash",
    "sha256": "file_hash",
    "filename|md5": "file_hash",
    "filename|sha256": "file_hash",
    "email": "email",
    "email-src": "email",
    "email-dst": "email",
    "vulnerability": "cve",
    "ja3-fingerprint-md5": "ja3",
}


def _map_misp_type(misp_type: str, value: str) -> tuple[str, str] | None:
    mapped = _MISP_TYPE_MAP.get(misp_type.lower())
    if not mapped:
        return None
    clean = value
    if "|" in value and mapped in {"ipv4", "file_hash"}:
        # ip|port or filename|hash → take the informative half
        left, right = value.split("|", 1)
        clean = right if mapped == "file_hash" else left
    return mapped, clean.strip()


async def sync_misp(
    session: Session,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Sync paginated MISP attributes and persist the newest timestamp."""
    url = (base_url if base_url is not None else settings.misp_url) or ""
    key = (api_key if api_key is not None else settings.misp_key) or ""
    url = url.strip()
    key = key.strip()
    if not url or not key:
        record_feed_health(session, SOURCE, status="disabled", error=None, indicator_count=0)
        session.commit()
        return {
            "source": SOURCE,
            "status": "disabled",
            "capability": "misp_sync",
            "reason": "misp_url or key unset",
            "upserted": 0,
        }

    own_client = client is None
    headers = {
        "Authorization": key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    client = client or httpx.AsyncClient(timeout=60.0)
    upserted = 0
    pages = 0
    checkpoint = get_feed_checkpoint(session, SOURCE)
    since = checkpoint.cursor if checkpoint else None
    newest_timestamp = since
    try:
        search_url = urljoin(url if url.endswith("/") else url + "/", "attributes/restSearch")
        for page in range(1, settings.misp_max_pages + 1):
            request_body: dict[str, Any] = {
                "returnFormat": "json",
                "to_ids": True,
                "page": page,
                "limit": settings.misp_page_size,
            }
            if since:
                request_body["timestamp"] = since
            resp = await client.post(search_url, json=request_body, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
            attrs: Any = []
            if isinstance(payload, dict):
                response = payload.get("response")
                if isinstance(response, dict):
                    attrs = response.get("Attribute") or []
                elif isinstance(response, list):
                    attrs = response
                else:
                    attrs = payload.get("Attribute") or []
            if not isinstance(attrs, list):
                raise ValueError("MISP response missing Attribute list")
            pages += 1

            for attr in attrs:
                if not isinstance(attr, dict):
                    continue
                misp_type = str(attr.get("type") or "")
                value = str(attr.get("value") or "").strip()
                if not misp_type or not value:
                    continue
                mapped = _map_misp_type(misp_type, value)
                if mapped is None:
                    continue
                otype, oval = mapped
                try:
                    confidence = max(0, min(100, int(float(attr.get("confidence") or 70))))
                except (TypeError, ValueError):
                    confidence = 70
                upsert_indicator(
                    session,
                    {
                        "indicator_id": f"ind-misp-{attr.get('id') or ULID()}",
                        "tenant_id": None,
                        "observable_type": otype,
                        "observable_value": oval,
                        "source": SOURCE,
                        "confidence": confidence,
                        "tlp": None,
                        "labels": ["misp"],
                        "campaigns": [],
                        "mitre_techniques": [],
                        "raw_json": attr,
                    },
                )
                upserted += 1
                attr_timestamp = str(attr.get("timestamp") or "").strip()
                if attr_timestamp and (
                    newest_timestamp is None or attr_timestamp > newest_timestamp
                ):
                    newest_timestamp = attr_timestamp
            if len(attrs) < settings.misp_page_size:
                break
        else:
            raise RuntimeError("MISP sync exceeded max page limit")

        update_feed_checkpoint(
            session,
            SOURCE,
            cursor=newest_timestamp,
            etag=resp.headers.get("etag"),
            last_modified=resp.headers.get("last-modified"),
        )
        record_feed_health(session, SOURCE, status="ok", error=None, indicator_count=upserted)
        session.commit()
        return {
            "source": SOURCE,
            "status": "ready",
            "capability": "misp_sync",
            "upserted": upserted,
            "pages": pages,
            "checkpoint": newest_timestamp,
        }
    except Exception as exc:
        record_feed_health(session, SOURCE, status="error", error=str(exc), indicator_count=upserted)
        session.commit()
        raise
    finally:
        if own_client:
            await client.aclose()
