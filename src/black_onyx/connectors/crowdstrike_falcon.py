"""CrowdStrike Falcon connector, via the Falcon Detects API.

Reuses `GenericRestConnector`'s OAuth2 client-credentials `authenticate()`/
`_auth_headers()` (Falcon's own token endpoint is a standard OAuth2
client-credentials flow), but overrides `pull_detections()` entirely: Falcon
detections are not a single paginated GET, they are a two-step query —
`GET .../queries/detects/v1` returns a page of opaque detection IDs, then
`POST .../entities/summaries/GET/v1` with those IDs returns the actual
detection records. That two-call shape doesn't fit the generic engine's
one-GET-per-page pagination model, so this is genuinely bespoke, not a config
knob — exactly the case the plan anticipated for named presets.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from black_onyx.connectors.base import DetectionPullResult
from black_onyx.connectors.generic_rest import (
    DEFAULT_MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    GenericRestConnector,
    _bounded_json,
)
from black_onyx.models.data_model import DataModel

DEFAULT_BASE_URL = "https://api.crowdstrike.com"
QUERY_IDS_PATH = "/detects/queries/detects/v1"
DETAILS_PATH = "/detects/entities/summaries/GET/v1"
PAGE_LIMIT = 100
# Falcon paginates by numeric offset over the ID query, capped the same way
# GenericRestConnector caps pages — bounds worst-case work per poll.
MAX_ID_PAGES_PER_POLL = 20


class CrowdStrikeFalconConnector(GenericRestConnector):
    """Optional config key: `base_url` (defaults to the US-1 cloud;
    US-2/EU-1/GovCloud tenants must set their own region-specific API host,
    e.g. "https://api.us-2.crowdstrike.com").

    Required secrets: `client_id`, `client_secret` (a Falcon API client with
    the "Detections: Read" scope).
    """

    def __init__(self, name: str, config: dict[str, Any], secrets: dict[str, str]) -> None:
        full_config = {
            **config,
            "base_url": config.get("base_url") or DEFAULT_BASE_URL,
            "auth": {
                "type": "oauth2_client_credentials",
                "token_url": (config.get("base_url") or DEFAULT_BASE_URL).rstrip("/") + "/oauth2/token",
            },
        }
        super().__init__(name=name, config=full_config, secrets=secrets)

    @property
    def source_type(self) -> str:
        return "crowdstrike_falcon"

    async def pull_detections(
        self, since: datetime | None, cursor: str | None,
    ) -> DetectionPullResult:
        await self.authenticate()
        max_bytes = self._config.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)
        base = self._base_url.rstrip("/")

        # Resume by numeric offset, not a token — Falcon's query endpoint is
        # plain offset/limit pagination, so the "cursor" this connector
        # persists between polls is just that offset as a string.
        offset = int(cursor) if cursor else 0
        detection_ids: list[str] = []

        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS, trust_env=False, follow_redirects=False,
        ) as client:
            for _ in range(MAX_ID_PAGES_PER_POLL):
                params: dict[str, Any] = {
                    "offset": offset, "limit": PAGE_LIMIT, "sort": "first_behavior|asc",
                }
                if since:
                    # FQL filter syntax per Falcon Query Language docs.
                    params["filter"] = f"first_behavior:>'{since.isoformat()}'"
                body, _ = await _bounded_json(
                    client, "GET", base + QUERY_IDS_PATH, max_bytes,
                    params=params, headers=self._auth_headers(),
                )
                page_ids = body.get("resources") or []
                if not page_ids:
                    break
                detection_ids.extend(page_ids)
                offset += len(page_ids)
                if len(page_ids) < PAGE_LIMIT:
                    break

            detections: list[dict[str, Any]] = []
            # The details endpoint itself also paginates by request-body size
            # limits in practice; batch IDs to keep each POST body reasonable.
            for batch_start in range(0, len(detection_ids), PAGE_LIMIT):
                batch = detection_ids[batch_start:batch_start + PAGE_LIMIT]
                body, _ = await _bounded_json(
                    client, "POST", base + DETAILS_PATH, max_bytes,
                    json={"ids": batch}, headers=self._auth_headers(),
                )
                detections.extend(body.get("resources") or [])

        return DetectionPullResult(
            detections=detections, next_cursor=str(offset), raw_count=len(detections),
        )

    def normalize(self, raw: dict[str, Any]) -> DataModel:
        detection_id = raw.get("detection_id") or "unknown"
        severity = str(raw.get("max_severity_displayname") or "").lower()
        device = raw.get("device") or {}
        hostname = device.get("hostname")
        title = f"CrowdStrike detection on {hostname}" if hostname else f"CrowdStrike detection {detection_id}"

        ip_addresses: list[str] = []
        sha256_hashes: list[str] = []
        md5_hashes: list[str] = []
        mitre_techniques: list[str] = []
        mitre_tactics: list[str] = []
        behavior_summaries: list[str] = []
        for behavior in raw.get("behaviors") or []:
            if behavior.get("local_ip"):
                ip_addresses.append(str(behavior["local_ip"]))
            if behavior.get("sha256"):
                sha256_hashes.append(str(behavior["sha256"]))
            if behavior.get("md5"):
                md5_hashes.append(str(behavior["md5"]))
            if behavior.get("technique"):
                mitre_techniques.append(str(behavior["technique"]))
            if behavior.get("tactic"):
                mitre_tactics.append(str(behavior["tactic"]))
            if behavior.get("scenario") or behavior.get("cmdline"):
                behavior_summaries.append(str(behavior.get("scenario") or behavior.get("cmdline")))

        body_text = f"{title}. " + "; ".join(behavior_summaries[:10])
        event_time = (
            raw.get("first_behavior")
            or raw.get("created_timestamp")
            or raw.get("date_updated")
            or raw.get("timestamp")
        )
        username = None
        for behavior in raw.get("behaviors") or []:
            if behavior.get("user_name"):
                username = str(behavior["user_name"])
                break
        return DataModel(
            title=title,
            body_text=body_text[:4000],
            source_file=f"connector:{self.name}:{detection_id}",
            payload_type="text",
            ioc_status="new",
            ip_addresses=list(dict.fromkeys(ip_addresses)),
            sha256_hashes=list(dict.fromkeys(sha256_hashes)),
            md5_hashes=list(dict.fromkeys(md5_hashes)),
            mitre_techniques=list(dict.fromkeys(mitre_techniques)),
            mitre_tactics=list(dict.fromkeys(mitre_tactics)),
            ioc_tags=[severity] if severity else [],
            capture_time=str(event_time) if event_time else None,
            enrichment_data={
                "event_time": str(event_time) if event_time else None,
                "severity": severity,
                "hostname": hostname,
                "username": username,
            },
        )
