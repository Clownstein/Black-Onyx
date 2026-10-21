"""Wazuh connector.

Wazuh alerts arrive two ways. The primary path is push: the Black Onyx shipper
running beside the Wazuh manager posts raw `alerts.json` objects to
`/api/v1/connectors/{id}/push`, which only calls `normalize()`. Managers on
private networks are push-only their base URL may be non-public when the
hostname is explicitly allowlisted (see `DetectionConnectorManager`).

Optional poll targets the Wazuh indexer, because the Wazuh server API does not
serve alerts; alerts live in the `wazuh-alerts-*` indices. Poll keeps the same
public-HTTPS, pinned-IP, bounded-response rules as every other connector.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from black_onyx.connectors.base import DetectionConnector, DetectionPullResult
from black_onyx.connectors.generic_rest import (
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_PAGES_PER_POLL,
    REQUEST_TIMEOUT_SECONDS,
    _bounded_json,
)
from black_onyx.models.data_model import DataModel
from black_onyx.net.safe_url import validate_public_https_url

DEFAULT_ALERTS_INDEX = "wazuh-alerts-*"
DEFAULT_MIN_LEVEL = 7
SURICATA_GROUPS = ("suricata", "ids", "eve")
PAGE_SIZE = 200
_HASH_FIELDS = {"md5": "md5_hashes", "sha1": "sha1_hashes", "sha256": "sha256_hashes"}


def wazuh_severity(level: Any) -> str:
    try:
        value = int(level)
    except (TypeError, ValueError):
        return "low"
    if value >= 12:
        return "critical"
    if value >= 10:
        return "high"
    if value >= 7:
        return "medium"
    return "low"


def wazuh_asset_id(agent_id: Any) -> str:
    text = str(agent_id or "").strip()
    return f"wazuh:{text}" if text else ""


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _valid_ip(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def _parse_hashes(value: Any) -> dict[str, str]:
    """Parse Sysmon `SHA256=..,MD5=..` strings into {algo: digest}."""
    out: dict[str, str] = {}
    if not isinstance(value, str):
        return out
    for part in value.split(","):
        if "=" not in part:
            continue
        algo, digest = part.split("=", 1)
        algo = algo.strip().lower()
        if algo in _HASH_FIELDS and digest.strip():
            out[algo] = digest.strip().lower()
    return out


class WazuhConnector(DetectionConnector):
    """Config keys (all optional):

    poll_enabled: bool poll the Wazuh indexer (default False; push-only).
    alerts_index: str index pattern (default "wazuh-alerts-*").
    min_level: int minimum `rule.level` pulled by poll (default 7).

    Secrets for poll: `username`, `password` (indexer basic auth).
    """

    def __init__(self, name: str, config: dict[str, Any], secrets: dict[str, str]) -> None:
        self._name = name
        self._config = config
        self._secrets = secrets
        self._base_url = str(config.get("base_url") or "").strip().rstrip("/")

    @property
    def name(self) -> str:
        return self._name

    @property
    def source_type(self) -> str:
        return "wazuh"

    @property
    def poll_enabled(self) -> bool:
        return bool(self._config.get("poll_enabled"))

    async def authenticate(self) -> None:
        if not self.poll_enabled:
            return
        validate_public_https_url(self._base_url, purpose="Wazuh indexer base_url")
        if not self._secrets.get("username") or not self._secrets.get("password"):
            raise ValueError("Wazuh poll requires username and password credentials")

    async def test_connection(self) -> dict[str, Any]:
        if not self.poll_enabled:
            return {
                "status": "ok",
                "connector": self.name,
                "mode": "push",
                "detail": "Push-only connector; rotate a push token for the Wazuh shipper",
            }
        return await super().test_connection()

    def _search_body(self, since: datetime | None, search_after: list[Any] | None) -> dict[str, Any]:
        filters: list[dict[str, Any]] = [
            {"range": {"rule.level": {"gte": int(self._config.get("min_level", DEFAULT_MIN_LEVEL))}}},
        ]
        if since and search_after is None:
            filters.append({"range": {"timestamp": {"gte": since.astimezone(timezone.utc).isoformat()}}})
        body: dict[str, Any] = {
            "size": PAGE_SIZE,
            "sort": [{"timestamp": "asc"}, {"id": "asc"}],
            # Suricata is ingested from eve.json by the shipper; polling those groups would file it twice.
            "query": {"bool": {"filter": filters, "must_not": [{"terms": {"rule.groups": list(SURICATA_GROUPS)}}]}},
        }
        if search_after is not None:
            body["search_after"] = search_after
        return body

    async def pull_detections(
        self, since: datetime | None, cursor: str | None,
    ) -> DetectionPullResult:
        if not self.poll_enabled:
            return DetectionPullResult(detections=[], next_cursor=cursor, raw_count=0)
        await self.authenticate()
        max_bytes = self._config.get("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)
        index = str(self._config.get("alerts_index") or DEFAULT_ALERTS_INDEX).strip("/")
        url = f"{self._base_url}/{index}/_search"
        auth = httpx.BasicAuth(self._secrets["username"], self._secrets["password"])
        search_after: list[Any] | None = json.loads(cursor) if cursor else None
        detections: list[dict[str, Any]] = []
        next_cursor = cursor

        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS, trust_env=False, follow_redirects=False,
        ) as client:
            for _ in range(MAX_PAGES_PER_POLL):
                body, _ = await _bounded_json(
                    client, "POST", url, max_bytes,
                    json=self._search_body(since, search_after), auth=auth,
                    headers={"Content-Type": "application/json"},
                )
                hits = ((body or {}).get("hits") or {}).get("hits") or []
                if not hits:
                    break
                for hit in hits:
                    source = hit.get("_source")
                    if isinstance(source, dict):
                        detections.append(source)
                last_sort = hits[-1].get("sort")
                if not last_sort:
                    break
                search_after = list(last_sort)
                next_cursor = json.dumps(search_after)
                if len(hits) < PAGE_SIZE:
                    break

        return DetectionPullResult(detections=detections, next_cursor=next_cursor, raw_count=len(detections))

    def normalize(self, raw: dict[str, Any]) -> DataModel:
        rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        syscheck = raw.get("syscheck") if isinstance(raw.get("syscheck"), dict) else {}
        win = data.get("win") if isinstance(data.get("win"), dict) else {}
        eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
        mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}

        agent_id = str(agent.get("id") or "").strip()
        rule_id = str(rule.get("id") or "").strip()
        alert_id = str(raw.get("id") or "").strip()
        event_time = raw.get("timestamp") or raw.get("@timestamp")
        detection_id = ":".join(
            part for part in (agent_id or "none", rule_id or "none", alert_id or str(event_time or "")) if part
        )
        level = rule.get("level")
        severity = wazuh_severity(level)
        hostname = str(agent.get("name") or "").strip() or None
        description = str(rule.get("description") or "").strip()
        title = description or f"Wazuh rule {rule_id or 'unknown'}"
        if hostname:
            title = f"{title} on {hostname}"

        ip_addresses: list[str] = []
        # agent.ip first: asset sightings use the first address as the host's own.
        for candidate in (
            agent.get("ip"), data.get("srcip"), data.get("dstip"),
            eventdata.get("ipAddress"), eventdata.get("sourceIp"), eventdata.get("destinationIp"),
        ):
            ip = _valid_ip(candidate)
            if ip:
                ip_addresses.append(ip)

        hashes: dict[str, list[str]] = {field: [] for field in _HASH_FIELDS.values()}
        for algo, field in _HASH_FIELDS.items():
            digest = syscheck.get(f"{algo}_after")
            if digest:
                hashes[field].append(str(digest).lower())
        for algo, digest in _parse_hashes(eventdata.get("hashes")).items():
            hashes[_HASH_FIELDS[algo]].append(digest)

        username = next(
            (
                str(value).strip()
                for value in (
                    data.get("srcuser"), data.get("dstuser"), eventdata.get("targetUserName"),
                    eventdata.get("user"), syscheck.get("uname_after"),
                )
                if value and str(value).strip()
            ),
            None,
        )

        groups = [str(g) for g in _as_list(rule.get("groups"))]
        techniques = [str(t) for t in _as_list(mitre.get("id"))]
        tactics = [str(t) for t in _as_list(mitre.get("tactic"))]

        summary_parts = [title]
        if syscheck.get("path"):
            summary_parts.append(f"file {syscheck['path']} ({syscheck.get('event') or 'changed'})")
        if eventdata.get("commandLine"):
            summary_parts.append(f"command {eventdata['commandLine']}")
        if raw.get("full_log"):
            summary_parts.append(str(raw["full_log"]))
        body_text = ". ".join(summary_parts)

        return DataModel(
            title=title[:500],
            body_text=body_text[:4000],
            source_file=f"connector:{self.name}:{detection_id}",
            payload_type="text",
            ioc_status="new",
            ip_addresses=list(dict.fromkeys(ip_addresses)),
            md5_hashes=list(dict.fromkeys(hashes["md5_hashes"])),
            sha1_hashes=list(dict.fromkeys(hashes["sha1_hashes"])),
            sha256_hashes=list(dict.fromkeys(hashes["sha256_hashes"])),
            mitre_techniques=list(dict.fromkeys(techniques)),
            mitre_tactics=list(dict.fromkeys(tactics)),
            ioc_tags=list(dict.fromkeys([severity, *groups])),
            capture_time=str(event_time) if event_time else None,
            enrichment_data={
                "event_time": str(event_time) if event_time else None,
                "severity": severity,
                "hostname": hostname,
                "username": username,
                "asset_id": wazuh_asset_id(agent_id) or None,
                "wazuh_agent_id": agent_id or None,
                "wazuh_rule_id": rule_id or None,
                "wazuh_rule_level": level,
                "wazuh_rule_groups": groups,
            },
        )
