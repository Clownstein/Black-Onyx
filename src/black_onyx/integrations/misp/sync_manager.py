"""MISP sync — pull events and publish IOCs via the MISP REST API."""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

MISP_ATTR_TO_IOC: dict[str, str] = {
    "ip-dst": "ip",
    "ip-src": "ip",
    "ip-dst|port": "ip",
    "ip-src|port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "link": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "filename|md5": "md5",
    "filename|sha1": "sha1",
    "filename|sha256": "sha256",
    "email-src": "email",
    "email-dst": "email",
    "email": "email",
    "vulnerability": "cve",
}

IOC_TO_MISP_ATTR: dict[str, str] = {
    "ip": "ip-dst",
    "ipv4": "ip-dst",
    "ipv6": "ip-dst",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "hash": "sha256",
    "email": "email-src",
    "cve": "vulnerability",
}


class MispSyncManager:
    """SQLite-backed MISP configuration, pull sync, and IOC publish."""

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "misp.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                url TEXT NOT NULL DEFAULT '',
                api_key_env TEXT NOT NULL DEFAULT 'MISP_API_KEY',
                enabled INTEGER NOT NULL DEFAULT 0,
                collection TEXT NOT NULL DEFAULT 'all-knowledge',
                last_sync TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS synced_events (
                event_id TEXT PRIMARY KEY,
                uuid TEXT,
                info TEXT,
                synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS synced_iocs (
                event_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                collection TEXT NOT NULL DEFAULT '',
                synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (event_id, ioc_type, ioc_value)
            );
            CREATE INDEX IF NOT EXISTS idx_synced_iocs_collection
                ON synced_iocs(collection);
            CREATE TABLE IF NOT EXISTS published (
                case_id TEXT NOT NULL,
                misp_event_id TEXT NOT NULL,
                published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (case_id, misp_event_id)
            );
            INSERT OR IGNORE INTO settings (id, url, api_key_env, enabled, collection)
            VALUES (1, '', 'MISP_API_KEY', 0, 'all-knowledge');
            """
        )
        self._conn.commit()

    @staticmethod
    def _validate_https_url(url: str) -> str:
        from black_onyx.net.safe_url import validate_public_https_url
        return validate_public_https_url(url, purpose="MISP URL")

    def configure(
        self,
        url: str,
        api_key_env: str = "MISP_API_KEY",
        collection: str = "all-knowledge",
        enabled: bool = True,
    ) -> dict[str, Any]:
        validated = self._validate_https_url(url) if url else ""
        env_name = (api_key_env or "MISP_API_KEY").strip() or "MISP_API_KEY"
        with self._lock:
            self._conn.execute(
                "UPDATE settings SET url = ?, api_key_env = ?, enabled = ?, collection = ? WHERE id = 1",
                (validated, env_name, 1 if enabled else 0, collection or "all-knowledge"),
            )
            self._conn.commit()
        return self.get_status()

    def _settings_row(self) -> sqlite3.Row:
        row = self._conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        assert row is not None
        return row

    def _api_key(self, env_name: str) -> str:
        return (os.environ.get(env_name) or "").strip()

    def get_status(self) -> dict[str, Any]:
        row = self._settings_row()
        api_key = self._api_key(row["api_key_env"])
        configured = bool(row["url"] and api_key)
        synced = self._conn.execute("SELECT COUNT(*) AS n FROM synced_events").fetchone()
        published = self._conn.execute("SELECT COUNT(*) AS n FROM published").fetchone()
        synced_iocs = self._conn.execute("SELECT COUNT(*) AS n FROM synced_iocs").fetchone()
        return {
            "configured": configured,
            "enabled": bool(row["enabled"]),
            "url": row["url"] or "",
            "api_key_env": row["api_key_env"],
            "api_key_present": bool(api_key),
            "collection": row["collection"],
            "last_sync": row["last_sync"],
            "synced_event_count": int(synced["n"]) if synced else 0,
            "synced_ioc_count": int(synced_iocs["n"]) if synced_iocs else 0,
            "published_count": int(published["n"]) if published else 0,
            "status": "ok" if configured and row["enabled"] else (
                "not configured" if not configured else "disabled"
            ),
        }

    def _headers(self, api_key: str) -> dict[str, str]:
        return {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _extract_iocs(attributes: list[dict[str, Any]]) -> list[dict[str, str]]:
        iocs: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for attr in attributes:
            misp_type = str(attr.get("type") or "")
            value = str(attr.get("value") or "").strip()
            if not value:
                continue
            if "|" in value and misp_type.startswith("filename|"):
                value = value.split("|", 1)[-1].strip()
            elif "|" in value and misp_type.endswith("|port"):
                value = value.split("|", 1)[0].strip()
            ioc_type = MISP_ATTR_TO_IOC.get(misp_type)
            if not ioc_type:
                continue
            key = (ioc_type, value)
            if key in seen:
                continue
            seen.add(key)
            iocs.append({"ioc_type": ioc_type, "ioc_value": value})
        return iocs

    def sync_pull(self, limit: int = 50) -> list[dict[str, Any]]:
        """Pull recent MISP events via restSearch and store metadata."""
        status = self.get_status()
        if not status["configured"]:
            raise ValueError("MISP is not configured")
        if not status["enabled"]:
            raise ValueError("MISP sync is disabled")

        row = self._settings_row()
        base_url = self._validate_https_url(row["url"])
        api_key = self._api_key(row["api_key_env"])
        limit = max(1, min(int(limit), 200))
        payload = {
            "returnFormat": "json",
            "limit": limit,
            "page": 1,
            "published": True,
        }
        url = f"{base_url}/events/restSearch"
        with httpx.Client(timeout=60, follow_redirects=False, trust_env=False) as client:
            response = client.post(url, headers=self._headers(api_key), json=payload)
            response.raise_for_status()
            body = response.json()

        events_raw = body.get("response", body) if isinstance(body, dict) else body
        if isinstance(events_raw, dict) and "Event" in events_raw:
            events_raw = [events_raw]
        if not isinstance(events_raw, list):
            events_raw = []

        results: list[dict[str, Any]] = []
        all_iocs: list[dict[str, str]] = []
        collection = str(row["collection"] or "MISP").strip() or "MISP"
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            for item in events_raw:
                event = item.get("Event", item) if isinstance(item, dict) else {}
                if not isinstance(event, dict):
                    continue
                event_id = str(event.get("id") or event.get("uuid") or "")
                if not event_id:
                    continue
                uuid_val = str(event.get("uuid") or "")
                info = str(event.get("info") or "")
                attributes = event.get("Attribute") or []
                if not isinstance(attributes, list):
                    attributes = []
                # Include attributes nested under objects when present
                for obj in event.get("Object") or []:
                    if isinstance(obj, dict):
                        nested = obj.get("Attribute") or []
                        if isinstance(nested, list):
                            attributes = list(attributes) + nested
                iocs = self._extract_iocs(attributes)
                self._conn.execute(
                    "INSERT OR REPLACE INTO synced_events (event_id, uuid, info, synced_at) "
                    "VALUES (?, ?, ?, ?)",
                    (event_id, uuid_val, info, now),
                )
                for ioc in iocs:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO synced_iocs "
                        "(event_id, ioc_type, ioc_value, collection, synced_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (event_id, ioc["ioc_type"], ioc["ioc_value"], collection, now),
                    )
                    all_iocs.append(dict(ioc))
                results.append({
                    "event_id": event_id,
                    "uuid": uuid_val,
                    "info": info,
                    "synced_at": now,
                    "iocs": iocs,
                })
            self._conn.execute(
                "UPDATE settings SET last_sync = ? WHERE id = 1", (now,),
            )
            self._conn.commit()
        return {
            "events": results,
            "iocs": all_iocs,
            "collection": collection,
            "ioc_count": len(all_iocs),
        }

    def publish_from_iocs(
        self,
        case_id: str,
        iocs: list[dict[str, str]],
        info: str = "",
    ) -> dict[str, Any]:
        """Create a MISP event from IOC list and record the publish."""
        status = self.get_status()
        if not status["configured"]:
            raise ValueError("MISP is not configured")

        row = self._settings_row()
        base_url = self._validate_https_url(row["url"])
        api_key = self._api_key(row["api_key_env"])

        attributes: list[dict[str, str]] = []
        for ioc in iocs:
            ioc_type = str(ioc.get("ioc_type") or "").strip().lower()
            ioc_value = str(ioc.get("ioc_value") or "").strip()
            if not ioc_type or not ioc_value:
                continue
            misp_type = IOC_TO_MISP_ATTR.get(ioc_type, "text")
            attributes.append({"type": misp_type, "value": ioc_value, "category": "External analysis"})
        if not attributes:
            raise ValueError("No valid IOCs to publish")

        event_info = (info or f"Black Onyx case {case_id}").strip()
        payload = {
            "Event": {
                "info": event_info,
                "distribution": "0",
                "threat_level_id": "2",
                "analysis": "0",
                "Attribute": attributes,
            }
        }
        url = f"{base_url}/events"
        with httpx.Client(timeout=60, follow_redirects=False, trust_env=False) as client:
            response = client.post(url, headers=self._headers(api_key), json=payload)
            response.raise_for_status()
            body = response.json()

        event = body.get("Event", body) if isinstance(body, dict) else {}
        misp_event_id = str(event.get("id") or event.get("uuid") or "")
        if not misp_event_id:
            raise ValueError("MISP did not return an event id")

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO published (case_id, misp_event_id, published_at) VALUES (?, ?, ?)",
                (case_id, misp_event_id, now),
            )
            self._conn.commit()
        return {
            "case_id": case_id,
            "misp_event_id": misp_event_id,
            "uuid": event.get("uuid"),
            "info": event_info,
            "published_at": now,
            "attribute_count": len(attributes),
        }

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
