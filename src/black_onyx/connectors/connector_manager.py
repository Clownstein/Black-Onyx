"""Detection connector persistence, polling, and scheduling.

Mirrors `feed_manager.py::FeedManager` deliberately: same per-feature SQLite
store shape, same "enabled + due-by-interval" poll_all semantics, same daemon
thread + asyncio.run scheduler loop. Feeds and detection connectors are the
same idea — periodically pull from an external source and ingest — so this
reuses that proven shape rather than inventing a new one.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from black_onyx.connectors.factory import create_detection_connector
from black_onyx.core.collections import detection_collection_name
from black_onyx.net.safe_url import validate_public_https_url

logger = logging.getLogger(__name__)

# Config keys that must never carry a raw secret — mirrors FeedManager.add_feed's
# rejection of a literal "password" in TAXII config, and MISP's api_key_env
# indirection. Real credential values only ever live in os.environ, referenced
# here by the env var *name* (credential_env), never copied into config_json.
_FORBIDDEN_CONFIG_KEYS = {"api_key", "client_secret", "bearer_token", "password", "token"}


class DetectionConnectorManager:
    """Manage detection connector configuration, polling, and scheduling."""

    def __init__(
        self,
        persist_dir: str | None = None,
        ingestor: Any = None,
        ingestor_factory: Callable[[], Any] | None = None,
        max_concurrent: int = 4,
        allowed_hosts: list[str] | None = None,
        max_response_bytes: int = 10 * 1024 * 1024,
        asset_manager: Any | None = None,
    ) -> None:
        self._ingestor = ingestor
        self._ingestor_factory = ingestor_factory
        self._asset_manager = asset_manager
        self._lock = threading.Lock()
        self._max_concurrent = max_concurrent
        self._allowed_hosts = {h.casefold() for h in (allowed_hosts or [])}
        self._max_response_bytes = max_response_bytes
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._scheduler_stop = threading.Event()
        self._scheduler_thread: threading.Thread | None = None
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "connectors.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS connectors (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                connector_type TEXT NOT NULL,
                base_url TEXT NOT NULL,
                tenant_id TEXT,
                collection TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                poll_interval_minutes INTEGER NOT NULL DEFAULT 60,
                last_poll_at TEXT,
                last_poll_status TEXT,
                last_poll_error TEXT,
                config_json TEXT NOT NULL DEFAULT '{}',
                credential_env_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS connector_cursors (
                connector_id TEXT PRIMARY KEY REFERENCES connectors(id) ON DELETE CASCADE,
                cursor_value TEXT,
                last_seen_at TEXT
            );
            CREATE TABLE IF NOT EXISTS seen_detections (
                connector_id TEXT NOT NULL,
                detection_key TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                PRIMARY KEY (connector_id, detection_key)
            );
            CREATE TABLE IF NOT EXISTS detection_dispositions (
                detection_key TEXT PRIMARY KEY,
                connector TEXT,
                title TEXT,
                disposition TEXT,
                disposition_by TEXT,
                disposition_note TEXT,
                disposition_at TEXT,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                acknowledged_at TEXT,
                promoted_case_id TEXT
            );
        """)
        # Additive column migration, matching FeedManager's PRAGMA-driven
        # pattern, so an existing connectors.sqlite picks these up in place.
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(connectors)")}
        for column, ddl in (
            ("last_success_at", "ALTER TABLE connectors ADD COLUMN last_success_at TEXT"),
            ("push_token_hash", "ALTER TABLE connectors ADD COLUMN push_token_hash TEXT"),
            ("push_token_prefix", "ALTER TABLE connectors ADD COLUMN push_token_prefix TEXT"),
        ):
            if column not in existing:
                self._conn.execute(ddl)
        self._conn.commit()

    def set_asset_manager(self, asset_manager: Any | None) -> None:
        self._asset_manager = asset_manager

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------ CRUD

    def add_connector(
        self,
        name: str,
        connector_type: str,
        base_url: str,
        config: dict[str, Any] | None = None,
        credential_env: dict[str, str] | None = None,
        collection: str | None = None,
        poll_interval_minutes: int = 60,
        tenant_id: str | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Register a new detection connector.

        `config` holds non-secret connector configuration (auth type, endpoint
        paths, pagination, field mapping — see GenericRestConnector's
        docstring); `credential_env` maps secret names ("api_key",
        "client_id", "client_secret", "bearer_token") to the *environment
        variable name* that holds the real value — never the value itself.
        """
        config = config or {}
        forbidden = _FORBIDDEN_CONFIG_KEYS & config.keys()
        if forbidden:
            raise ValueError(
                f"config must not contain raw secrets ({', '.join(sorted(forbidden))}); "
                f"use credential_env to reference an environment variable instead"
            )
        validated_url = validate_public_https_url(base_url, purpose="Connector base_url")
        if self._allowed_hosts:
            from urllib.parse import urlparse
            hostname = (urlparse(validated_url).hostname or "").casefold()
            if hostname not in self._allowed_hosts:
                raise ValueError("Connector hostname is not allowlisted")
        # Bounds each connector's own response reads (GenericRestConnector),
        # same idea as feeds' max_response_bytes — a config-level knob, not
        # hardcoded in the connector, so one deployment's policy applies
        # uniformly across every connector instance it creates.
        config = dict(config or {})
        config.setdefault("max_response_bytes", self._max_response_bytes)
        connector_id = str(uuid.uuid4())
        now = self._now()
        resolved_collection = collection or detection_collection_name(name)
        with self._lock:
            self._conn.execute(
                "INSERT INTO connectors (id, name, connector_type, base_url, tenant_id, "
                "collection, enabled, poll_interval_minutes, config_json, credential_env_json, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    connector_id, name.strip(), connector_type, base_url, tenant_id,
                    resolved_collection, 1 if enabled else 0, poll_interval_minutes,
                    json.dumps(config), json.dumps(credential_env or {}), now, now,
                ),
            )
            self._conn.commit()
        return self.get_connector(connector_id)  # type: ignore[return-value]

    def get_connector(self, connector_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM connectors WHERE id = ?", (connector_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def list_connectors(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM connectors ORDER BY name").fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_connector(
        self, connector_id: str,
        enabled: bool | None = None,
        poll_interval_minutes: int | None = None,
    ) -> dict[str, Any] | None:
        fields: list[str] = []
        values: list[Any] = []
        if enabled is not None:
            fields.append("enabled=?")
            values.append(1 if enabled else 0)
        if poll_interval_minutes is not None:
            fields.append("poll_interval_minutes=?")
            values.append(poll_interval_minutes)
        if not fields:
            return self.get_connector(connector_id)
        fields.append("updated_at=?")
        values.append(self._now())
        values.append(connector_id)
        with self._lock:
            self._conn.execute(
                f"UPDATE connectors SET {','.join(fields)} WHERE id=?", tuple(values),
            )
            self._conn.commit()
        return self.get_connector(connector_id)

    def delete_connector(self, connector_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM connectors WHERE id = ?", (connector_id,))
            self._conn.execute("DELETE FROM connector_cursors WHERE connector_id = ?", (connector_id,))
            self._conn.execute("DELETE FROM seen_detections WHERE connector_id = ?", (connector_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["enabled"] = bool(d["enabled"])
        d["config"] = json.loads(d.pop("config_json") or "{}")
        d["credential_env"] = json.loads(d.pop("credential_env_json") or "{}")
        d.pop("push_token_hash", None)
        d["push_token_prefix"] = d.get("push_token_prefix")
        d["has_push_token"] = bool(row["push_token_hash"] if "push_token_hash" in row.keys() else False)
        return d

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def rotate_push_token(self, connector_id: str) -> dict[str, Any] | None:
        """Issue a new push token (plaintext returned once)."""
        token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)
        prefix = token[:8]
        now = self._now()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE connectors SET push_token_hash = ?, push_token_prefix = ?, updated_at = ? "
                "WHERE id = ?",
                (token_hash, prefix, now, connector_id),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                return None
        row = self.get_connector(connector_id)
        if not row:
            return None
        return {**row, "push_token": token, "token": token}

    def authenticate_push_token(self, connector_id: str, token: str) -> dict[str, Any] | None:
        """Validate X-Connector-Token / Bearer for machine push ingest."""
        if not token or len(token) > 256:
            return None
        token_hash = self._hash_token(token)
        row = self._conn.execute(
            "SELECT * FROM connectors WHERE id = ?", (connector_id,),
        ).fetchone()
        if row is None or not row["push_token_hash"]:
            return None
        if not hmac.compare_digest(str(row["push_token_hash"]), token_hash):
            return None
        if not row["enabled"]:
            return None
        return self._row_to_dict(row)

    def detection_key_known(self, detection_key: str, qdrant_store: Any | None = None) -> bool:
        """True if the key was seen via poll/push or already has a disposition row."""
        if not detection_key:
            return False
        seen = self._conn.execute(
            "SELECT 1 FROM seen_detections WHERE detection_key = ? LIMIT 1",
            (detection_key,),
        ).fetchone()
        if seen:
            return True
        if self.get_detection_disposition(detection_key):
            return True
        if qdrant_store is not None:
            try:
                for det in self.list_recent_detections(qdrant_store, limit=200):
                    if det.get("detection_key") == detection_key or det.get("source_file") == detection_key:
                        return True
            except Exception:
                logger.debug("detection_key_known qdrant check failed", exc_info=True)
        return False

    # ------------------------------------------------------------- secrets

    def _build_connector(self, row: dict[str, Any]) -> Any:
        """Construct a connector for a stored row.

        `base_url` lives in its own validated column (that is what
        `add_connector` checks against the SSRF allowlist), but connectors
        read it out of their `config` dict. Injecting the column here keeps
        the column authoritative and single-source: a connector created with
        the documented request shape — `base_url` top-level, `config` holding
        only endpoint/auth/pagination settings — previously raised
        `KeyError: 'base_url'` on every poll, because nothing ever copied the
        validated column into the config the connector actually reads.
        """
        config = {**row["config"], "base_url": row["base_url"]}
        secrets = self._resolve_secrets(row["credential_env"])
        return create_detection_connector(
            row["connector_type"], row["name"], config, secrets,
        )

    @staticmethod
    def _resolve_secrets(credential_env: dict[str, str]) -> dict[str, str]:
        """Read each declared env var name's current value. A name with no
        value set in the environment resolves to an empty string — the
        connector's own auth call will then fail cleanly (401/403) rather
        than this raising, so a misconfigured connector surfaces as a normal
        poll failure recorded on the connector row, not a crash."""
        return {key: os.environ.get(env_name, "") for key, env_name in credential_env.items()}

    # --------------------------------------------------------------- cursor

    def _get_cursor(self, connector_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT cursor_value FROM connector_cursors WHERE connector_id = ?", (connector_id,),
        ).fetchone()
        return row["cursor_value"] if row else None

    def _save_cursor(self, connector_id: str, cursor: str | None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO connector_cursors (connector_id, cursor_value, last_seen_at) "
                "VALUES (?, ?, ?) ON CONFLICT(connector_id) DO UPDATE SET "
                "cursor_value=excluded.cursor_value, last_seen_at=excluded.last_seen_at",
                (connector_id, cursor, self._now()),
            )
            self._conn.commit()

    # ------------------------------------------------------------ dedupe

    def _already_seen(self, connector_id: str, detection_key: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM seen_detections WHERE connector_id=? AND detection_key=?",
            (connector_id, detection_key),
        ).fetchone()
        return row is not None

    def _mark_seen(self, connector_id: str, detection_key: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO seen_detections (connector_id, detection_key, first_seen_at) "
                "VALUES (?, ?, ?)",
                (connector_id, detection_key, self._now()),
            )
            self._conn.commit()

    # ----------------------------------------------------------------- poll

    def _record_outcome(self, connector_id: str, status: str, error: str | None) -> None:
        """Record a poll attempt.

        `last_poll_at` is the *attempt* timestamp and drives due-scheduling, so
        a failing connector still backs off to its configured interval instead
        of being retried every scheduler tick. `last_success_at` is only
        advanced by `_record_success` and is what feeds the `since` watermark —
        keeping them separate is what stops a failed poll from skipping over
        detections that were never actually fetched.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE connectors SET last_poll_at=?, last_poll_status=?, last_poll_error=? WHERE id=?",
                (self._now(), status, error, connector_id),
            )
            self._conn.commit()

    def _record_success(self, connector_id: str) -> None:
        now = self._now()
        with self._lock:
            self._conn.execute(
                "UPDATE connectors SET last_poll_at=?, last_success_at=?, "
                "last_poll_status='ok', last_poll_error=NULL WHERE id=?",
                (now, now, connector_id),
            )
            self._conn.commit()

    async def _ingest_raw_detections(
        self,
        row: dict[str, Any],
        connector: Any,
        detections: list[Any],
        *,
        next_cursor: Any = ...,
        record_success: bool = True,
        raw_count: int | None = None,
    ) -> dict[str, Any]:
        """Normalize + ingest a batch of raw detections through the shared pipeline."""
        connector_id = row["id"]
        ingestor = self._ingestor
        if ingestor is None and self._ingestor_factory is not None and detections:
            ingestor = self._ingestor_factory()
            self._ingestor = ingestor
        processed = 0
        skipped = 0
        errors = 0
        for raw in detections:
            try:
                data_model = connector.normalize(raw)
                # source_file is the connector's stable per-detection key
                # ("connector:<name>:<id>"). Skipping ones already ingested
                # matters because re-processing is not free or idempotent
                # downstream: the Qdrant upsert would be a no-op, but
                # `_observe_iocs` -> `check_iocs` INSERTs a *new* alert row
                # every time, so a connector that legitimately re-sees a
                # detection (offset pagination, an overlapping `since`
                # window, a manual re-poll) would otherwise raise duplicate
                # watchlist alerts on every cycle and re-embed the same text.
                detection_key = data_model.source_file or ""
                if detection_key and self._already_seen(connector_id, detection_key):
                    skipped += 1
                    continue
                if ingestor:
                    # process_document is CPU-bound (embedding) and
                    # synchronous; keep the event loop free for other
                    # concurrent polls and requests, same reasoning as
                    # the feed poller's asyncio.to_thread use.
                    await asyncio.to_thread(
                        ingestor.process_document,
                        data_model, row["collection"], f"connector:{row['name']}",
                    )
                self._upsert_asset_from_model(data_model, connector_name=row["name"])
                if detection_key:
                    self._mark_seen(connector_id, detection_key)
                processed += 1
            except Exception:
                errors += 1
                logger.warning(
                    "Connector %s: failed to normalize/ingest one detection", row["name"],
                    exc_info=True,
                )
        if next_cursor is not ...:
            self._save_cursor(connector_id, next_cursor)
        if record_success:
            self._record_success(connector_id)
        return {
            "connector": row["name"],
            "processed": processed,
            "skipped": skipped,
            "errors": errors,
            "raw_count": raw_count if raw_count is not None else len(detections),
        }

    async def poll_connector(self, connector_id: str) -> dict[str, Any]:
        """Poll one connector: pull new detections, normalize each, and push
        it through the ingestor's shared pipeline (see
        `Ingestor.process_document`) — no code here touches Qdrant directly."""
        row = self.get_connector(connector_id)
        if not row:
            return {"error": "Connector not found"}
        if not row["enabled"]:
            return {"connector": row["name"], "skipped": "Connector is disabled"}

        try:
            connector = self._build_connector(row)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._record_outcome(connector_id, "failed", error)
            return {"connector": row["name"], "error": error}

        cursor = self._get_cursor(connector_id)
        # Watermark comes from the last *successful* poll, never a failed
        # attempt — otherwise a single upstream 500 would advance `since` past
        # detections that were never fetched, silently losing them forever.
        since = datetime.fromisoformat(row["last_success_at"]) if row["last_success_at"] else None
        processed = 0
        skipped = 0
        errors = 0
        try:
            result = await connector.pull_detections(since=since, cursor=cursor)
            outcome = await self._ingest_raw_detections(
                row, connector, list(result.detections or []),
                next_cursor=result.next_cursor,
                record_success=True,
                raw_count=result.raw_count,
            )
            return outcome
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._record_outcome(connector_id, "failed", error)
            return {
                "connector": row["name"], "error": error,
                "processed": processed, "skipped": skipped, "errors": errors,
            }

    async def push_detections(
        self, connector_id: str, detections: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Push-ingest path: accept already-fetched raw detections and run
        the same normalize → process_document pipeline as poll (no upstream pull)."""
        row = self.get_connector(connector_id)
        if not row:
            return {"error": "Connector not found"}
        if not row["enabled"]:
            return {"connector": row["name"], "skipped": "Connector is disabled"}
        if not detections:
            return {
                "connector": row["name"], "processed": 0, "skipped": 0,
                "errors": 0, "raw_count": 0,
            }
        try:
            connector = self._build_connector(row)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._record_outcome(connector_id, "failed", error)
            return {"connector": row["name"], "error": error}
        try:
            outcome = await self._ingest_raw_detections(
                row, connector, detections, record_success=True,
            )
            outcome["mode"] = "push"
            return outcome
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._record_outcome(connector_id, "failed", error)
            return {"connector": row["name"], "error": error, "mode": "push"}

    async def test_connector(self, connector_id: str) -> dict[str, Any]:
        row = self.get_connector(connector_id)
        if not row:
            return {"status": "error", "error": "Connector not found"}
        try:
            connector = self._build_connector(row)
        except Exception as exc:
            return {"status": "error", "connector": row["name"], "error": str(exc)}
        return await connector.test_connection()

    async def poll_all(self) -> dict[str, dict[str, Any]]:
        """Poll every enabled connector that is due, reporting the ones that are not."""
        now = datetime.now(timezone.utc)
        due: list[dict[str, Any]] = []
        skipped: dict[str, dict[str, Any]] = {}
        for row in self.list_connectors():
            if not row["enabled"]:
                skipped[row["name"]] = {"connector": row["name"], "skipped": "Connector is disabled"}
                continue
            last_poll = datetime.fromisoformat(row["last_poll_at"]) if row["last_poll_at"] else None
            if last_poll and (now - last_poll).total_seconds() < row["poll_interval_minutes"] * 60:
                next_due = last_poll + timedelta(minutes=row["poll_interval_minutes"])
                skipped[row["name"]] = {
                    "connector": row["name"],
                    "skipped": f"Not due until {next_due.isoformat(timespec='minutes')}",
                }
                continue
            due.append(row)

        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def poll(row: dict[str, Any]) -> tuple[str, dict[str, Any]]:
            async with semaphore:
                return row["name"], await self.poll_connector(row["id"])

        polled = dict(await asyncio.gather(*(poll(row) for row in due)))
        return {**skipped, **polled}

    def start_scheduler(self, interval_seconds: int = 60) -> None:
        """Start a background scheduler to poll connectors periodically."""
        def _scheduler() -> None:
            while not self._scheduler_stop.is_set():
                try:
                    asyncio.run(self.poll_all())
                except Exception as exc:
                    logger.error("Connector scheduler error: %s", exc)
                self._scheduler_stop.wait(interval_seconds)

        if not self._scheduler_thread or not self._scheduler_thread.is_alive():
            self._scheduler_stop.clear()
            self._scheduler_thread = threading.Thread(target=_scheduler, daemon=True)
            self._scheduler_thread.start()

    def close(self) -> None:
        self._scheduler_stop.set()
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
        if self._conn:
            self._conn.close()

    # --------------------------------------------------------------- reads

    def list_recent_detections(self, qdrant_store: Any, limit: int = 20) -> list[dict[str, Any]]:
        """Best-effort recent-detections view across every connector's
        collection, for the Dashboard/Detections page. Scrolls each enabled
        connector's collection (Qdrant has no cross-collection query) and
        merges client-side by indexed_at — fine at this scale (a handful of
        connectors, a `limit`-sized result), not meant for deep pagination.
        """
        items: list[dict[str, Any]] = []
        for row in self.list_connectors():
            try:
                points, _ = qdrant_store.scroll(
                    row["collection"], limit=limit, with_payload=True, with_vectors=False,
                )
            except Exception:
                continue  # collection may not exist yet if the connector has never polled
            for point in points:
                payload = point.payload or {}
                techniques = payload.get("mitre_techniques") or payload.get("technique_ids") or []
                if isinstance(techniques, str):
                    techniques = [techniques]
                tags = payload.get("ioc_tags") or []
                severity = ""
                if isinstance(tags, list) and tags:
                    severity = str(tags[0])
                elif payload.get("severity"):
                    severity = str(payload.get("severity"))
                source_file = payload.get("source_file") or ""
                disposition = self.get_detection_disposition(source_file) if source_file else None
                items.append({
                    "connector": row["name"],
                    "title": payload.get("title"),
                    "source_file": source_file,
                    "detection_key": source_file,
                    "indexed_at": payload.get("indexed_at"),
                    "ioc_status": payload.get("ioc_status"),
                    "event_time": (
                        payload.get("event_time")
                        or payload.get("capture_time")
                        or (payload.get("enrichment_data") or {}).get("event_time")
                    ),
                    "capture_time": payload.get("capture_time"),
                    "severity": severity or (payload.get("enrichment_data") or {}).get("severity") or "",
                    "technique_ids": list(techniques),
                    "hostname": payload.get("hostname") or (payload.get("enrichment_data") or {}).get("hostname"),
                    "username": payload.get("username") or (payload.get("enrichment_data") or {}).get("username"),
                    "point_id": str(getattr(point, "id", "")),
                    "collection": row["collection"],
                    "disposition": (disposition or {}).get("disposition"),
                    "acknowledged": bool((disposition or {}).get("acknowledged")),
                    "promoted_case_id": (disposition or {}).get("promoted_case_id"),
                })
        items.sort(key=lambda item: item.get("indexed_at") or "", reverse=True)
        return items[:limit]

    def _upsert_asset_from_model(self, data_model: Any, *, connector_name: str) -> None:
        if not self._asset_manager or not hasattr(self._asset_manager, "upsert_from_sighting"):
            return
        enrichment = getattr(data_model, "enrichment_data", None) or {}
        if not isinstance(enrichment, dict):
            enrichment = {}
        hostname = enrichment.get("hostname") or ""
        username = enrichment.get("username") or ""
        ips = list(getattr(data_model, "ip_addresses", None) or [])
        ip_address = str(ips[0]) if ips else ""
        if not hostname and not username and not ip_address:
            return
        try:
            self._asset_manager.upsert_from_sighting(
                hostname=str(hostname or ""),
                ip_address=ip_address,
                username=str(username or ""),
                source=f"connector:{connector_name}",
            )
        except Exception:
            logger.debug("asset upsert from connector failed", exc_info=True)

    def get_detection_disposition(self, detection_key: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM detection_dispositions WHERE detection_key = ?",
            (detection_key,),
        ).fetchone()
        return dict(row) if row else None

    def dispose_detection(
        self,
        detection_key: str,
        *,
        disposition: str,
        disposition_by: str = "",
        disposition_note: str = "",
        connector: str = "",
        title: str = "",
        acknowledge: bool = True,
    ) -> dict[str, Any]:
        from black_onyx.threat.watchlist_manager import DISPOSITIONS
        if disposition not in DISPOSITIONS:
            raise ValueError(f"Invalid disposition. Allowed: {', '.join(sorted(DISPOSITIONS))}")
        if not self.detection_key_known(detection_key):
            raise LookupError(f"Unknown detection_key: {detection_key}")
        now = self._now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO detection_dispositions "
                "(detection_key, connector, title, disposition, disposition_by, "
                "disposition_note, disposition_at, acknowledged, acknowledged_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(detection_key) DO UPDATE SET "
                "disposition=excluded.disposition, disposition_by=excluded.disposition_by, "
                "disposition_note=excluded.disposition_note, disposition_at=excluded.disposition_at, "
                "acknowledged=excluded.acknowledged, acknowledged_at=excluded.acknowledged_at, "
                "connector=COALESCE(excluded.connector, detection_dispositions.connector), "
                "title=COALESCE(excluded.title, detection_dispositions.title)",
                (
                    detection_key, connector, title, disposition, disposition_by,
                    disposition_note, now, 1 if acknowledge else 0, now if acknowledge else None,
                ),
            )
            self._conn.commit()
        return self.get_detection_disposition(detection_key)  # type: ignore[return-value]

    def acknowledge_detection(self, detection_key: str) -> dict[str, Any] | None:
        now = self._now()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE detection_dispositions SET acknowledged = 1, acknowledged_at = ? "
                "WHERE detection_key = ?",
                (now, detection_key),
            )
            if cur.rowcount == 0:
                self._conn.execute(
                    "INSERT INTO detection_dispositions "
                    "(detection_key, acknowledged, acknowledged_at) VALUES (?, 1, ?)",
                    (detection_key, now),
                )
            self._conn.commit()
        return self.get_detection_disposition(detection_key)

    def set_detection_promoted_case(self, detection_key: str, case_id: str) -> dict[str, Any] | None:
        """Link a detection to a case. Returns None if already promoted."""
        if not self.detection_key_known(detection_key):
            raise LookupError(f"Unknown detection_key: {detection_key}")
        now = self._now()
        with self._lock:
            existing = self.get_detection_disposition(detection_key)
            if existing and existing.get("promoted_case_id"):
                return None
            if existing:
                cur = self._conn.execute(
                    "UPDATE detection_dispositions SET promoted_case_id = ?, acknowledged = 1, "
                    "acknowledged_at = COALESCE(acknowledged_at, ?) "
                    "WHERE detection_key = ? AND (promoted_case_id IS NULL OR promoted_case_id = '')",
                    (case_id, now, detection_key),
                )
                self._conn.commit()
                if cur.rowcount == 0:
                    return None
            else:
                self._conn.execute(
                    "INSERT INTO detection_dispositions "
                    "(detection_key, promoted_case_id, acknowledged, acknowledged_at) "
                    "VALUES (?, ?, 1, ?)",
                    (detection_key, case_id, now),
                )
                self._conn.commit()
        return self.get_detection_disposition(detection_key)
