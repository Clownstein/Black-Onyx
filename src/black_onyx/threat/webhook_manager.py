"""Inbound webhook tokens for external IOC / event ingestion."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class WebhookManager:
    """Create and validate inbound webhook tokens (SQLite-backed)."""

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "webhooks.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS webhooks (
                webhook_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                token_prefix TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP,
                event_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_webhooks_hash ON webhooks(token_hash);
            CREATE TABLE IF NOT EXISTS webhook_events (
                event_id TEXT PRIMARY KEY,
                webhook_id TEXT NOT NULL,
                webhook_name TEXT NOT NULL,
                source TEXT,
                ioc_count INTEGER NOT NULL DEFAULT 0,
                iocs_json TEXT NOT NULL DEFAULT '{}',
                alert_ids_json TEXT NOT NULL DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                acknowledged_at TIMESTAMP,
                disposition TEXT,
                disposition_by TEXT,
                disposition_note TEXT,
                disposition_at TIMESTAMP,
                promoted_case_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_webhook_events_created
                ON webhook_events(created_at DESC);
            """
        )
        self._conn.commit()

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_webhook(self, name: str) -> dict:
        """Create a webhook and return metadata including the one-time plaintext token."""
        webhook_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)
        prefix = token[:8]
        with self._lock:
            self._conn.execute(
                "INSERT INTO webhooks (webhook_id, name, token_hash, token_prefix) VALUES (?, ?, ?, ?)",
                (webhook_id, name.strip(), token_hash, prefix),
            )
            self._conn.commit()
        return {
            "webhook_id": webhook_id,
            "name": name.strip(),
            "token": token,
            "token_prefix": prefix,
            "enabled": True,
            "event_count": 0,
            "created_at": datetime.now().isoformat(),
            "last_used_at": None,
        }

    def list_webhooks(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT webhook_id, name, token_prefix, enabled, created_at, last_used_at, event_count "
            "FROM webhooks ORDER BY created_at DESC"
        ).fetchall()
        return [
            {
                "webhook_id": r["webhook_id"],
                "name": r["name"],
                "token_prefix": r["token_prefix"],
                "enabled": bool(r["enabled"]),
                "created_at": r["created_at"],
                "last_used_at": r["last_used_at"],
                "event_count": r["event_count"],
            }
            for r in rows
        ]

    def delete_webhook(self, webhook_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM webhooks WHERE webhook_id = ?", (webhook_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def set_enabled(self, webhook_id: str, enabled: bool) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE webhooks SET enabled = ? WHERE webhook_id = ?",
                (1 if enabled else 0, webhook_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def authenticate(self, token: str) -> dict | None:
        """Validate a bearer/header token. Returns webhook metadata or None."""
        if not token or len(token) > 256:
            return None
        token_hash = self._hash_token(token)
        row = self._conn.execute(
            "SELECT webhook_id, name, enabled FROM webhooks WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        # Constant-time compare already implied by hash lookup; keep hmac for defense in depth
        stored = self._conn.execute(
            "SELECT token_hash FROM webhooks WHERE webhook_id = ?",
            (row["webhook_id"],),
        ).fetchone()
        if stored is None or not hmac.compare_digest(stored["token_hash"], token_hash):
            return None
        if not row["enabled"]:
            return None
        with self._lock:
            self._conn.execute(
                "UPDATE webhooks SET last_used_at = ?, event_count = event_count + 1 WHERE webhook_id = ?",
                (datetime.now().isoformat(), row["webhook_id"]),
            )
            self._conn.commit()
        return {"webhook_id": row["webhook_id"], "name": row["name"]}

    def record_event(
        self,
        *,
        webhook_id: str,
        webhook_name: str,
        source: str,
        iocs: dict[str, list[str]],
        alert_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Persist an inbound webhook event for triage / query history."""
        event_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        ioc_count = sum(len(v) for v in (iocs or {}).values())
        with self._lock:
            self._conn.execute(
                "INSERT INTO webhook_events "
                "(event_id, webhook_id, webhook_name, source, ioc_count, iocs_json, "
                "alert_ids_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    webhook_id,
                    webhook_name,
                    source,
                    ioc_count,
                    json.dumps(iocs or {}),
                    json.dumps(alert_ids or []),
                    now,
                ),
            )
            self._conn.commit()
        return self.get_event(event_id)  # type: ignore[return-value]

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM webhook_events WHERE event_id = ?", (event_id,),
        ).fetchone()
        return self._row_to_event(row) if row else None

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM webhook_events ORDER BY created_at DESC LIMIT ?",
            (max(1, min(limit, 2_000)),),
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def dispose_event(
        self,
        event_id: str,
        *,
        disposition: str,
        disposition_by: str = "",
        disposition_note: str = "",
        acknowledge: bool = True,
    ) -> dict[str, Any] | None:
        from black_onyx.threat.watchlist_manager import DISPOSITIONS
        if disposition not in DISPOSITIONS:
            raise ValueError(f"Invalid disposition. Allowed: {', '.join(sorted(DISPOSITIONS))}")
        now = datetime.now().isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE webhook_events SET disposition = ?, disposition_by = ?, "
                "disposition_note = ?, disposition_at = ?, "
                "acknowledged = CASE WHEN ? THEN 1 ELSE acknowledged END, "
                "acknowledged_at = CASE WHEN ? THEN ? ELSE acknowledged_at END "
                "WHERE event_id = ?",
                (
                    disposition, disposition_by, disposition_note, now,
                    1 if acknowledge else 0, 1 if acknowledge else 0, now, event_id,
                ),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                return None
        return self.get_event(event_id)

    def acknowledge_event(self, event_id: str) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE webhook_events SET acknowledged = 1, acknowledged_at = ? "
                "WHERE event_id = ?",
                (now, event_id),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                return None
        return self.get_event(event_id)

    def set_event_promoted_case(self, event_id: str, case_id: str) -> dict[str, Any] | None:
        """Link a webhook event to a case. Returns None if already promoted."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE webhook_events SET promoted_case_id = ?, acknowledged = 1, "
                "acknowledged_at = COALESCE(acknowledged_at, ?), "
                "disposition = COALESCE(disposition, 'escalated') "
                "WHERE event_id = ? AND (promoted_case_id IS NULL OR promoted_case_id = '')",
                (case_id, now, event_id),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                return None
        return self.get_event(event_id)

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
        try:
            iocs = json.loads(row["iocs_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            iocs = {}
        try:
            alert_ids = json.loads(row["alert_ids_json"] or "[]")
        except (TypeError, json.JSONDecodeError):
            alert_ids = []
        return {
            "event_id": row["event_id"],
            "webhook_id": row["webhook_id"],
            "webhook_name": row["webhook_name"],
            "source": row["source"],
            "ioc_count": row["ioc_count"],
            "iocs": iocs,
            "alert_ids": alert_ids,
            "created_at": row["created_at"],
            "acknowledged": bool(row["acknowledged"]),
            "acknowledged_at": row["acknowledged_at"],
            "disposition": row["disposition"],
            "disposition_by": row["disposition_by"],
            "disposition_note": row["disposition_note"],
            "disposition_at": row["disposition_at"],
            "promoted_case_id": row["promoted_case_id"],
        }

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
