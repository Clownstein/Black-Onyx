"""Watchlist management — track IOCs and alert on matches during ingestion."""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DISPOSITIONS = frozenset({
    "true_positive",
    "false_positive",
    "benign_positive",
    "duplicate",
    "informational",
    "escalated",
})


class WatchlistManager:
    """Manages IOC watchlists with SQLite persistence.

    Tables: watchlists, watchlist_items, alerts.
    """

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "watchlists.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS watchlists (
                list_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS watchlist_items (
                item_id TEXT PRIMARY KEY,
                list_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (list_id) REFERENCES watchlists(list_id)
            );
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                list_id TEXT NOT NULL,
                item_id TEXT NOT NULL,
                triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                collection TEXT,
                point_id TEXT,
                context TEXT,
                acknowledged INTEGER DEFAULT 0,
                FOREIGN KEY (list_id) REFERENCES watchlists(list_id)
            );
            CREATE INDEX IF NOT EXISTS idx_items_value ON watchlist_items(ioc_value);
            CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);
        """)
        item_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(watchlist_items)")}
        for column, ddl in (
            ("suppressed", "ALTER TABLE watchlist_items ADD COLUMN suppressed INTEGER DEFAULT 0"),
            ("confidence", "ALTER TABLE watchlist_items ADD COLUMN confidence REAL DEFAULT 1.0"),
        ):
            if column not in item_cols:
                self._conn.execute(ddl)
        alert_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(alerts)")}
        for column, ddl in (
            ("acknowledged_at", "ALTER TABLE alerts ADD COLUMN acknowledged_at TIMESTAMP"),
            ("disposition", "ALTER TABLE alerts ADD COLUMN disposition TEXT"),
            ("disposition_by", "ALTER TABLE alerts ADD COLUMN disposition_by TEXT"),
            ("disposition_note", "ALTER TABLE alerts ADD COLUMN disposition_note TEXT"),
            ("promoted_case_id", "ALTER TABLE alerts ADD COLUMN promoted_case_id TEXT"),
        ):
            if column not in alert_cols:
                self._conn.execute(ddl)
        self._conn.commit()

    def create_watchlist(self, name: str, description: str = "") -> str:
        list_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO watchlists (list_id, name, description) VALUES (?, ?, ?)",
                (list_id, name, description),
            )
            self._conn.commit()
        return list_id

    def add_items(self, list_id: str, items: list[tuple[str, str]]) -> None:
        with self._lock:
            for ioc_type, ioc_value in items:
                item_id = str(uuid.uuid4())
                self._conn.execute(
                    "INSERT INTO watchlist_items (item_id, list_id, ioc_type, ioc_value, suppressed, confidence) "
                    "VALUES (?, ?, ?, ?, 0, 1.0)",
                    (item_id, list_id, ioc_type, ioc_value),
                )
            self._conn.execute(
                "UPDATE watchlists SET updated_at = ? WHERE list_id = ?",
                (datetime.now().isoformat(), list_id),
            )
            self._conn.commit()

    def remove_item(self, item_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM watchlist_items WHERE item_id = ?", (item_id,))
            self._conn.commit()

    def list_watchlists(self) -> list[dict]:
        rows = self._conn.execute("""
            SELECT w.*, COUNT(i.item_id) as item_count
            FROM watchlists w
            LEFT JOIN watchlist_items i ON w.list_id = i.list_id
            GROUP BY w.list_id
            ORDER BY w.updated_at DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_items(self, list_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM watchlist_items WHERE list_id = ? ORDER BY added_at DESC",
            (list_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_item(self, item_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM watchlist_items WHERE item_id = ?", (item_id,),
        ).fetchone()
        return dict(row) if row else None

    def check_iocs(
        self, iocs: dict[str, list], collection: str = "", point_id: str = "", context: str = ""
    ) -> list[dict]:
        """Check extracted IOCs against all watchlists.

        Args:
            iocs: Dict from IOCResult.to_dict() (e.g. {"ipv4": [...], "domains": [...]}).

        Returns:
            List of alert dicts for any matches found.
        """
        alerts: list[dict] = []
        all_values: set[str] = set()
        for values in iocs.values():
            if isinstance(values, list):
                all_values.update(values)

        if not all_values:
            return alerts

        rows: list[sqlite3.Row] = []
        for value in all_values:
            rows.extend(self._conn.execute(
                "SELECT i.*, w.name as watchlist_name FROM watchlist_items i "
                "JOIN watchlists w ON i.list_id = w.list_id "
                "WHERE i.ioc_value = ? AND COALESCE(i.suppressed, 0) = 0",
                (value,),
            ).fetchall())

        for row in rows:
            alert_id = str(uuid.uuid4())
            with self._lock:
                self._conn.execute(
                    "INSERT INTO alerts (alert_id, list_id, item_id, collection, point_id, context) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (alert_id, row["list_id"], row["item_id"], collection, point_id, context),
                )
                self._conn.commit()
            alerts.append({
                "alert_id": alert_id,
                "list_id": row["list_id"],
                "watchlist_name": row["watchlist_name"],
                "ioc_type": row["ioc_type"],
                "ioc_value": row["ioc_value"],
                "triggered_at": datetime.now().isoformat(),
            })

        return alerts

    def get_alert(self, alert_id: str) -> dict | None:
        row = self._conn.execute("""
            SELECT a.*, i.ioc_type, i.ioc_value, w.name as watchlist_name
            FROM alerts a
            LEFT JOIN watchlist_items i ON a.item_id = i.item_id
            LEFT JOIN watchlists w ON a.list_id = w.list_id
            WHERE a.alert_id = ?
        """, (alert_id,)).fetchone()
        return dict(row) if row else None

    def get_alerts(self, limit: int = 50, unacknowledged_only: bool = False) -> list[dict]:
        """Return alerts joined with the watchlist item/name that triggered them."""
        where = "WHERE a.acknowledged = 0" if unacknowledged_only else ""
        rows = self._conn.execute(f"""
            SELECT a.*, i.ioc_type, i.ioc_value, i.added_at AS item_added_at, w.name as watchlist_name
            FROM alerts a
            LEFT JOIN watchlist_items i ON a.item_id = i.item_id
            LEFT JOIN watchlists w ON a.list_id = w.list_id
            {where}
            ORDER BY a.triggered_at DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: str) -> None:
        now = datetime.now().isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET acknowledged = 1, acknowledged_at = COALESCE(acknowledged_at, ?) "
                "WHERE alert_id = ?",
                (now, alert_id),
            )
            self._conn.commit()

    def dispose_alert(
        self,
        alert_id: str,
        disposition: str,
        disposition_by: str = "",
        disposition_note: str = "",
        *,
        suppress_item: bool = False,
        lower_confidence: bool = False,
        confidence_delta: float = 0.25,
    ) -> dict[str, Any]:
        """Set disposition on an alert; optionally suppress / lower confidence of the IOC item.

        For false_positive dispositions, callers may pass suppress_item / lower_confidence
        to apply CTI feedback against the watchlist item that triggered the alert.
        """
        if disposition not in DISPOSITIONS:
            raise ValueError(
                f"Invalid disposition '{disposition}'. "
                f"Allowed: {', '.join(sorted(DISPOSITIONS))}"
            )
        alert = self.get_alert(alert_id)
        if not alert:
            raise KeyError(f"Alert not found: {alert_id}")

        now = datetime.now().isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET acknowledged = 1, "
                "acknowledged_at = COALESCE(acknowledged_at, ?), "
                "disposition = ?, disposition_by = ?, disposition_note = ? "
                "WHERE alert_id = ?",
                (now, disposition, disposition_by, disposition_note, alert_id),
            )
            feedback: dict[str, Any] = {}
            item_id = alert.get("item_id")
            if disposition == "false_positive" and item_id and (suppress_item or lower_confidence):
                if suppress_item:
                    self._conn.execute(
                        "UPDATE watchlist_items SET suppressed = 1 WHERE item_id = ?",
                        (item_id,),
                    )
                    feedback["suppressed"] = True
                if lower_confidence:
                    row = self._conn.execute(
                        "SELECT confidence FROM watchlist_items WHERE item_id = ?",
                        (item_id,),
                    ).fetchone()
                    current = float(row["confidence"] if row and row["confidence"] is not None else 1.0)
                    new_conf = max(0.0, current - abs(confidence_delta))
                    self._conn.execute(
                        "UPDATE watchlist_items SET confidence = ? WHERE item_id = ?",
                        (new_conf, item_id),
                    )
                    feedback["confidence"] = new_conf
            self._conn.commit()

        updated = self.get_alert(alert_id) or {}
        if feedback:
            updated["cti_feedback"] = feedback
        return updated

    def set_promoted_case_id(self, alert_id: str, case_id: str) -> dict | None:
        """Link an alert to a case. Returns None if already promoted (race loser)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alerts SET promoted_case_id = ?, acknowledged = 1, "
                "acknowledged_at = COALESCE(acknowledged_at, ?), "
                "disposition = COALESCE(disposition, 'escalated') "
                "WHERE alert_id = ? AND (promoted_case_id IS NULL OR promoted_case_id = '')",
                (case_id, now, alert_id),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                return None
        return self.get_alert(alert_id)

    def alerts_since(self, since_iso: str, limit: int = 10_000) -> list[dict]:
        rows = self._conn.execute("""
            SELECT a.*, i.ioc_type, i.ioc_value, i.added_at AS item_added_at, w.name as watchlist_name
            FROM alerts a
            LEFT JOIN watchlist_items i ON a.item_id = i.item_id
            LEFT JOIN watchlists w ON a.list_id = w.list_id
            WHERE a.triggered_at >= ?
            ORDER BY a.triggered_at DESC LIMIT ?
        """, (since_iso, limit)).fetchall()
        return [dict(r) for r in rows]

    def delete_watchlist(self, list_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM watchlist_items WHERE list_id = ?", (list_id,))
            self._conn.execute("DELETE FROM alerts WHERE list_id = ?", (list_id,))
            self._conn.execute("DELETE FROM watchlists WHERE list_id = ?", (list_id,))
            self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
