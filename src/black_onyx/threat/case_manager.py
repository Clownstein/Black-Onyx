"""Case management — SQLite-backed investigation tracking."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default SLA hours by normalized severity
_SLA_HOURS: dict[str, int] = {
    "critical": 4,
    "high": 24,
    "medium": 72,
    "low": 168,
    "informational": 336,
}

_PRIORITY_TO_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


@dataclass
class Case:
    """Investigation case data model."""
    case_id: str
    title: str
    description: str
    status: str = "open"
    priority: str = "medium"
    severity: str = "medium"
    assignee: str | None = None
    tags: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    detected_at: str | None = None
    contained_at: str | None = None
    closed_at: str | None = None
    sla_due_at: str | None = None
    external_incident_id: str | None = None
    related_iocs: list[str] = field(default_factory=list)
    related_points: list[str] = field(default_factory=list)


class CaseManager:
    """Manages investigation cases with SQLite persistence.

    Tables: cases, case_iocs, case_points, case_notes, case_timeline.
    """

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        self._sla_hours = dict(_SLA_HOURS)
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "cases.sqlite")
            self._load_sla_policy()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _sla_policy_path(self) -> Path | None:
        if not self._persist_dir:
            return None
        return self._persist_dir / "sla_policy.json"

    def _load_sla_policy(self) -> None:
        path = self._sla_policy_path()
        if not path or not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for key, value in data.items():
                    if key in self._sla_hours and isinstance(value, (int, float)) and value > 0:
                        self._sla_hours[key] = int(value)
        except Exception:
            logger.debug("Failed to load SLA policy", exc_info=True)

    def get_sla_hours(self) -> dict[str, int]:
        return dict(self._sla_hours)

    def set_sla_hours(self, hours: dict[str, Any]) -> dict[str, int]:
        updated = dict(self._sla_hours)
        for key, value in (hours or {}).items():
            if key not in updated:
                continue
            try:
                hours_int = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid SLA hours for {key}") from exc
            if hours_int < 1 or hours_int > 10_000:
                raise ValueError(f"SLA hours for {key} must be between 1 and 10000")
            updated[key] = hours_int
        self._sla_hours = updated
        path = self._sla_policy_path()
        if path:
            path.write_text(json.dumps(updated, indent=2), encoding="utf-8")
        return dict(self._sla_hours)

    def _init_db(self) -> None:
        if not self._conn:
            return
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'open',
                priority TEXT DEFAULT 'medium',
                assignee TEXT,
                tags TEXT,
                external_incident_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS case_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            );
            CREATE TABLE IF NOT EXISTS case_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                collection_name TEXT NOT NULL,
                point_id TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            );
            CREATE TABLE IF NOT EXISTS case_notes (
                note_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                author TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            );
            CREATE TABLE IF NOT EXISTS case_timeline (
                event_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT,
                description TEXT,
                author TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            );
        """)
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(cases)")}
        for column, ddl in (
            ("severity", "ALTER TABLE cases ADD COLUMN severity TEXT"),
            ("detected_at", "ALTER TABLE cases ADD COLUMN detected_at TIMESTAMP"),
            ("contained_at", "ALTER TABLE cases ADD COLUMN contained_at TIMESTAMP"),
            ("closed_at", "ALTER TABLE cases ADD COLUMN closed_at TIMESTAMP"),
            ("sla_due_at", "ALTER TABLE cases ADD COLUMN sla_due_at TIMESTAMP"),
            ("external_incident_id", "ALTER TABLE cases ADD COLUMN external_incident_id TEXT"),
        ):
            if column not in existing:
                self._conn.execute(ddl)
        # One-shot backfill only for rows still missing severity/SLA (not every construct).
        rows = self._conn.execute(
            "SELECT case_id, priority, severity, created_at, sla_due_at FROM cases "
            "WHERE severity IS NULL OR severity = '' OR sla_due_at IS NULL OR sla_due_at = ''"
        ).fetchall()
        for row in rows:
            updates: list[str] = []
            params: list[Any] = []
            sev = row["severity"] or _PRIORITY_TO_SEVERITY.get(row["priority"] or "medium", "medium")
            if not row["severity"]:
                updates.append("severity = ?")
                params.append(sev)
            if not row["sla_due_at"] and row["created_at"]:
                try:
                    created = datetime.fromisoformat(str(row["created_at"]))
                except ValueError:
                    created = datetime.now(timezone.utc)
                hours = self._sla_hours.get(sev, 72)
                updates.append("sla_due_at = ?")
                params.append((created + timedelta(hours=hours)).isoformat())
            if updates:
                params.append(row["case_id"])
                self._conn.execute(
                    f"UPDATE cases SET {', '.join(updates)} WHERE case_id = ?",
                    params,
                )
        self._conn.commit()

    def _compute_sla_due(self, severity: str, detected_at: str | None = None) -> str:
        base = datetime.now(timezone.utc)
        if detected_at:
            try:
                parsed = datetime.fromisoformat(str(detected_at).replace("Z", "+00:00"))
                if parsed.tzinfo is not None:
                    base = parsed.astimezone(timezone.utc)
                else:
                    base = parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        hours = self._sla_hours.get(severity, 72)
        return (base + timedelta(hours=hours)).isoformat()

    def create_case(
        self,
        title: str,
        description: str = "",
        priority: str = "medium",
        assignee: str | None = None,
        tags: list[str] | None = None,
        *,
        severity: str | None = None,
        detected_at: str | None = None,
        contained_at: str | None = None,
        closed_at: str | None = None,
        sla_due_at: str | None = None,
        external_incident_id: str | None = None,
    ) -> Case:
        case_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        tags_json = json.dumps(tags or [])
        sev = severity or _PRIORITY_TO_SEVERITY.get(priority, "medium")
        detected = detected_at or now
        sla = sla_due_at or self._compute_sla_due(sev, detected)
        with self._lock:
            self._conn.execute(
                "INSERT INTO cases (case_id, title, description, status, priority, severity, "
                "assignee, tags, created_at, updated_at, detected_at, contained_at, closed_at, "
                "sla_due_at, external_incident_id) "
                "VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case_id, title, description, priority, sev, assignee, tags_json,
                    now, now, detected, contained_at, closed_at, sla, external_incident_id,
                ),
            )
            self._conn.execute(
                "INSERT INTO case_timeline (event_id, case_id, event_type, description, author, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()), case_id, "status_change",
                    "status:open", "system", now,
                ),
            )
            self._conn.commit()
        return Case(
            case_id=case_id, title=title, description=description,
            status="open", priority=priority, severity=sev, assignee=assignee,
            tags=tags or [], created_at=now, updated_at=now,
            detected_at=detected, contained_at=contained_at, closed_at=closed_at,
            sla_due_at=sla, external_incident_id=external_incident_id,
        )

    def get_case_by_external_incident(self, external_incident_id: str) -> Case | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM cases WHERE external_incident_id = ? ORDER BY created_at DESC LIMIT 1",
                (external_incident_id,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_case(row)

    def get_case(self, case_id: str) -> Case | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM cases WHERE case_id = ?", (case_id,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_case(row)

    def list_cases(self, status: str | None = None, limit: int = 50) -> list[Case]:
        if status:
            rows = self._conn.execute(
                "SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,),
            ).fetchall()
        return [self._row_to_case(r) for r in rows]

    def cases_since(self, since_iso: str, limit: int = 10_000) -> list[Case]:
        rows = self._conn.execute(
            "SELECT * FROM cases WHERE created_at >= ? OR COALESCE(detected_at, '') >= ? "
            "ORDER BY updated_at DESC LIMIT ?",
            (since_iso, since_iso, limit),
        ).fetchall()
        return [self._row_to_case(r) for r in rows]

    def update_case(self, case_id: str, **kwargs: Any) -> Case | None:
        statements = {
            "title": "UPDATE cases SET title = ? WHERE case_id = ?",
            "description": "UPDATE cases SET description = ? WHERE case_id = ?",
            "status": "UPDATE cases SET status = ? WHERE case_id = ?",
            "priority": "UPDATE cases SET priority = ? WHERE case_id = ?",
            "severity": "UPDATE cases SET severity = ? WHERE case_id = ?",
            "assignee": "UPDATE cases SET assignee = ? WHERE case_id = ?",
            "tags": "UPDATE cases SET tags = ? WHERE case_id = ?",
            "detected_at": "UPDATE cases SET detected_at = ? WHERE case_id = ?",
            "contained_at": "UPDATE cases SET contained_at = ? WHERE case_id = ?",
            "closed_at": "UPDATE cases SET closed_at = ? WHERE case_id = ?",
            "sla_due_at": "UPDATE cases SET sla_due_at = ? WHERE case_id = ?",
            "external_incident_id": "UPDATE cases SET external_incident_id = ? WHERE case_id = ?",
        }
        updates: list[tuple[str, Any]] = []
        for k, v in kwargs.items():
            if k in statements:
                updates.append((k, json.dumps(v) if k == "tags" else v))
        if not updates:
            return self.get_case(case_id)

        now = datetime.now().isoformat()
        current = self.get_case(case_id)
        if not current:
            return None
        # Auto-stamp closed_at / contained_at when status transitions
        status_val = kwargs.get("status")
        if status_val in ("resolved", "closed") and "closed_at" not in kwargs:
            updates.append(("closed_at", now))
        if status_val == "resolved" and "contained_at" not in kwargs:
            if not current.contained_at:
                updates.append(("contained_at", now))
        if "priority" in kwargs and "severity" not in kwargs:
            sev = _PRIORITY_TO_SEVERITY.get(str(kwargs["priority"]), "medium")
            updates.append(("severity", sev))

        with self._lock:
            for column, value in updates:
                self._conn.execute(statements[column], (value, case_id))
            self._conn.execute(
                "UPDATE cases SET updated_at = ? WHERE case_id = ?",
                (now, case_id),
            )
            if status_val and status_val != current.status:
                self._conn.execute(
                    "INSERT INTO case_timeline (event_id, case_id, event_type, description, author, timestamp) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()), case_id, "status_change",
                        f"status:{status_val}", "system", now,
                    ),
                )
            self._conn.commit()
        return self.get_case(case_id)

    def add_ioc_to_case(self, case_id: str, ioc_type: str, ioc_value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO case_iocs (case_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                (case_id, ioc_type, ioc_value),
            )
            self._conn.commit()

    def add_point_to_case(self, case_id: str, collection_name: str, point_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO case_points (case_id, collection_name, point_id) VALUES (?, ?, ?)",
                (case_id, collection_name, point_id),
            )
            self._conn.commit()

    def add_note(self, case_id: str, author: str, content: str) -> str:
        note_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO case_notes (note_id, case_id, author, content) VALUES (?, ?, ?, ?)",
                (note_id, case_id, author, content),
            )
            self._conn.commit()
        return note_id

    def get_notes(self, case_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at DESC",
            (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def add_timeline_event(
        self, case_id: str, event_type: str, description: str, author: str = "system",
    ) -> str:
        event_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO case_timeline (event_id, case_id, event_type, description, author) "
                "VALUES (?, ?, ?, ?, ?)",
                (event_id, case_id, event_type, description, author),
            )
            self._conn.commit()
        return event_id

    def get_timeline(self, case_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM case_timeline WHERE case_id = ? ORDER BY timestamp ASC",
            (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_case_iocs(self, case_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM case_iocs WHERE case_id = ?", (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_case_points(self, case_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM case_points WHERE case_id = ?", (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_case(self, case_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM case_iocs WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM case_points WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM case_notes WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM case_timeline WHERE case_id = ?", (case_id,))
            self._conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
            self._conn.commit()

    @staticmethod
    def _row_to_case(row: sqlite3.Row) -> Case:
        keys = set(row.keys())
        priority = row["priority"]
        severity = row["severity"] if "severity" in keys and row["severity"] else (
            _PRIORITY_TO_SEVERITY.get(priority, "medium")
        )
        return Case(
            case_id=row["case_id"],
            title=row["title"],
            description=row["description"] or "",
            status=row["status"],
            priority=priority,
            severity=severity,
            assignee=row["assignee"],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            detected_at=row["detected_at"] if "detected_at" in keys else None,
            contained_at=row["contained_at"] if "contained_at" in keys else None,
            closed_at=row["closed_at"] if "closed_at" in keys else None,
            sla_due_at=row["sla_due_at"] if "sla_due_at" in keys else None,
            external_incident_id=(
                row["external_incident_id"] if "external_incident_id" in keys else None
            ),
        )

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
