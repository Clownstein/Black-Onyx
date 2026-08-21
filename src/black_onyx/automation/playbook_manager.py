"""SOAR-lite playbook persistence — playbooks, runs, outbound endpoints."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from black_onyx.net.safe_url import validate_public_https_url

logger = logging.getLogger(__name__)

VALID_TRIGGER_TYPES = {"watchlist_alert", "webhook_event", "manual"}
VALID_STEP_TYPES = {"enrich", "create_case", "notify_webhook", "generate_sigma", "wait_approval"}

# Matched by name, not a dedicated flag column — this is the only playbook the
# "auto-enrich on watchlist match" settings toggle manages, and identifying it
# by name keeps the schema untouched and the toggle idempotent across restarts.
AUTO_ENRICH_PLAYBOOK_NAME = "Auto-enrich on watchlist match"


class PlaybookManager:
    """SQLite-backed playbook definitions, run history, and outbound endpoints."""

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "playbooks.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS playbooks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                trigger_type TEXT NOT NULL,
                steps_json TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                playbook_id TEXT NOT NULL,
                status TEXT NOT NULL,
                context_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                finished_at TIMESTAMP,
                FOREIGN KEY (playbook_id) REFERENCES playbooks(id)
            );
            CREATE TABLE IF NOT EXISTS run_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                step_index INTEGER NOT NULL,
                step_type TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT,
                FOREIGN KEY (run_id) REFERENCES runs(run_id)
            );
            CREATE TABLE IF NOT EXISTS outbound_endpoints (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            """
        )
        self._conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_playbook(
        self,
        name: str,
        trigger_type: str,
        steps: list[dict[str, Any]],
        enabled: bool = True,
    ) -> dict[str, Any]:
        if trigger_type not in VALID_TRIGGER_TYPES:
            raise ValueError(f"Invalid trigger_type: {trigger_type}")
        if not steps:
            raise ValueError("Playbook requires at least one step")
        for step in steps:
            step_type = str(step.get("type") or "")
            if step_type not in VALID_STEP_TYPES:
                raise ValueError(f"Invalid step type: {step_type}")
        playbook_id = str(uuid.uuid4())
        now = self._now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO playbooks (id, name, trigger_type, steps_json, enabled, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    playbook_id,
                    name.strip(),
                    trigger_type,
                    json.dumps(steps),
                    1 if enabled else 0,
                    now,
                ),
            )
            self._conn.commit()
        return self.get_playbook(playbook_id)  # type: ignore[return-value]

    def list_playbooks(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM playbooks ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_playbook(r) for r in rows]

    def get_playbook(self, playbook_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM playbooks WHERE id = ?", (playbook_id,),
        ).fetchone()
        if not row:
            return None
        return self._row_to_playbook(row)

    def list_enabled_by_trigger(self, trigger_type: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM playbooks WHERE enabled = 1 AND trigger_type = ? ORDER BY created_at",
            (trigger_type,),
        ).fetchall()
        return [self._row_to_playbook(r) for r in rows]

    def ensure_default_watchlist_enrich_playbook(self, enabled: bool) -> dict[str, Any]:
        """Create-if-absent, then set enabled/disabled, the seeded playbook that
        makes "auto-enrich on watchlist match" a reality: a single `enrich` step
        on the `watchlist_alert` trigger. Toggling the settings switch off
        disables rather than deletes it, so any analyst edits to its steps
        survive being turned back on.
        """
        existing = next(
            (p for p in self.list_playbooks()
             if p["name"] == AUTO_ENRICH_PLAYBOOK_NAME and p["trigger_type"] == "watchlist_alert"),
            None,
        )
        if existing is None:
            existing = self.create_playbook(
                name=AUTO_ENRICH_PLAYBOOK_NAME,
                trigger_type="watchlist_alert",
                steps=[{"type": "enrich"}],
                enabled=enabled,
            )
        self.set_enabled(existing["id"], enabled)
        return self.get_playbook(existing["id"])  # type: ignore[return-value]

    def set_enabled(self, playbook_id: str, enabled: bool) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE playbooks SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, playbook_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def delete_playbook(self, playbook_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def update_playbook(
        self,
        playbook_id: str,
        name: str | None = None,
        trigger_type: str | None = None,
        steps: list[dict[str, Any]] | None = None,
        enabled: bool | None = None,
    ) -> dict[str, Any] | None:
        existing = self.get_playbook(playbook_id)
        if existing is None:
            return None
        if trigger_type is not None and trigger_type not in VALID_TRIGGER_TYPES:
            raise ValueError(f"Invalid trigger_type: {trigger_type}")
        if steps is not None:
            if not steps:
                raise ValueError("Playbook requires at least one step")
            for step in steps:
                step_type = str(step.get("type") or "")
                if step_type not in VALID_STEP_TYPES:
                    raise ValueError(f"Invalid step type: {step_type}")
        with self._lock:
            if name is not None:
                self._conn.execute(
                    "UPDATE playbooks SET name = ? WHERE id = ?",
                    (name.strip(), playbook_id),
                )
            if trigger_type is not None:
                self._conn.execute(
                    "UPDATE playbooks SET trigger_type = ? WHERE id = ?",
                    (trigger_type, playbook_id),
                )
            if steps is not None:
                self._conn.execute(
                    "UPDATE playbooks SET steps_json = ? WHERE id = ?",
                    (json.dumps(steps), playbook_id),
                )
            if enabled is not None:
                self._conn.execute(
                    "UPDATE playbooks SET enabled = ? WHERE id = ?",
                    (1 if enabled else 0, playbook_id),
                )
            self._conn.commit()
        return self.get_playbook(playbook_id)

    @staticmethod
    def _row_to_playbook(row: sqlite3.Row) -> dict[str, Any]:
        try:
            steps = json.loads(row["steps_json"] or "[]")
        except json.JSONDecodeError:
            steps = []
        return {
            "id": row["id"],
            "name": row["name"],
            "trigger_type": row["trigger_type"],
            "steps": steps if isinstance(steps, list) else [],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
        }

    def create_endpoint(self, name: str, url: str, enabled: bool = True) -> dict[str, Any]:
        validated = validate_public_https_url(url, purpose="Outbound endpoint URL")
        endpoint_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO outbound_endpoints (id, name, url, enabled) VALUES (?, ?, ?, ?)",
                (endpoint_id, name.strip(), validated, 1 if enabled else 0),
            )
            self._conn.commit()
        return {
            "id": endpoint_id,
            "name": name.strip(),
            "url": validated,
            "enabled": enabled,
        }

    def list_endpoints(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM outbound_endpoints ORDER BY name"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "url": r["url"],
                "enabled": bool(r["enabled"]),
            }
            for r in rows
        ]

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM outbound_endpoints WHERE id = ?", (endpoint_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "name": row["name"],
            "url": row["url"],
            "enabled": bool(row["enabled"]),
        }

    def delete_endpoint(self, endpoint_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM outbound_endpoints WHERE id = ?", (endpoint_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def set_endpoint_enabled(self, endpoint_id: str, enabled: bool) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE outbound_endpoints SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, endpoint_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def start_run(self, playbook_id: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        playbook = self.get_playbook(playbook_id)
        if playbook is None:
            raise ValueError("Playbook not found")
        run_id = str(uuid.uuid4())
        now = self._now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO runs (run_id, playbook_id, status, context_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (run_id, playbook_id, "running", json.dumps(context or {}), now),
            )
            self._conn.commit()
        return self.get_run(run_id)  # type: ignore[return-value]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,),
        ).fetchone()
        if not row:
            return None
        try:
            context = json.loads(row["context_json"] or "{}")
        except json.JSONDecodeError:
            context = {}
        steps = self._conn.execute(
            "SELECT step_index, step_type, status, result_json FROM run_steps "
            "WHERE run_id = ? ORDER BY step_index",
            (run_id,),
        ).fetchall()
        step_rows = []
        for s in steps:
            try:
                result = json.loads(s["result_json"]) if s["result_json"] else None
            except json.JSONDecodeError:
                result = None
            step_rows.append({
                "step_index": s["step_index"],
                "step_type": s["step_type"],
                "status": s["status"],
                "result": result,
            })
        return {
            "run_id": row["run_id"],
            "playbook_id": row["playbook_id"],
            "status": row["status"],
            "context": context if isinstance(context, dict) else {},
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "steps": step_rows,
        }

    def list_runs(self, limit: int = 50, playbook_id: str | None = None) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        if playbook_id:
            rows = self._conn.execute(
                "SELECT run_id FROM runs WHERE playbook_id = ? ORDER BY created_at DESC LIMIT ?",
                (playbook_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT run_id FROM runs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        results = []
        for row in rows:
            run = self.get_run(row["run_id"])
            if run:
                results.append(run)
        return results

    def analytics(self, since_iso: str | None = None) -> dict[str, Any]:
        """Aggregate run success, duration, and approval-wait metrics."""
        from datetime import datetime

        def _parse(ts: Any) -> datetime | None:
            if not ts:
                return None
            try:
                return datetime.fromisoformat(str(ts).replace("Z", "+00:00").replace("+00:00", ""))
            except ValueError:
                return None

        if since_iso:
            rows = self._conn.execute(
                "SELECT run_id, status, created_at, finished_at FROM runs "
                "WHERE created_at >= ? ORDER BY created_at DESC LIMIT 2000",
                (since_iso,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT run_id, status, created_at, finished_at FROM runs "
                "ORDER BY created_at DESC LIMIT 2000",
            ).fetchall()

        total = len(rows)
        completed = [r for r in rows if r["status"] == "completed"]
        failed = [r for r in rows if r["status"] == "failed"]
        waiting = [r for r in rows if r["status"] == "waiting_approval"]
        durations: list[float] = []
        for row in completed:
            start = _parse(row["created_at"])
            end = _parse(row["finished_at"])
            if start and end and end >= start:
                durations.append((end - start).total_seconds())

        approval_waits: list[float] = []
        for row in rows:
            steps = self._conn.execute(
                "SELECT step_type, status, result_json FROM run_steps WHERE run_id = ?",
                (row["run_id"],),
            ).fetchall()
            for step in steps:
                if step["step_type"] != "wait_approval":
                    continue
                # Approximate wait as time from run start to finish when approval was involved
                start = _parse(row["created_at"])
                end = _parse(row["finished_at"]) or datetime.now()
                if start and end >= start and row["status"] in ("completed", "failed", "waiting_approval"):
                    approval_waits.append((end - start).total_seconds())
                    break

        success_rate = (len(completed) / total) if total else None
        avg_duration = (sum(durations) / len(durations)) if durations else None
        avg_approval_wait = (sum(approval_waits) / len(approval_waits)) if approval_waits else None
        return {
            "n": total,
            "completed": len(completed),
            "failed": len(failed),
            "waiting_approval": len(waiting),
            "success_rate": success_rate,
            "avg_duration_seconds": avg_duration,
            "avg_approval_wait_seconds": avg_approval_wait,
            "playbook_success_rate": success_rate,
            "playbook_n": total,
        }

    def set_run_status(self, run_id: str, status: str, finished: bool = False) -> None:
        finished_at = self._now() if finished else None
        with self._lock:
            if finished_at:
                self._conn.execute(
                    "UPDATE runs SET status = ?, finished_at = ? WHERE run_id = ?",
                    (status, finished_at, run_id),
                )
            else:
                self._conn.execute(
                    "UPDATE runs SET status = ? WHERE run_id = ?",
                    (status, run_id),
                )
            self._conn.commit()

    def update_run_context(self, run_id: str, context: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runs SET context_json = ? WHERE run_id = ?",
                (json.dumps(context), run_id),
            )
            self._conn.commit()

    def record_step(
        self,
        run_id: str,
        step_index: int,
        step_type: str,
        status: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM run_steps WHERE run_id = ? AND step_index = ?",
                (run_id, step_index),
            ).fetchone()
            payload = json.dumps(result) if result is not None else None
            if existing:
                self._conn.execute(
                    "UPDATE run_steps SET status = ?, result_json = ?, step_type = ? WHERE id = ?",
                    (status, payload, step_type, existing["id"]),
                )
            else:
                self._conn.execute(
                    "INSERT INTO run_steps (run_id, step_index, step_type, status, result_json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (run_id, step_index, step_type, status, payload),
                )
            self._conn.commit()

    def approve_run(self, run_id: str) -> dict[str, Any] | None:
        run = self.get_run(run_id)
        if run is None:
            return None
        if run["status"] != "waiting_approval":
            raise ValueError("Run is not waiting for approval")
        self.set_run_status(run_id, "running", finished=False)
        return self.get_run(run_id)

    def next_step_index(self, run_id: str) -> int:
        row = self._conn.execute(
            "SELECT MAX(step_index) AS m FROM run_steps WHERE run_id = ? AND status = 'completed'",
            (run_id,),
        ).fetchone()
        if row is None or row["m"] is None:
            return 0
        return int(row["m"]) + 1

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
