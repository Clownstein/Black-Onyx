"""Lightweight asset CMDB — hosts/apps with posture findings, SQLite-backed."""

from __future__ import annotations

import csv
import io
import logging
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AssetManager:
    """Persists assets, case links, and posture findings under persist_dir."""

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "assets.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                hostname TEXT,
                ip_address TEXT,
                asset_type TEXT DEFAULT 'host',
                owner TEXT,
                criticality TEXT DEFAULT 'medium',
                tags TEXT DEFAULT '[]',
                notes TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS asset_case_links (
                asset_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (asset_id, case_id),
                FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
            );
            CREATE TABLE IF NOT EXISTS posture_findings (
                finding_id TEXT PRIMARY KEY,
                asset_id TEXT,
                title TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                category TEXT DEFAULT 'misconfiguration',
                description TEXT DEFAULT '',
                source TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
            );
            CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
            CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON posture_findings(status);
        """)
        self._conn.commit()

    def create_asset(
        self,
        hostname: str = "",
        ip_address: str = "",
        asset_type: str = "host",
        owner: str = "",
        criticality: str = "medium",
        tags: list[str] | None = None,
        notes: str = "",
        asset_id: str | None = None,
    ) -> dict[str, Any]:
        import json
        asset_id = (asset_id or "").strip() or str(uuid.uuid4())
        now = datetime.now().isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO assets (asset_id, hostname, ip_address, asset_type, owner, "
                "criticality, tags, notes, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    asset_id, hostname, ip_address, asset_type, owner, criticality,
                    json.dumps(tags or []), notes, now, now,
                ),
            )
            self._conn.commit()
        return self.get_asset(asset_id)  # type: ignore[return-value]

    def find_by_hostname_or_ip(self, hostname: str = "", ip_address: str = "") -> dict[str, Any] | None:
        hostname = (hostname or "").strip()
        ip_address = (ip_address or "").strip()
        if hostname:
            row = self._conn.execute(
                "SELECT asset_id FROM assets WHERE lower(hostname) = lower(?) LIMIT 1",
                (hostname,),
            ).fetchone()
            if row:
                return self.get_asset(row["asset_id"])
        if ip_address:
            row = self._conn.execute(
                "SELECT asset_id FROM assets WHERE ip_address = ? LIMIT 1",
                (ip_address,),
            ).fetchone()
            if row:
                return self.get_asset(row["asset_id"])
        return None

    def upsert_from_sighting(
        self,
        *,
        hostname: str = "",
        ip_address: str = "",
        username: str = "",
        source: str = "",
    ) -> dict[str, Any] | None:
        """Create or refresh an asset from connector host/user/IP signals."""
        hostname = (hostname or "").strip()
        ip_address = (ip_address or "").strip()
        username = (username or "").strip()
        if not hostname and not ip_address and not username:
            return None
        existing = self.find_by_hostname_or_ip(hostname=hostname, ip_address=ip_address)
        tags = [t for t in [source, f"user:{username}" if username else ""] if t]
        if existing:
            updates: dict[str, Any] = {}
            if hostname and not existing.get("hostname"):
                updates["hostname"] = hostname
            if ip_address and not existing.get("ip_address"):
                updates["ip_address"] = ip_address
            merged_tags = list(dict.fromkeys([*(existing.get("tags") or []), *tags]))
            if merged_tags != (existing.get("tags") or []):
                updates["tags"] = merged_tags
            if updates:
                return self.update_asset(existing["asset_id"], **updates)
            # Touch updated_at so recently seen assets float in inventory
            return self.update_asset(existing["asset_id"], notes=existing.get("notes") or "")
        asset_type = "identity" if (username and not hostname and not ip_address) else "host"
        return self.create_asset(
            hostname=hostname or (f"user:{username}" if username else ""),
            ip_address=ip_address,
            asset_type=asset_type,
            owner=username,
            criticality="medium",
            tags=tags,
            notes=f"Auto-upserted from {source}" if source else "Auto-upserted from connector",
        )

    def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        import json
        row = self._conn.execute(
            "SELECT * FROM assets WHERE asset_id = ?", (asset_id,),
        ).fetchone()
        if not row:
            return None
        data = dict(row)
        try:
            data["tags"] = json.loads(data.get("tags") or "[]")
        except (TypeError, json.JSONDecodeError):
            data["tags"] = []
        return data

    def list_assets(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM assets ORDER BY updated_at DESC LIMIT ?", (limit,),
        ).fetchall()
        return [self.get_asset(r["asset_id"]) for r in rows]  # type: ignore[misc]

    def update_asset(self, asset_id: str, **kwargs: Any) -> dict[str, Any] | None:
        import json
        allowed = {
            "hostname", "ip_address", "asset_type", "owner",
            "criticality", "tags", "notes",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return self.get_asset(asset_id)
        if "tags" in updates and isinstance(updates["tags"], list):
            updates["tags"] = json.dumps(updates["tags"])
        sets = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values())
        values.extend([datetime.now().isoformat(), asset_id])
        with self._lock:
            self._conn.execute(
                f"UPDATE assets SET {sets}, updated_at = ? WHERE asset_id = ?",
                values,
            )
            self._conn.commit()
        return self.get_asset(asset_id)

    def delete_asset(self, asset_id: str) -> bool:
        with self._lock:
            self._conn.execute("DELETE FROM asset_case_links WHERE asset_id = ?", (asset_id,))
            self._conn.execute("DELETE FROM posture_findings WHERE asset_id = ?", (asset_id,))
            cur = self._conn.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def link_to_case(self, asset_id: str, case_id: str) -> None:
        if not self.get_asset(asset_id):
            raise KeyError(f"Asset not found: {asset_id}")
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO asset_case_links (asset_id, case_id) VALUES (?, ?)",
                (asset_id, case_id),
            )
            self._conn.commit()

    def unlink_from_case(self, asset_id: str, case_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM asset_case_links WHERE asset_id = ? AND case_id = ?",
                (asset_id, case_id),
            )
            self._conn.commit()

    def list_case_links(self, asset_id: str | None = None, case_id: str | None = None) -> list[dict]:
        if asset_id:
            rows = self._conn.execute(
                "SELECT * FROM asset_case_links WHERE asset_id = ?", (asset_id,),
            ).fetchall()
        elif case_id:
            rows = self._conn.execute(
                "SELECT * FROM asset_case_links WHERE case_id = ?", (case_id,),
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM asset_case_links").fetchall()
        return [dict(r) for r in rows]

    def import_csv(self, csv_text: str) -> dict[str, Any]:
        """Import assets from CSV with headers hostname,ip_address,asset_type,owner,criticality."""
        reader = csv.DictReader(io.StringIO(csv_text))
        created = 0
        skipped = 0
        errors: list[str] = []
        for i, row in enumerate(reader, start=1):
            hostname = (row.get("hostname") or row.get("host") or "").strip()
            ip_address = (row.get("ip_address") or row.get("ip") or "").strip()
            if not hostname and not ip_address:
                skipped += 1
                errors.append(f"row {i}: missing hostname and ip")
                continue
            try:
                self.create_asset(
                    hostname=hostname,
                    ip_address=ip_address,
                    asset_type=(row.get("asset_type") or "host").strip(),
                    owner=(row.get("owner") or "").strip(),
                    criticality=(row.get("criticality") or "medium").strip(),
                    tags=[t.strip() for t in (row.get("tags") or "").split(",") if t.strip()],
                    notes=(row.get("notes") or "").strip(),
                )
                created += 1
            except Exception as exc:
                skipped += 1
                errors.append(f"row {i}: {exc}")
        return {"created": created, "skipped": skipped, "errors": errors[:50]}

    def create_finding(
        self,
        title: str,
        asset_id: str | None = None,
        severity: str = "medium",
        status: str = "open",
        category: str = "misconfiguration",
        description: str = "",
        source: str = "",
    ) -> dict[str, Any]:
        finding_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO posture_findings (finding_id, asset_id, title, severity, status, "
                "category, description, source, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id, asset_id, title, severity, status,
                    category, description, source, now, now,
                ),
            )
            self._conn.commit()
        return self.get_finding(finding_id)  # type: ignore[return-value]

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM posture_findings WHERE finding_id = ?", (finding_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_findings(
        self,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT * FROM posture_findings {where} ORDER BY updated_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def update_finding(self, finding_id: str, **kwargs: Any) -> dict[str, Any] | None:
        allowed = {"title", "severity", "status", "category", "description", "source", "asset_id"}
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return self.get_finding(finding_id)
        sets = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values())
        values.extend([datetime.now().isoformat(), finding_id])
        with self._lock:
            self._conn.execute(
                f"UPDATE posture_findings SET {sets}, updated_at = ? WHERE finding_id = ?",
                values,
            )
            self._conn.commit()
        return self.get_finding(finding_id)

    def posture_board(self) -> dict[str, Any]:
        """Aggregate open findings by severity/status for a board view."""
        by_severity = self._conn.execute("""
            SELECT severity, COUNT(*) as count FROM posture_findings
            WHERE status = 'open' GROUP BY severity
        """).fetchall()
        by_status = self._conn.execute("""
            SELECT status, COUNT(*) as count FROM posture_findings GROUP BY status
        """).fetchall()
        by_category = self._conn.execute("""
            SELECT category, COUNT(*) as count FROM posture_findings
            WHERE status = 'open' GROUP BY category
        """).fetchall()
        open_findings = self.list_findings(status="open", limit=100)
        return {
            "by_severity": {r["severity"]: r["count"] for r in by_severity},
            "by_status": {r["status"]: r["count"] for r in by_status},
            "by_category": {r["category"]: r["count"] for r in by_category},
            "open_findings": open_findings,
            "n": len(open_findings),
        }

    def all_assets_raw(self, limit: int = 10_000) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM assets ORDER BY updated_at DESC LIMIT ?", (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        if self._conn:
            self._conn.close()
