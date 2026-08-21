"""Store for authored/generated Sigma and YARA detection rules."""

from __future__ import annotations

import io
import logging
import re
import sqlite3
import threading
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

RULE_TYPES = frozenset({"sigma", "yara"})
RULE_STATUSES = frozenset({"draft", "pending_approval", "approved", "rejected", "deprecated"})


class DetectionRulesManager:
    """SQLite persistence for Sigma/YARA rules with basic validation and export."""

    def __init__(self, persist_dir: str | None = None) -> None:
        self._persist_dir = Path(persist_dir) if persist_dir else None
        self._lock = threading.Lock()
        db_path = ":memory:"
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(self._persist_dir / "detection_rules.sqlite")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS detection_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                content TEXT NOT NULL,
                status TEXT DEFAULT 'draft',
                source TEXT DEFAULT 'authored',
                author TEXT DEFAULT '',
                tags TEXT DEFAULT '[]',
                validation_ok INTEGER DEFAULT 0,
                validation_errors TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                submitted_at TIMESTAMP,
                approved_at TIMESTAMP,
                approved_by TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_rules_type ON detection_rules(rule_type);
            CREATE INDEX IF NOT EXISTS idx_rules_status ON detection_rules(status);
        """)
        self._conn.commit()

    @staticmethod
    def validate_rule(rule_type: str, content: str) -> dict[str, Any]:
        """Basic structural checks — does not execute rules locally."""
        errors: list[str] = []
        if rule_type not in RULE_TYPES:
            errors.append(f"Unsupported rule_type '{rule_type}'")
            return {"ok": False, "errors": errors}
        text = (content or "").strip()
        if not text:
            errors.append("Empty rule content")
            return {"ok": False, "errors": errors}

        if rule_type == "sigma":
            try:
                import yaml  # type: ignore[import-untyped]
                data = yaml.safe_load(text)
            except Exception as exc:
                errors.append(f"Invalid YAML: {exc}")
                return {"ok": False, "errors": errors}
            if not isinstance(data, dict):
                errors.append("Sigma rule must be a YAML mapping")
            else:
                for key in ("title", "detection", "logsource"):
                    if key not in data:
                        errors.append(f"Missing required Sigma field: {key}")
                detection = data.get("detection") if isinstance(data, dict) else None
                if isinstance(detection, dict) and "condition" not in detection:
                    errors.append("Sigma detection.condition is required")
        else:  # yara
            if "rule " not in text and not text.lstrip().startswith("rule"):
                errors.append("YARA content must contain a rule declaration")
            if "{" not in text or "}" not in text:
                errors.append("YARA rule must include a body block")
            if "condition:" not in text and "condition :" not in text:
                errors.append("YARA rule should include a condition section")

        return {"ok": len(errors) == 0, "errors": errors}

    def create_rule(
        self,
        name: str,
        rule_type: str,
        content: str,
        *,
        author: str = "",
        source: str = "authored",
        tags: list[str] | None = None,
        status: str = "draft",
    ) -> dict[str, Any]:
        import json
        if rule_type not in RULE_TYPES:
            raise ValueError(f"Invalid rule_type '{rule_type}'")
        if status not in RULE_STATUSES:
            raise ValueError(f"Invalid status '{status}'")
        validation = self.validate_rule(rule_type, content)
        rule_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO detection_rules (rule_id, name, rule_type, content, status, source, "
                "author, tags, validation_ok, validation_errors, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rule_id, name, rule_type, content, status, source, author,
                    json.dumps(tags or []),
                    1 if validation["ok"] else 0,
                    json.dumps(validation["errors"]),
                    now, now,
                ),
            )
            self._conn.commit()
        return self.get_rule(rule_id)  # type: ignore[return-value]

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        import json
        row = self._conn.execute(
            "SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,),
        ).fetchone()
        if not row:
            return None
        data = dict(row)
        for key in ("tags", "validation_errors"):
            try:
                data[key] = json.loads(data.get(key) or "[]")
            except (TypeError, json.JSONDecodeError):
                data[key] = []
        data["validation_ok"] = bool(data.get("validation_ok"))
        return data

    def list_rules(
        self,
        rule_type: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if rule_type:
            clauses.append("rule_type = ?")
            params.append(rule_type)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT rule_id FROM detection_rules {where} ORDER BY updated_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [self.get_rule(r["rule_id"]) for r in rows]  # type: ignore[misc]

    def update_rule(self, rule_id: str, **kwargs: Any) -> dict[str, Any] | None:
        import json
        allowed = {
            "name", "content", "status", "author", "source", "tags",
            "submitted_at", "approved_at", "approved_by",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
        if not updates:
            return self.get_rule(rule_id)
        existing = self.get_rule(rule_id)
        if not existing:
            return None
        if "status" in updates and updates["status"] not in RULE_STATUSES:
            raise ValueError(f"Invalid status '{updates['status']}'")
        if "content" in updates:
            validation = self.validate_rule(existing["rule_type"], updates["content"])
            updates["validation_ok"] = 1 if validation["ok"] else 0
            updates["validation_errors"] = json.dumps(validation["errors"])
        if "tags" in updates and isinstance(updates["tags"], list):
            updates["tags"] = json.dumps(updates["tags"])
        if updates.get("status") == "pending_approval" and "submitted_at" not in updates:
            updates["submitted_at"] = datetime.now().isoformat()
        if updates.get("status") == "approved" and "approved_at" not in updates:
            updates["approved_at"] = datetime.now().isoformat()

        sets = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values())
        values.extend([datetime.now().isoformat(), rule_id])
        with self._lock:
            self._conn.execute(
                f"UPDATE detection_rules SET {sets}, updated_at = ? WHERE rule_id = ?",
                values,
            )
            self._conn.commit()
        return self.get_rule(rule_id)

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM detection_rules WHERE rule_id = ?", (rule_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def export_package(
        self,
        rule_ids: list[str] | None = None,
        status: str | None = "approved",
    ) -> bytes:
        """Export matching rules as a zip of .yml / .yar files."""
        if rule_ids:
            rules = [self.get_rule(rid) for rid in rule_ids]
            rules = [r for r in rules if r]
        else:
            rules = self.list_rules(status=status, limit=5_000)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for rule in rules:
                ext = "yml" if rule["rule_type"] == "sigma" else "yar"
                safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in rule["name"])[:80]
                zf.writestr(f"{safe}_{rule['rule_id'][:8]}.{ext}", rule["content"])
        return buf.getvalue()

    @staticmethod
    def _extract_match_needles(rule_type: str, content: str) -> list[str]:
        """Pull literal strings from Sigma/YARA for evidence dry-run matching."""
        needles: list[str] = []
        text = content or ""
        if rule_type == "yara":
            for match in re.finditer(r'\$\w+\s*=\s*"([^"]+)"', text):
                if match.group(1).strip():
                    needles.append(match.group(1).strip())
            for match in re.finditer(r"\$\w+\s*=\s*'([^']+)'", text):
                if match.group(1).strip():
                    needles.append(match.group(1).strip())
        else:
            try:
                import yaml  # type: ignore[import-untyped]
                data = yaml.safe_load(text)
            except Exception:
                data = None
            if isinstance(data, dict):
                detection = data.get("detection") or {}
                if isinstance(detection, dict):
                    for key, value in detection.items():
                        if key == "condition":
                            continue
                        if isinstance(value, dict):
                            for field_val in value.values():
                                if isinstance(field_val, str) and field_val.strip():
                                    needles.append(field_val.strip())
                                elif isinstance(field_val, list):
                                    needles.extend(str(v).strip() for v in field_val if str(v).strip())
                        elif isinstance(value, str) and value.strip():
                            needles.append(value.strip())
            # Fallback: quoted literals in raw text
            if not needles:
                needles.extend(m.group(1) for m in re.finditer(r'"([^"]{3,120})"', text))
        # Deduplicate, drop very short tokens
        seen: set[str] = set()
        out: list[str] = []
        for needle in needles:
            key = needle.lower()
            if len(needle) < 3 or key in seen:
                continue
            seen.add(key)
            out.append(needle)
        return out[:40]

    def dry_run_against_evidence(
        self,
        rule_id: str,
        qdrant_store: Any,
        *,
        max_collections: int = 20,
        max_points: int = 400,
    ) -> dict[str, Any]:
        """String-match rule literals against already ingested evidence payloads.

        This is an analyst review aid only — not live detection or enforcement.
        """
        rule = self.get_rule(rule_id)
        if not rule:
            raise ValueError("Rule not found")
        needles = self._extract_match_needles(rule["rule_type"], rule["content"])
        if not needles:
            return {
                "rule_id": rule_id,
                "mode": "evidence_dry_run",
                "needles": [],
                "matches": [],
                "n": 0,
                "note": "No literal strings extracted from rule for dry-run matching.",
            }
        matches: list[dict[str, Any]] = []
        try:
            collections = qdrant_store.list_collections() or []
        except Exception:
            collections = []
        for coll in collections[:max_collections]:
            name = coll.get("name") if isinstance(coll, dict) else str(coll)
            if not name:
                continue
            try:
                points, _ = qdrant_store.scroll(
                    name, limit=min(100, max_points), with_payload=True, with_vectors=False,
                )
            except Exception:
                continue
            for point in points or []:
                payload = getattr(point, "payload", None) or {}
                if not isinstance(payload, dict):
                    continue
                blob = " ".join(
                    str(payload.get(k) or "")
                    for k in ("text", "content", "body_text", "title", "source_file", "ocr_text")
                ).lower()
                hit_needles = [n for n in needles if n.lower() in blob]
                if hit_needles:
                    matches.append({
                        "collection": name,
                        "point_id": str(getattr(point, "id", "")),
                        "source_file": payload.get("source_file") or "",
                        "title": payload.get("title") or "",
                        "matched": hit_needles[:8],
                    })
                if len(matches) >= 50:
                    break
            if len(matches) >= 50:
                break
        return {
            "rule_id": rule_id,
            "rule_name": rule.get("name"),
            "rule_type": rule.get("rule_type"),
            "mode": "evidence_dry_run",
            "needles": needles,
            "matches": matches,
            "n": len(matches),
            "note": (
                "Evidence dry-run only — string match against ingested payloads. "
                "Not live detection or enforcement."
            ),
        }

    def analytics(self, since_iso: str | None = None) -> dict[str, Any]:
        """Rule volume and approval latency stats."""
        params: list[Any] = []
        where = ""
        if since_iso:
            where = "WHERE created_at >= ?"
            params.append(since_iso)
        by_type = self._conn.execute(
            f"SELECT rule_type, COUNT(*) as count FROM detection_rules {where} GROUP BY rule_type",
            params,
        ).fetchall()
        by_status = self._conn.execute(
            f"SELECT status, COUNT(*) as count FROM detection_rules {where} GROUP BY status",
            params,
        ).fetchall()
        if since_iso:
            latency_sql = (
                "SELECT submitted_at, approved_at FROM detection_rules "
                "WHERE created_at >= ? AND submitted_at IS NOT NULL AND approved_at IS NOT NULL"
            )
            latency_params: list[Any] = [since_iso]
        else:
            latency_sql = (
                "SELECT submitted_at, approved_at FROM detection_rules "
                "WHERE submitted_at IS NOT NULL AND approved_at IS NOT NULL"
            )
            latency_params = []
        latency_rows = self._conn.execute(latency_sql, latency_params).fetchall()
        latencies_hours: list[float] = []
        for row in latency_rows:
            try:
                submitted = datetime.fromisoformat(str(row["submitted_at"]))
                approved = datetime.fromisoformat(str(row["approved_at"]))
                latencies_hours.append((approved - submitted).total_seconds() / 3600.0)
            except (TypeError, ValueError):
                continue
        avg_latency = sum(latencies_hours) / len(latencies_hours) if latencies_hours else None
        total = sum(r["count"] for r in by_type)
        return {
            "by_type": {r["rule_type"]: r["count"] for r in by_type},
            "by_status": {r["status"]: r["count"] for r in by_status},
            "approval_latency_hours_avg": avg_latency,
            "approval_latency_n": len(latencies_hours),
            "n": total,
        }

    def close(self) -> None:
        if self._conn:
            self._conn.close()
