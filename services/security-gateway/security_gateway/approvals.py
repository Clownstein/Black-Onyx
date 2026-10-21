"""Durable, single-use approvals and paused agent runs for security tools.

State lives in one SQLite database (``SECURITY_APPROVAL_DB``) whose schema is
versioned through ``schema_migrations``; migrations are forward-only and run
under an immediate transaction so concurrent gateway workers apply them once.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from security_gateway.db import _postgres_url, gateway_connection

POLICY_VERSION = 2
APPROVAL_TTL_SECONDS = 300
AGENT_RUN_TTL_SECONDS = 3600

_MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, """CREATE TABLE IF NOT EXISTS approvals (
        approval_id TEXT PRIMARY KEY,
        principal TEXT NOT NULL,
        tool TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        policy_version INTEGER NOT NULL,
        approved_by TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
    )"""),
    (2, """CREATE TABLE IF NOT EXISTS agent_runs (
        run_id TEXT PRIMARY KEY,
        principal TEXT NOT NULL,
        status TEXT NOT NULL,
        state TEXT NOT NULL,
        pending_tool TEXT,
        pending_digest TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    )"""),
    (3, "CREATE INDEX IF NOT EXISTS ix_approvals_expires ON approvals(expires_at)"),
    (4, "CREATE INDEX IF NOT EXISTS ix_agent_runs_principal ON agent_runs(principal, status)"),
)
SCHEMA_VERSION = _MIGRATIONS[-1][0]


def request_digest(principal: str, tool: str, body: dict[str, Any]) -> str:
    bound = {
        "policy_version": POLICY_VERSION,
        "principal": principal,
        "tool": tool,
        "arguments": body.get("arguments", {}),
        "session_id": body.get("session_id", "default"),
        "network_profile": body.get("network_profile", "offline"),
        "destinations": body.get("destinations", []),
        "ports": body.get("ports", []),
        "lab_profile_id": body.get("lab_profile_id"),
        "resolved_targets": body.get("resolved_targets", {}),
        "timeout": body.get("timeout", 30),
    }
    encoded = json.dumps(bound, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    key = os.environ.get("SECURITY_GATEWAY_KEY", "").encode()
    if len(key) < 32:
        raise RuntimeError("SECURITY_GATEWAY_KEY is required to sign request previews")
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def migrate(connection: sqlite3.Connection) -> int:
    """Apply pending schema migrations; returns the resulting version."""
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)"
    )
    connection.execute("BEGIN IMMEDIATE")
    try:
        applied = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
        for version, statement in _MIGRATIONS:
            if version in applied:
                continue
            connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, int(time.time())),
            )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    current = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    if current is None or current > SCHEMA_VERSION:
        raise RuntimeError("Security approval store schema is newer than this gateway")
    return int(current)


@contextmanager
def _database():
    with gateway_connection() as db:
        if not _postgres_url():
            migrate(db)
        yield db


def approve(principal: str, tool: str, body: dict[str, Any], approver: str) -> str:
    approval_id = secrets.token_urlsafe(24)
    with _database() as db:
        db.execute(
            "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
            (approval_id, principal, tool, request_digest(principal, tool, body),
             POLICY_VERSION, approver, int(time.time()) + APPROVAL_TTL_SECONDS),
        )
        db.execute("DELETE FROM approvals WHERE expires_at < ?", (int(time.time()) - 86400,))
    return approval_id


def consume(approval_id: str, principal: str, tool: str, body: dict[str, Any]) -> bool:
    if not isinstance(approval_id, str) or not approval_id or len(approval_id) > 128:
        return False
    with _database() as db:
        cursor = db.execute(
            """UPDATE approvals SET used_at=? WHERE approval_id=? AND principal=?
               AND tool=? AND request_digest=? AND policy_version=?
               AND expires_at>? AND used_at IS NULL""",
            (int(time.time()), approval_id, principal, tool,
             request_digest(principal, tool, body), POLICY_VERSION, int(time.time())),
        )
        return cursor.rowcount == 1


# ── Paused agent runs ───────────────────────────────────────────────────


def save_agent_run(
    principal: str, state: dict[str, Any], pending_tool: str, pending_digest: str,
    run_id: str | None = None,
) -> str:
    """Persist a run paused on a tool that needs approval."""
    now = int(time.time())
    run_id = run_id or secrets.token_urlsafe(18)
    encoded = json.dumps(state, separators=(",", ":"))
    with _database() as db:
        db.execute(
            """INSERT INTO agent_runs(run_id, principal, status, state, pending_tool,
                   pending_digest, created_at, updated_at, expires_at)
               VALUES (?, ?, 'pending_approval', ?, ?, ?, ?, ?, ?)
               ON CONFLICT(run_id) DO UPDATE SET status='pending_approval', state=excluded.state,
                   pending_tool=excluded.pending_tool, pending_digest=excluded.pending_digest,
                   updated_at=excluded.updated_at, expires_at=excluded.expires_at
               WHERE agent_runs.principal=excluded.principal""",
            (run_id, principal, encoded, pending_tool, pending_digest, now, now,
             now + AGENT_RUN_TTL_SECONDS),
        )
        db.execute("DELETE FROM agent_runs WHERE expires_at < ?", (now - 86400,))
    return run_id


def claim_agent_run(run_id: str, principal: str) -> dict[str, Any] | None:
    """Atomically move a paused run to ``resuming`` so it resumes only once."""
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        return None
    now = int(time.time())
    with _database() as db:
        cursor = db.execute(
            """UPDATE agent_runs SET status='resuming', updated_at=?
               WHERE run_id=? AND principal=? AND status='pending_approval' AND expires_at>?""",
            (now, run_id, principal, now),
        )
        if cursor.rowcount != 1:
            return None
        row = db.execute(
            "SELECT state, pending_tool, pending_digest FROM agent_runs WHERE run_id=?", (run_id,)
        ).fetchone()
    state = json.loads(row[0])
    state["pending_tool"], state["pending_digest"] = row[1], row[2]
    return state


def finish_agent_run(run_id: str, status: str) -> None:
    with _database() as db:
        db.execute(
            "UPDATE agent_runs SET status=?, state='{}', updated_at=? WHERE run_id=?",
            (status, int(time.time()), run_id),
        )


def get_agent_run(run_id: str, principal: str) -> dict[str, Any] | None:
    with _database() as db:
        row = db.execute(
            """SELECT status, pending_tool, pending_digest, state, created_at, updated_at, expires_at
               FROM agent_runs WHERE run_id=? AND principal=?""",
            (run_id, principal),
        ).fetchone()
    if row is None:
        return None
    status = "expired" if int(row[6]) <= int(time.time()) and row[0] == "pending_approval" else row[0]
    result = {
        "run_id": run_id,
        "status": status,
        "pending_tool": row[1],
        "created_at": row[4],
        "updated_at": row[5],
        "expires_at": row[6],
    }
    if status == "pending_approval":
        try:
            state = json.loads(row[3])
        except (TypeError, json.JSONDecodeError):
            state = {}
        pending = state.get("pending_call") if isinstance(state, dict) else None
        pending = pending if isinstance(pending, dict) else {}
        stored = state.get("pending_request") if isinstance(state, dict) else None
        stored = stored if isinstance(stored, dict) else {}
        result["pending_approval"] = {
            "tool": row[1],
            "tier": __import__("security_gateway.tool_catalog", fromlist=["TOOL_CATALOG"]).TOOL_CATALOG.get(
                row[1], {}
            ).get("tier", "unknown"),
            "arguments": stored.get("arguments", pending.get("arguments", {})),
            "session_id": stored.get(
                "session_id",
                state.get("session_id", "default") if isinstance(state, dict) else "default",
            ),
            "timeout": stored.get("timeout", 30),
            "network_profile": stored.get("network_profile", "offline"),
            "destinations": stored.get("destinations", []),
            "ports": stored.get("ports", []),
            "lab_profile_id": stored.get("lab_profile_id"),
            "resolved_targets": stored.get("resolved_targets", {}),
            "preview_hash": row[2],
            "expires_at": row[6],
        }
    return result
