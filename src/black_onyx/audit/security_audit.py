"""Security tooling audit JSONL with secret redaction.

Merged from model-tools/gateway/audit.py. Forwards security tooling events
to a JSONL audit log with redaction of secrets, PEM blocks, API keys, and
long hex strings. Thread-safe writes with rotation.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Keys whose values are always redacted regardless of content
_SECRET_KEY_PATTERN = re.compile(
    r"(?i)(credential|api_key|apikey|private_key|authorization|password|passwd|"
    r"secret|token|bearer|rpc_url|apiToken)"
)

# Content patterns to redact from values
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.DOTALL)
_SK_TOKEN = re.compile(r"sk-[A-Za-z0-9]{20,}")
_HEX_STRING = re.compile(r"\b[a-fA-F0-9]{64,}\b")
_COMMAND_SECRET = re.compile(
    r"(--(?:private-key|password|pass|pwd|secret|token)[=\s]\S+)", re.IGNORECASE
)

_REDACT_VALUE_PATTERNS = (_PEM_BLOCK, _SK_TOKEN, _HEX_STRING, _COMMAND_SECRET)

# Rotation threshold (10 MiB → .1)
_MAX_LOG_BYTES = 10 * 1024 * 1024


def redact(value: Any, max_chars: int = 4096) -> Any:
    """Recursively redact secrets from a value before audit logging."""
    if isinstance(value, str):
        s = value[:max_chars]
        for pattern in _REDACT_VALUE_PATTERNS:
            s = pattern.sub("[REDACTED]", s)
        return s
    if isinstance(value, dict):
        return {
            k: "[REDACTED]" if _SECRET_KEY_PATTERN.search(k) else redact(v, max_chars)
            for k, v in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [redact(v, max_chars) for v in value[:100]]
    return value


class SecurityAuditLogger:
    """JSONL audit logger for security tooling events.

    Events are written one per line with:
      - timestamp (unix epoch)
      - event type
      - request_id (UUID hex)
      - redacted payload fields

    Rotation: when the log exceeds _MAX_LOG_BYTES, it is renamed to .1
    (overwriting any previous .1).
    """

    def __init__(self, path: str | None = None) -> None:
        self._path = Path(
            path or os.environ.get("SECURITY_AUDIT_LOG_PATH", ".checkpoints/security_audit.jsonl")
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, event_type: str, **fields: Any) -> None:
        """Write one audit event. Never raises audit failures are logged."""
        entry = {
            "timestamp": time.time(),
            "event": event_type,
            "request_id": fields.pop("request_id", None) or uuid.uuid4().hex,
            **redact(fields),
        }
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        try:
            with self._lock:
                self._rotate_if_needed()
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except OSError:
            logger.exception("Security audit write failed (path=%s)", self._path)

    def _rotate_if_needed(self) -> None:
        """Rotate the log to .1 when it exceeds the size threshold."""
        try:
            if self._path.exists() and self._path.stat().st_size > _MAX_LOG_BYTES:
                rotated = self._path.with_suffix(".jsonl.1")
                rotated.unlink(missing_ok=True)
                self._path.rename(rotated)
        except OSError:
            logger.exception("Security audit rotation failed")

    # ── Convenience methods for common event types ─────────────────

    def log_tool_call(
        self, tool: str, args: dict[str, Any], principal: str, **extra: Any
    ) -> None:
        self.log("security.tool.call", tool=tool, args=args, principal=principal, **extra)

    def log_tool_result(
        self, tool: str, status: str, duration_s: float, **extra: Any
    ) -> None:
        self.log("security.tool.result", tool=tool, status=status, duration_s=round(duration_s, 3), **extra)

    def log_denial(self, tool: str, reason: str, principal: str) -> None:
        self.log("security.tool.denied", tool=tool, reason=reason, principal=principal)

    def log_agent_run(
        self, message_preview: str, rounds: int, principal: str, **extra: Any
    ) -> None:
        self.log(
            "security.agent.run",
            message_preview=message_preview[:200],
            rounds=rounds,
            principal=principal,
            **extra,
        )
