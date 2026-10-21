"""Sandbox safe IO sanitized input/output helpers.

Merged from model-tools/sandbox/safe_io.py. Provides functions to sanitize
file paths, limit output size, and strip ANSI escape sequences from tool
output before it's returned to the agent or logged.
"""

from __future__ import annotations

import re
from pathlib import Path

# ANSI escape sequence pattern
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Control character pattern (except newline, tab, carriage return)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

MAX_OUTPUT_CHARS = 50_000


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return _ANSI_ESCAPE.sub("", text or "")


def strip_control_chars(text: str) -> str:
    """Remove non-printable control characters (preserves \\n, \\t, \\r)."""
    return _CONTROL_CHARS.sub("", text or "")


def sanitize_output(text: str, *, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    """Sanitize tool output: strip ANSI, control chars, and truncate."""
    result = strip_ansi(text)
    result = strip_control_chars(result)
    if len(result) > max_chars:
        result = result[:max_chars] + "\n...[truncated]"
    return result


def sanitize_filename(name: str) -> str:
    """Sanitize a filename to prevent path traversal and invalid characters."""
    # Remove path separators and parent references
    name = name.replace("/", "_").replace("\\", "_").replace("..", "_")
    # Remove null bytes
    name = name.replace("\x00", "")
    # Limit length
    if len(name) > 255:
        name = name[:255]
    return name or "unnamed"


def safe_join(base: Path, *parts: str) -> Path:
    """Safely join path parts to a base directory, preventing traversal."""
    joined = base
    for part in parts:
        if not part or part in (".", ".."):
            continue
        part = part.replace("\\", "/")
        for component in part.split("/"):
            if component and component not in (".", ".."):
                joined = joined / component
    return joined.resolve()


def truncate_lines(text: str, max_lines: int = 500) -> str:
    """Truncate text to a maximum number of lines."""
    lines = (text or "").splitlines()
    if len(lines) <= max_lines:
        return text or ""
    return "\n".join(lines[:max_lines]) + f"\n...[{len(lines) - max_lines} more lines truncated]"


def redact_secrets_in_output(text: str) -> str:
    """Redact common secret patterns from tool output."""
    from black_onyx_sandbox.security import redact_command_for_audit
    return redact_command_for_audit(text or "")
