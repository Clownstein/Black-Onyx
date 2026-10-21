"""Escape untrusted log/code fragments before UI rendering."""

from __future__ import annotations

import html


def escape_for_ui(value: str) -> str:
    """HTML-escape user-controlled strings (logs, code snippets, comments)."""
    return html.escape(value, quote=True)


def contains_raw_script_tag(value: str) -> bool:
    lowered = value.lower()
    return "<script" in lowered or "javascript:" in lowered
