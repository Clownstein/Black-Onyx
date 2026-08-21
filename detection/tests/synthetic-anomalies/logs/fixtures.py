"""Synthetic auth-sequence fixtures with seeded corruptions."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

NORMAL_AUTH_SEQUENCE: list[dict[str, Any]] = [
    {"template_id": "tpl-auth-success", "severity": "INFO"},
    {"template_id": "tpl-session-create", "severity": "INFO"},
    {"template_id": "tpl-auth-failure", "severity": "WARN"},
    {"template_id": "tpl-session-refresh", "severity": "INFO"},
    {"template_id": "tpl-db-query", "severity": "INFO"},
    {"template_id": "tpl-http-200", "severity": "INFO"},
    {"template_id": "tpl-cache-hit", "severity": "INFO"},
    {"template_id": "tpl-auth-success", "severity": "INFO"},
]


def normal_sequence() -> list[dict[str, Any]]:
    return deepcopy(NORMAL_AUTH_SEQUENCE)


def event_deletion() -> list[dict[str, Any]]:
    seq = normal_sequence()
    del seq[2]  # remove auth-failure
    return seq


def event_insertion() -> list[dict[str, Any]]:
    seq = normal_sequence()
    seq.insert(3, {"template_id": "tpl-shell-exec", "severity": "ERROR"})
    return seq


def event_reorder() -> list[dict[str, Any]]:
    seq = normal_sequence()
    seq[1], seq[5] = seq[5], seq[1]
    return seq


def novel_template() -> list[dict[str, Any]]:
    seq = normal_sequence()
    seq[4] = {"template_id": "tpl-novel-unknown-xyz", "severity": "ERROR"}
    return seq


def privilege_event() -> list[dict[str, Any]]:
    seq = normal_sequence()
    seq[3] = {"template_id": "tpl-privilege-change", "severity": "CRITICAL"}
    return seq


CORRUPTIONS = {
    "deletion": event_deletion,
    "insertion": event_insertion,
    "reorder": event_reorder,
    "novel_template": novel_template,
    "privilege_event": privilege_event,
}
