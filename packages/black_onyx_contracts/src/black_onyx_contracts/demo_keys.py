"""Fail closed when demo/service keys are used without ALLOW_DEMO_KEYS=true."""

from __future__ import annotations

import os
import sys


_DEMO_PREFIXES = ("dev-", "demo-", "changeme", "minioadmin")


def assert_no_demo_keys(*, service: str, keys: dict[str, str]) -> None:
    allow = os.environ.get("ALLOW_DEMO_KEYS", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if allow:
        return
    bad: list[str] = []
    for name, value in keys.items():
        v = (value or "").strip().lower()
        if not v:
            continue
        if any(v.startswith(p) or v == p for p in _DEMO_PREFIXES):
            bad.append(name)
    if bad:
        print(
            f"{service}: refusing to start with demo credentials {bad} "
            f"unless ALLOW_DEMO_KEYS=true",
            file=sys.stderr,
        )
        raise SystemExit(2)
