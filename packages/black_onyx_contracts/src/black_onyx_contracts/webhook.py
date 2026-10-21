"""Webhook HMAC signature helpers shared by notifications and security tests."""

from __future__ import annotations

import hashlib
import hmac
import time


def sign_payload(secret: str, body: bytes, *, timestamp: int | None = None) -> str:
    ts = int(time.time()) if timestamp is None else timestamp
    message = f"{ts}.".encode() + body
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"t={ts},v1={digest}"


def verify_signature(secret: str, body: bytes, header: str, *, max_skew_seconds: int = 300) -> bool:
    parts = dict(item.split("=", 1) for item in header.split(",") if "=" in item)
    if "t" not in parts or "v1" not in parts:
        return False
    try:
        ts = int(parts["t"])
    except ValueError:
        return False
    if abs(int(time.time()) - ts) > max_skew_seconds:
        return False
    expected = sign_payload(secret, body, timestamp=ts)
    return hmac.compare_digest(expected, f"t={ts},v1={parts['v1']}")
