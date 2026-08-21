"""Mask variable tokens before Drain3 template mining."""

from __future__ import annotations

import re

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"\b:(?:[0-9a-fA-F]{1,4}:){1,7}\b"
)
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
LONG_NUMBER_RE = re.compile(r"\b\d{6,}\b")


def mask_message(message: str) -> str:
    """Replace IPs, UUIDs, emails, and long numbers with typed placeholders."""
    text = IPV4_RE.sub("<IP>", message)
    text = IPV6_RE.sub("<IP>", text)
    text = UUID_RE.sub("<UUID>", text)
    text = EMAIL_RE.sub("<EMAIL>", text)
    text = LONG_NUMBER_RE.sub("<NUM>", text)
    return text
