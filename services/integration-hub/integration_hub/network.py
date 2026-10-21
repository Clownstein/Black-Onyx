"""Validation for user-selected outbound webhook destinations."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


def validate_public_https_url(value: str, *, resolve_dns: bool = True) -> str:
    if len(value) > 2048:
        raise ValueError("webhook URL is too long")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https":
        raise ValueError("webhook URL must use HTTPS")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("webhook URL must have a host and no embedded credentials")
    if parsed.fragment:
        raise ValueError("webhook URL fragments are not allowed")
    try:
        literal_address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal_address = None
    if literal_address is not None and not literal_address.is_global:
        raise ValueError("webhook host is a non-public address")
    if resolve_dns and literal_address is None:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
                )
            }
        except (OSError, ValueError) as exc:
            raise ValueError("webhook host could not be resolved") from exc
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError("webhook host resolves to a non-public address")
    return urlunsplit(("https", parsed.netloc, parsed.path or "/", parsed.query, ""))
