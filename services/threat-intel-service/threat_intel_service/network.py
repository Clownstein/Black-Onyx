"""SSRF-safe, size-bounded JSON fetching for threat-intel feeds."""

from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx


def validate_public_https_url(value: str, *, resolve_dns: bool = True) -> str:
    if len(value) > 2048:
        raise ValueError("feed URL is too long")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https":
        raise ValueError("feed URL must use HTTPS")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("feed URL must have a host and no embedded credentials")
    if parsed.fragment:
        raise ValueError("feed URL fragments are not allowed")
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise ValueError("feed host is a non-public address")
    if resolve_dns and literal is None:
        try:
            addresses = {
                ipaddress.ip_address(info[4][0])
                for info in socket.getaddrinfo(
                    parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM
                )
            }
        except (OSError, ValueError) as exc:
            raise ValueError("feed host could not be resolved") from exc
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError("feed host resolves to a non-public address")
    return urlunsplit(("https", parsed.netloc, parsed.path or "/", parsed.query, ""))


async def request_json_bounded(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_bytes: int,
    **kwargs: Any,
) -> tuple[Any, httpx.Headers]:
    async with client.stream(method, url, **kwargs) as response:
        response.raise_for_status()
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > max_bytes:
                    raise ValueError("feed response exceeds configured byte limit")
            except ValueError as exc:
                if "exceeds" in str(exc):
                    raise
                raise ValueError("feed response has invalid Content-Length") from exc
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > max_bytes:
                raise ValueError("feed response exceeds configured byte limit")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("feed response is not valid JSON") from exc
        return payload, response.headers
