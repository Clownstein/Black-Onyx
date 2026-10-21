"""Outbound notification URL validation."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def validate_public_https_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned or len(cleaned) > 2048:
        raise ValueError("webhook URL is empty or too long")
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("webhook URL must use HTTPS with a hostname")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("webhook URL must not contain credentials or a fragment")
    hostname = parsed.hostname.casefold()
    port = parsed.port or 443
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("webhook hostname did not resolve") from exc
    addresses = {
        str(info[4][0]).split("%", 1)[0]
        for info in infos
        if info[4]
    }
    if not addresses:
        raise ValueError("webhook hostname did not resolve")
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("webhook hostname resolves to a non-public address")
    return cleaned


def request_public_https_sync(
    client: object,
    method: str,
    url: str,
    *,
    max_bytes: int,
    headers: dict[str, str] | None = None,
    **kwargs: object,
) -> object:
    """Pin a bounded request to the public IP that passed DNS validation.

    The TLS SNI and HTTP Host header remain bound to the original hostname.
    Redirects are rejected for this notification POST so signed payloads and
    delivery credentials cannot move to another origin.
    """
    import httpx

    cleaned = validate_public_https_url(url)
    parsed = urlparse(cleaned)
    hostname = str(parsed.hostname).casefold()
    port = parsed.port or 443
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, ValueError) as exc:
        raise ValueError("webhook hostname did not resolve") from exc
    addresses: list[str] = []
    for info in infos:
        if not info[4]:
            continue
        address = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not ip.is_global:
            raise ValueError("webhook hostname resolves to a non-public address")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("webhook hostname did not resolve")

    address = addresses[0]
    pinned_host = f"[{address}]" if ":" in address else address
    pinned_url = parsed._replace(netloc=f"{pinned_host}:{port}").geturl()
    request_headers = dict(headers or {})
    request_headers["Host"] = hostname if port == 443 else f"{hostname}:{port}"
    with client.stream(  # type: ignore[attr-defined]
        method,
        pinned_url,
        headers=request_headers,
        extensions={"sni_hostname": hostname},
        **kwargs,
    ) as response:
        if response.is_redirect:
            raise ValueError("webhook redirects are not allowed")
        length = response.headers.get("content-length")
        if length and int(length) > max_bytes:
            raise ValueError(f"webhook response exceeds {max_bytes} bytes")
        content = bytearray()
        for chunk in response.iter_bytes():
            content.extend(chunk)
            if len(content) > max_bytes:
                raise ValueError(f"webhook response exceeds {max_bytes} bytes")
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=bytes(content),
            request=httpx.Request(method, cleaned),
        )
