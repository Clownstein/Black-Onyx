"""SSRF-safe URL validation for outbound HTTPS integrations."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def validate_public_https_url(url: str, *, purpose: str = "URL") -> str:
    """Require HTTPS with a hostname that resolves only to public addresses.

    Rejects credentials/fragments in the URL, non-HTTPS schemes, unresolved
    hosts, and any address that is not globally routable (loopback, RFC1918,
    link-local, metadata, etc.).
    """
    cleaned = (url or "").strip()
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"{purpose} must use HTTPS with a hostname")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError(f"{purpose} must not include credentials or fragments")
    hostname = parsed.hostname.casefold()
    port = parsed.port or 443
    try:
        infos = socket.getaddrinfo(hostname, port)
    except socket.gaierror as exc:
        raise ValueError(f"{purpose} hostname did not resolve: {hostname}") from exc
    saw_address = False
    for info in infos:
        address = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        saw_address = True
        if not ip.is_global:
            raise ValueError(f"{purpose} hostname resolves to a non-public address")
    if not saw_address:
        raise ValueError(f"{purpose} hostname did not resolve: {hostname}")
    return cleaned.rstrip("/")
