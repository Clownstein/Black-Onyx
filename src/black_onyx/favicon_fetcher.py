"""Best-effort same-origin favicon fetch-and-cache for user-pinned sites.

Fetches a site's own /favicon.ico (bounded size/time), caches the bytes
under storage.state_dir/favicons/, and serves them from Black Onyx's own
origin — so gallery tiles never need to widen the CSP img-src allowlist to
a third-party favicon CDN.

Unlike "Open site" (which opens in the user's own browser), this fetch is
server-initiated and unauthenticated-to-the-target, on behalf of any
authenticated user including viewers. Sites are expected to include internal
tools the user already has legitimate access to, but the *server* making an
automated outbound request to an arbitrary user-supplied address is a
distinct SSRF risk (e.g. probing internal services or a cloud metadata
endpoint like 169.254.169.254) independent of whether that address happens
to be legitimate for that particular user. So this module refuses to fetch
anything that resolves to a private, loopback, link-local, reserved,
multicast, or unspecified address, and never follows redirects (a redirect
to such an address would otherwise bypass the initial hostname check).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from pathlib import Path
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

MAX_FAVICON_BYTES = 256 * 1024
FETCH_TIMEOUT_SECONDS = 5.0


def _resolves_to_public_address(hostname: str) -> bool:
    """True only if every address `hostname` resolves to is a routable
    public address — never private/loopback/link-local/reserved/multicast/
    unspecified. Fails closed: unresolvable or ambiguous hosts are rejected.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError):
        return False
    if not results:
        return False
    for family, _type, _proto, _canonname, sockaddr in results:
        raw_ip = sockaddr[0]
        if family == socket.AF_INET6:
            raw_ip = raw_ip.split("%", 1)[0]  # strip zone id, e.g. fe80::1%eth0
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            return False
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
        ):
            return False
    return True


def _sniff_extension(data: bytes, content_type: str) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data.startswith((b"\x00\x00\x01\x00", b"\x00\x00\x02\x00")):
        return "ico"
    if content_type.startswith("image/svg") or b"<svg" in data[:512].lower():
        return "svg"
    return None


def fetch_and_cache_favicon(url: str, state_dir: str, site_id: str) -> str | None:
    """Fetch a site's favicon.ico and cache it to disk.

    Returns the relative path (under state_dir) on success, or None if the
    fetch failed, the target resolved to a non-public address, or the
    response did not look like an image. Never raises — a missing favicon
    must never fail site creation.
    """
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if not _resolves_to_public_address(parsed.hostname):
            logger.debug("Refusing favicon fetch for non-public host: %s", parsed.hostname)
            return None
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        with httpx.stream(
            "GET", favicon_url, timeout=FETCH_TIMEOUT_SECONDS,
            follow_redirects=False,  # a redirect could otherwise retarget a private/metadata address
        ) as response:
            if response.status_code != 200:
                return None
            content_type = response.headers.get("content-type", "")
            total = 0
            chunks: list[bytes] = []
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_FAVICON_BYTES:
                    return None
                chunks.append(chunk)
        data = b"".join(chunks)
        if not data:
            return None
        extension = _sniff_extension(data, content_type)
        if extension is None:
            return None
        favicon_dir = Path(state_dir) / "favicons"
        favicon_dir.mkdir(parents=True, exist_ok=True)
        relative_path = f"favicons/{site_id}.{extension}"
        (Path(state_dir) / relative_path).write_bytes(data)
        return relative_path
    except Exception:
        logger.debug("Favicon fetch failed for site %s", site_id, exc_info=True)
        return None
