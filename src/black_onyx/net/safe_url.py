"""SSRF-safe URL validation for outbound HTTPS integrations."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse


def _resolve_public_destination(url: str, *, purpose: str) -> tuple[str, int, list[str]]:
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
    except (socket.gaierror, ValueError) as exc:
        raise ValueError(f"{purpose} hostname did not resolve: {hostname}") from exc
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not ip.is_global:
            raise ValueError(f"{purpose} hostname resolves to a non-public address")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError(f"{purpose} hostname did not resolve: {hostname}")
    return hostname, port, addresses


def validate_public_https_url(url: str, *, purpose: str = "URL") -> str:
    """Validate an HTTPS URL and reject hosts resolving to non-public IPs."""
    cleaned = (url or "").strip()
    _resolve_public_destination(cleaned, purpose=purpose)
    return cleaned.rstrip("/")


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    return parsed.scheme.casefold(), (parsed.hostname or "").casefold(), parsed.port or 443


def _response_from_decoded(response: Any, content: bytes, method: str, url: str) -> Any:
    """Build a response whose body is already decoded.

    ``stream`` yields decompressed bytes, but the upstream headers still say
    ``Content-Encoding``. Passing both to ``httpx.Response`` makes the next
    ``.content`` read decompress the plaintext again.
    """
    import httpx

    items = response.headers.multi_items() if hasattr(response.headers, "multi_items") else response.headers.items()
    headers = [
        (key, value)
        for key, value in items
        if key.lower() not in {"content-encoding", "content-length", "transfer-encoding"}
    ]
    headers.append(("content-length", str(len(content))))
    return httpx.Response(
        response.status_code,
        headers=headers,
        content=content,
        request=httpx.Request(method, url),
    )


async def request_public_https(
    client: Any,
    method: str,
    url: str,
    *,
    max_bytes: int,
    purpose: str = "URL",
    auth: Any = None,
    allowed_hosts: set[str] | None = None,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> Any:
    """Make one bounded HTTPS request to the exact IP that passed validation.

    Every redirect is independently resolved and pinned. Credentials are
    rejected on cross-origin redirects, and environment proxies are avoided by
    requiring a caller-created client with ``trust_env=False``.
    """
    import httpx
    from urllib.parse import urljoin

    initial_origin = _origin(url)
    current = url
    request_headers = dict(headers or {})
    for hop in range(5):
        parsed_current = urlparse(current)
        hostname = (parsed_current.hostname or "").casefold()
        if allowed_hosts and hostname not in {host.casefold() for host in allowed_hosts}:
            raise ValueError(f"{purpose} hostname is not allowlisted")
        hostname, port, addresses = await __import__("asyncio").to_thread(
            _resolve_public_destination, current, purpose=purpose,
        )
        parsed = urlparse(current)
        address = addresses[0]
        pinned_host = f"[{address}]" if ":" in address else address
        pinned_url = parsed._replace(netloc=f"{pinned_host}:{port}").geturl()
        outbound_headers = dict(request_headers)
        outbound_headers["Host"] = hostname if port == 443 else f"{hostname}:{port}"
        try:
            async with client.stream(
                method,
                pinned_url,
                headers=outbound_headers,
                auth=auth if _origin(current) == initial_origin else None,
                extensions={"sni_hostname": hostname},
                **kwargs,
            ) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise ValueError(f"{purpose} redirect has no location")
                    destination = urljoin(current, location)
                    if _origin(destination) != initial_origin and (
                        auth is not None
                        or any(k.casefold() == "authorization" for k in request_headers)
                    ):
                        raise ValueError(f"{purpose} authenticated redirect changed origin")
                    if method.upper() not in {"GET", "HEAD"}:
                        raise ValueError(f"{purpose} does not permit redirects for {method.upper()}")
                    current = destination
                    kwargs.pop("params", None)
                    continue
                length = response.headers.get("content-length")
                if length and int(length) > max_bytes:
                    raise ValueError(f"{purpose} response exceeds the {max_bytes} byte limit")
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > max_bytes:
                        raise ValueError(f"{purpose} response exceeds the {max_bytes} byte limit")
                return _response_from_decoded(response, bytes(content), method, current)
        except httpx.TimeoutException:
            raise
        except httpx.TransportError:
            raise
    raise ValueError(f"{purpose} exceeded the redirect limit")


def request_public_https_sync(
    client: Any,
    method: str,
    url: str,
    *,
    max_bytes: int,
    purpose: str = "URL",
    headers: dict[str, str] | None = None,
    allowed_hosts: set[str] | None = None,
    **kwargs: Any,
) -> Any:
    """Synchronous counterpart to :func:`request_public_https`."""
    from urllib.parse import urljoin

    initial_origin = _origin(url)
    current = url
    request_headers = dict(headers or {})
    for _hop in range(5):
        parsed_current = urlparse(current)
        resolved_host = (parsed_current.hostname or "").casefold()
        if allowed_hosts and resolved_host not in {host.casefold() for host in allowed_hosts}:
            raise ValueError(f"{purpose} hostname is not allowlisted")
        hostname, port, addresses = _resolve_public_destination(current, purpose=purpose)
        parsed = urlparse(current)
        address = addresses[0]
        pinned_host = f"[{address}]" if ":" in address else address
        pinned_url = parsed._replace(netloc=f"{pinned_host}:{port}").geturl()
        outbound_headers = dict(request_headers)
        outbound_headers["Host"] = hostname if port == 443 else f"{hostname}:{port}"
        with client.stream(
            method,
            pinned_url,
            headers=outbound_headers,
            extensions={"sni_hostname": hostname},
            **kwargs,
        ) as response:
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise ValueError(f"{purpose} redirect has no location")
                destination = urljoin(current, location)
                if _origin(destination) != initial_origin and any(
                    key.casefold() == "authorization" for key in request_headers
                ):
                    raise ValueError(f"{purpose} authenticated redirect changed origin")
                if method.upper() not in {"GET", "HEAD"}:
                    raise ValueError(f"{purpose} does not permit redirects for {method.upper()}")
                current = destination
                kwargs.pop("params", None)
                continue
            length = response.headers.get("content-length")
            if length and int(length) > max_bytes:
                raise ValueError(f"{purpose} response exceeds the {max_bytes} byte limit")
            content = response.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise ValueError(f"{purpose} response exceeds the {max_bytes} byte limit")
            return _response_from_decoded(response, content, method, current)
    raise ValueError(f"{purpose} exceeded the redirect limit")
