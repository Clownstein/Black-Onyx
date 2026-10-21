"""Narrow, bounded Shodan provider adapter; credentials never enter tool jobs."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import socket
from typing import Any
from urllib.parse import quote

import httpx


API_HOST = "api.shodan.io"
API_PORT = 443
MAX_RESPONSE_BYTES = 1024 * 1024


def _api_key() -> str:
    value = os.environ.get("SHODAN_API_KEY", "").strip()
    if not value or len(value) > 512 or "\x00" in value:
        raise RuntimeError("Shodan provider credential is unavailable")
    return value


def parse_query(query: str) -> tuple[str, str]:
    if not isinstance(query, str) or len(query) > 512 or "\x00" in query:
        raise ValueError("Shodan query is invalid")
    match = re.fullmatch(r"\s*(ip|hostname):([A-Za-z0-9.:-]{1,253})\s*", query, re.IGNORECASE)
    if not match:
        raise ValueError("Shodan supports only exact ip:<address> or hostname:<name> lookups")
    kind, target = match.group(1).lower(), match.group(2).lower().rstrip(".")
    if kind == "ip":
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            raise ValueError("Shodan IP lookup requires a valid address") from exc
        if address.version != 4 or not address.is_global:
            raise ValueError("Shodan IP lookup requires a globally routed IPv4 address")
        return "ip", str(address)
    if (
        len(target) > 253 or "." not in target
        or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", target)
        or target.endswith((".local", ".localhost", ".internal"))
    ):
        raise ValueError("Shodan hostname lookup requires a public DNS name")
    return "hostname", target


def _resolve_api_addresses() -> list[str]:
    """Resolve the fixed provider hostname once and reject non-public results."""
    try:
        records = socket.getaddrinfo(API_HOST, API_PORT, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        raise RuntimeError("Shodan provider did not resolve") from exc
    addresses: set[str] = set()
    for record in records:
        try:
            address = ipaddress.ip_address(record[4][0])
        except (ValueError, IndexError, TypeError):
            continue
        if address.version != 4 or not address.is_global:
            raise RuntimeError("Shodan provider resolved to a non-public address")
        addresses.add(str(address))
    if not addresses:
        raise RuntimeError("Shodan provider did not resolve")
    return sorted(addresses)


async def _get(path: str, *, key: str, params: dict[str, str] | None = None) -> Any:
    if not re.fullmatch(r"/[A-Za-z0-9_./-]{1,1024}", path) or ".." in path:
        raise RuntimeError("Shodan provider path is invalid")
    query = {"key": key, **(params or {})}
    chunks: list[bytes] = []
    size = 0
    addresses = await asyncio.to_thread(_resolve_api_addresses)
    pinned_url = f"https://{addresses[0]}:{API_PORT}{path}"
    async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=3.0), trust_env=False, follow_redirects=False) as client:
        async with client.stream(
            "GET",
            pinned_url,
            params=query,
            headers={"Host": API_HOST},
            extensions={"sni_hostname": API_HOST},
        ) as response:
            if response.is_redirect:
                raise RuntimeError("Shodan returned a redirect")
            if response.status_code >= 400:
                raise RuntimeError("Shodan provider rejected the request")
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise RuntimeError("Shodan response exceeded the configured limit")
                chunks.append(chunk)
    try:
        return json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Shodan returned an invalid response") from exc


async def readiness_check() -> bool:
    try:
        result = await _get("/api-info", key=_api_key())
        return isinstance(result, dict) and isinstance(result.get("plan"), str)
    except (RuntimeError, httpx.HTTPError, ValueError):
        return False


async def lookup(query: str) -> dict[str, Any]:
    kind, target = parse_query(query)
    key = _api_key()
    if kind == "hostname":
        resolved = await _get("/dns/resolve", key=key, params={"hostnames": target})
        target_ip = resolved.get(target) if isinstance(resolved, dict) else None
        try:
            address = ipaddress.ip_address(target_ip)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("Shodan could not resolve the requested hostname") from exc
        if address.version != 4 or not address.is_global:
            raise RuntimeError("Shodan hostname did not resolve to a public IPv4 address")
        target = str(address)
    result = await _get(f"/shodan/host/{quote(target, safe='.')}", key=key)
    if not isinstance(result, dict):
        raise RuntimeError("Shodan returned an invalid host record")
    ports = result.get("ports", [])
    vulns = result.get("vulns", [])
    hostnames = result.get("hostnames", [])
    return {
        "ip": str(result.get("ip_str", target))[:64],
        "organization": str(result.get("org", ""))[:200],
        "ports": [port for port in ports[:32] if isinstance(port, int)] if isinstance(ports, list) else [],
        "vulnerabilities": [str(item)[:64] for item in list(vulns)[:32]] if isinstance(vulns, (list, set)) else [],
        "hostnames": [str(item)[:253] for item in hostnames[:16]] if isinstance(hostnames, list) else [],
    }
