"""Passive DNS and WHOIS pivots (soft-fail WHOIS)."""

from __future__ import annotations

import asyncio
from typing import Any

import dns.resolver
from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def passive_dns_whois(*, domain: str, query_types: list[str] | None = None) -> dict[str, Any]:
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        raise ValueError("domain is required")

    types = query_types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    dns_records: dict[str, list[str]] = {}
    errors: list[str] = []

    for rtype in types:
        try:
            answers = await asyncio.to_thread(
                dns.resolver.resolve,
                domain,
                rtype,
                lifetime=5.0,
            )
            dns_records[rtype] = [r.to_text() for r in answers]
        except Exception as exc:  # noqa: BLE001 — soft-fail per record type
            errors.append(f"{rtype}: {exc}")

    whois_data: dict[str, Any] | None = None
    whois_error: str | None = None
    try:
        import whois  # type: ignore[import-untyped]

        raw = await asyncio.to_thread(whois.whois, domain)
        whois_data = _normalize_whois(raw)
    except Exception as exc:  # noqa: BLE001
        whois_error = str(exc)

    return {
        "domain": domain,
        "dns": dns_records,
        "dns_errors": errors,
        "whois": whois_data,
        "whois_error": whois_error,
    }


def _normalize_whois(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): _stringify(v) for k, v in raw.items()}
    return {"raw": _stringify(raw)}


def _stringify(value: Any) -> Any:
    if isinstance(value, list):
        return [_stringify(v) for v in value]
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    return value


def register_passive_dns_whois(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="passive_dns_whois")
    async def passive_dns_whois_tool(
        domain: str,
        query_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Resolve DNS records and optionally fetch WHOIS (WHOIS soft-fails)."""
        _ = client
        return await passive_dns_whois(domain=domain, query_types=query_types)
