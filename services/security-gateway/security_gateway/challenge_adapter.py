"""Bounded adapters for operator-registered challenge checkers.

Provider endpoints and their resolved addresses are operator configuration;
callers submit only a challenge ID. Solution content is bounded text/JSON and
is forwarded as data. This module never evaluates or launches submitted code.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import ipaddress
import json
import os
import re
import socket
import sqlite3
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy.exc import SQLAlchemyError

from security_gateway.db import _postgres_url, challenge_connection

REFERENCE_CHALLENGE_ID = "reference-basic"
REFERENCE_ANSWER = "flag{black_onyx_reference}"
MAX_SOLUTION_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


class ChallengeUnavailable(RuntimeError):
    """A registered challenge adapter could not safely complete its request."""


def _ensure_challenge_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS challenge_solves ("
        "actor_id TEXT NOT NULL, challenge_id TEXT NOT NULL, solved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
        "PRIMARY KEY(actor_id, challenge_id))"
    )


@contextmanager
def _database():
    with challenge_connection() as connection:
        if not _postgres_url():
            _ensure_challenge_schema(connection)
        try:
            yield connection
            if hasattr(connection, "commit"):
                connection.commit()
        except BaseException:
            if hasattr(connection, "rollback"):
                connection.rollback()
            raise


def _registry() -> dict[str, dict[str, Any]]:
    raw = os.environ.get("SECURITY_CHALLENGE_PROVIDERS_JSON", "")
    if not raw:
        return {}
    if len(raw) > 65536:
        raise ValueError("Challenge provider registry is too large")
    try:
        source = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Challenge provider registry is invalid JSON") from exc
    if not isinstance(source, dict) or len(source) > 64:
        raise ValueError("Challenge provider registry is invalid")
    result: dict[str, dict[str, Any]] = {}
    for challenge_id, provider in source.items():
        if (
            not isinstance(challenge_id, str)
            or not _ID_RE.fullmatch(challenge_id)
            or challenge_id == REFERENCE_CHALLENGE_ID
            or not isinstance(provider, dict)
            or set(provider) != {"status_url", "submit_url", "allowed_ips"}
        ):
            raise ValueError("Challenge provider registration is invalid")
        allowed = provider["allowed_ips"]
        if not isinstance(allowed, list) or not 1 <= len(allowed) <= 16:
            raise ValueError("Challenge provider address registration is invalid")
        addresses: set[str] = set()
        for value in allowed:
            try:
                address = ipaddress.ip_address(value)
            except (TypeError, ValueError) as exc:
                raise ValueError("Challenge provider addresses must be literal IPs") from exc
            if (
                address.version != 4
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or address.is_reserved
            ):
                raise ValueError("Challenge provider address is not permitted")
            addresses.add(str(address))
        endpoints: dict[str, str] = {}
        registered_origin: tuple[str, str, int] | None = None
        for key in ("status_url", "submit_url"):
            value = provider[key]
            try:
                parsed = urlsplit(value) if isinstance(value, str) else None
                hostname = parsed.hostname if parsed is not None else None
            except ValueError as exc:
                raise ValueError("Challenge provider endpoint is invalid") from exc
            if (
                parsed is None
                or len(value) > 2048
                or parsed.scheme not in {"http", "https"}
                or not hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
                or parsed.query
                or hostname.casefold() in {"localhost", "metadata.google.internal"}
            ):
                raise ValueError("Challenge provider endpoint is invalid")
            if parsed.scheme == "http" and any(ipaddress.ip_address(ip).is_global for ip in addresses):
                raise ValueError("Public challenge providers must use HTTPS")
            try:
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
            except ValueError as exc:
                raise ValueError("Challenge provider port is invalid") from exc
            if not 1 <= port <= 65535:
                raise ValueError("Challenge provider port is invalid")
            origin = (parsed.scheme, hostname.casefold(), port)
            if registered_origin is not None and origin != registered_origin:
                raise ValueError("Challenge status and submit endpoints must share one registered origin")
            registered_origin = origin
            endpoints[key] = value
        result[challenge_id] = {
            **endpoints,
            "allowed_ips": frozenset(addresses),
        }
    return result


def ready() -> bool:
    """Validate durable local state and provider registration without network calls."""
    try:
        providers = _registry()
        with _database() as db:
            db.execute("SELECT 1 FROM challenge_solves LIMIT 1").fetchone()
        return bool(REFERENCE_CHALLENGE_ID and providers is not None)
    except (OSError, sqlite3.Error, SQLAlchemyError, ValueError, RuntimeError):
        return False


def registered_ids() -> set[str]:
    return {REFERENCE_CHALLENGE_ID, *_registry().keys()}


def _validate_id(challenge_id: str) -> None:
    if not isinstance(challenge_id, str) or not _ID_RE.fullmatch(challenge_id):
        raise ValueError("Challenge ID is invalid")


def validate_solution(solution: str) -> str:
    if not isinstance(solution, str) or "\x00" in solution:
        raise ValueError("Solution must be bounded UTF-8 text or JSON")
    encoded = solution.encode("utf-8")
    if not encoded or len(encoded) > MAX_SOLUTION_BYTES:
        raise ValueError("Solution must be between 1 byte and 16 KiB")
    try:
        value = json.loads(solution)
    except json.JSONDecodeError:
        return solution
    if not isinstance(value, (dict, list, str, int, float, bool)) and value is not None:
        raise ValueError("Solution JSON value is unsupported")
    return solution


def _reference_status(actor_id: str) -> dict[str, Any]:
    with _database() as db:
        row = db.execute(
            "SELECT 1 FROM challenge_solves WHERE actor_id = ? AND challenge_id = ?",
            (actor_id, REFERENCE_CHALLENGE_ID),
        ).fetchone()
    return {
        "challenge_id": REFERENCE_CHALLENGE_ID,
        "solved": row is not None,
        "description": "Submit the reference flag as plain text; submissions are compared, never executed.",
    }


def _submit_reference(actor_id: str, solution: str) -> dict[str, Any]:
    accepted = solution.strip() == REFERENCE_ANSWER
    if accepted:
        with _database() as db:
            db.execute(
                "INSERT OR IGNORE INTO challenge_solves(actor_id, challenge_id) VALUES (?, ?)",
                (actor_id, REFERENCE_CHALLENGE_ID),
            )
    return {"challenge_id": REFERENCE_CHALLENGE_ID, "accepted": accepted, "solved": accepted}


def _resolve_pinned(host: str, port: int, allowed_ips: frozenset[str]) -> list[str]:
    try:
        records = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        raise ChallengeUnavailable("challenge provider did not resolve") from exc
    resolved = {str(ipaddress.ip_address(record[4][0])) for record in records}
    if not resolved or not resolved.issubset(allowed_ips):
        raise ChallengeUnavailable("challenge provider DNS differs from its registered addresses")
    return sorted(resolved)


async def _request_provider(challenge_id: str, method: str, *, solution: str | None = None) -> dict[str, Any]:
    provider = _registry().get(challenge_id)
    if provider is None:
        raise KeyError(challenge_id)
    endpoint = provider["submit_url"] if method == "POST" else provider["status_url"]
    parsed = urlsplit(endpoint)
    host = parsed.hostname.casefold()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    allowed_ips = provider["allowed_ips"]
    addresses = await asyncio.to_thread(_resolve_pinned, host, port, allowed_ips)
    pinned = parsed._replace(netloc=f"{addresses[0]}:{port}").geturl()
    headers = {"Host": host if port in {80, 443} else f"{host}:{port}"}
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=2.0), trust_env=False, follow_redirects=False,
        ) as client:
            async with client.stream(
                method,
                pinned,
                headers=headers,
                json={"solution": solution} if method == "POST" else None,
                extensions={"sni_hostname": host} if parsed.scheme == "https" else {},
            ) as response:
                if response.is_redirect or response.status_code < 200 or response.status_code >= 300:
                    raise ChallengeUnavailable("challenge provider returned an unsuccessful response")
                length = response.headers.get("content-length")
                if length and int(length) > MAX_RESPONSE_BYTES:
                    raise ChallengeUnavailable("challenge provider response exceeded its limit")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > MAX_RESPONSE_BYTES:
                        raise ChallengeUnavailable("challenge provider response exceeded its limit")
    except (httpx.HTTPError, OSError, ValueError) as exc:
        raise ChallengeUnavailable("challenge provider is unavailable") from exc
    try:
        result = json.loads(data)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ChallengeUnavailable("challenge provider response was invalid") from exc
    if not isinstance(result, dict):
        raise ChallengeUnavailable("challenge provider response was invalid")
    expected_field = "accepted" if method == "POST" else "solved"
    if not isinstance(result.get(expected_field), bool):
        raise ChallengeUnavailable("challenge provider response was invalid")
    return {"challenge_id": challenge_id, expected_field: result[expected_field]}


async def status(actor_id: str, challenge_id: str) -> dict[str, Any]:
    _validate_id(challenge_id)
    if challenge_id == REFERENCE_CHALLENGE_ID:
        return _reference_status(actor_id)
    return await _request_provider(challenge_id, "GET")


async def submit(actor_id: str, challenge_id: str, solution: str) -> dict[str, Any]:
    _validate_id(challenge_id)
    solution = validate_solution(solution)
    if challenge_id == REFERENCE_CHALLENGE_ID:
        return _submit_reference(actor_id, solution)
    return await _request_provider(challenge_id, "POST", solution=solution)
