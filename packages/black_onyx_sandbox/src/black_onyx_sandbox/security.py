"""Sandbox security SSRF validation, workspace path resolution, audit redaction.

Merged from model-tools/sandbox/security.py. Fail-closed target validation:
IMDS always blocked, internal Docker service names blocked, DNS resolution
checked against blocked ranges, allowlist/blocklist modes supported.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Hostnames that must never be reachable from the sandbox
BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "metadata.google.internal",
    "docker-socket-proxy",
    "security-runner",
    "security-gateway",
    "incident-api",
    "asset-registry",
    "threat-intel-service",
    "integration-hub",
    "response-orchestrator",
    "notification-service",
    "training-orchestrator",
    "ingestion-gateway",
    "model-gateway",
    "correlation-engine",
    "inference-worker",
    "qdrant",
    "postgres",
    "redpanda",
    "opensearch",
    "minio",
    "redis",
    "mlflow",
    "searxng",
    "web",
})

# IMDS and infrastructure ranges always blocked regardless of config
ALWAYS_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.169.254/32",  # IMDS
        "169.254.0.0/16",      # link-local
        "224.0.0.0/4",         # multicast
        "240.0.0.0/4",         # reserved
        "0.0.0.0/8",           # unspecified
        "::1/128",             # IPv6 loopback
        "fe80::/10",           # IPv6 link-local
        "ff00::/8",            # IPv6 multicast
    )
)

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)

MAX_DNS_ANSWERS = 100

_REDACT_PATTERNS = (
    # --flag=value for credential-ish flags
    re.compile(r"(--(?:private-key|password|pass|pwd|secret|token)[=\s]\S+)", re.IGNORECASE),
    # CAST_PRIVATE_KEY= / ETH_PRIVATE_KEY= assignments
    re.compile(r"(CAST_PRIVATE_KEY=\S+)", re.IGNORECASE),
    re.compile(r"(ETH_PRIVATE_KEY=\S+)", re.IGNORECASE),
    # 64+ hex strings (private keys, digests with secret material)
    re.compile(r"\b[a-fA-F0-9]{64,}\b"),
)


class TargetBlockedError(PermissionError):
    """Raised when a target host/IP is blocked by policy."""


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _allowed_targets() -> list[str]:
    """Parse ALLOWED_TARGETS (comma-separated hostnames or CIDRs)."""
    raw = (os.environ.get("ALLOWED_TARGETS") or "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def allowed_targets_configured() -> bool:
    """Whether an explicit ALLOWED_TARGETS allowlist is set."""
    return bool(_allowed_targets())


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for net in ALWAYS_BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


def _ip_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for net in _PRIVATE_NETWORKS:
        if ip in net:
            return True
    return False


def _resolve_host(host: str) -> list[str]:
    """Resolve a hostname to IP address strings, bounded to MAX_DNS_ANSWERS."""
    try:
        answers = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetBlockedError(f"DNS resolution failed for {host!r}") from exc
    ips: list[str] = []
    for answer in answers[:MAX_DNS_ANSWERS]:
        sockaddr = answer[4]
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips


def _matches_allowlist(host: str, allowlist: Iterable[str]) -> bool:
    allow = list(allowlist)
    for entry in allow:
        if entry == host:
            return True
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        try:
            if ipaddress.ip_address(host) in net:
                return True
        except ValueError:
            # host is a hostname; resolve and check
            for ip in _resolve_host(host):
                try:
                    if ipaddress.ip_address(ip) in net:
                        return True
                except ValueError:
                    continue
    return False


def validate_target(host: str) -> None:
    """Validate a target host against SSRF policy. Raises TargetBlockedError.

    Rules (fail-closed):
    - IMDS/link-local/multicast/reserved always blocked
    - Internal Docker service names always blocked
    - If ALLOWED_TARGETS set: every host must match an entry (allowlist mode)
    - Else: private/loopback require ALLOW_PRIVATE_TARGETS=true
    - Public targets require ALLOW_PUBLIC_TARGETS=true (blocklist mode)
    """
    host = (host or "").strip()
    if not host:
        raise TargetBlockedError("Empty target host")
    lowered = host.lower()

    if lowered in BLOCKED_HOSTNAMES:
        raise TargetBlockedError(f"Blocked hostname: {host}")

    allow_host_docker = env_bool("ALLOW_HOST_DOCKER_INTERNAL", False)
    if lowered == "host.docker.internal" and not allow_host_docker:
        raise TargetBlockedError("Blocked hostname: host.docker.internal")

    # Reject ambiguous numeric targets (e.g. "10.1" shorthand) and single labels
    # that could resolve against Docker's embedded DNS.
    if re.fullmatch(r"\d+(\.\d+){0,2}", host):
        raise TargetBlockedError(f"Ambiguous numeric target: {host}")

    allowlist = _allowed_targets()
    if allowlist:
        if not _matches_allowlist(host, allowlist):
            raise TargetBlockedError(f"Target not in ALLOWED_TARGETS: {host}")
        # IMDS still blocked even for allowlisted hosts
        for ip in _resolve_host(host):
            addr = ipaddress.ip_address(ip)
            if _ip_blocked(addr):
                raise TargetBlockedError(f"Resolved IP {ip} is in an always-blocked range")
        return

    # Blocklist mode
    for ip in _resolve_host(host):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if _ip_blocked(addr):
            raise TargetBlockedError(f"Resolved IP {ip} is in an always-blocked range")
        if _ip_private(addr) and not env_bool("ALLOW_PRIVATE_TARGETS", False):
            raise TargetBlockedError(
                f"Resolved IP {ip} is private/loopback; set ALLOW_PRIVATE_TARGETS=true to permit"
            )
        if not _ip_private(addr) and not env_bool("ALLOW_PUBLIC_TARGETS", False):
            raise TargetBlockedError(
                f"Resolved IP {ip} is public; set ALLOW_PUBLIC_TARGETS=true to permit"
            )


def validate_url(url: str) -> None:
    """Validate a target URL: scheme, credentials, fragment, and host policy."""
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise TargetBlockedError(f"Invalid URL: {url!r}") from exc
    if parsed.scheme not in ("http", "https"):
        raise TargetBlockedError(f"Unsupported URL scheme: {parsed.scheme!r}")
    if parsed.username or parsed.password:
        raise TargetBlockedError("URL must not contain credentials")
    if parsed.fragment:
        raise TargetBlockedError("URL must not contain a fragment")
    host = parsed.hostname
    if not host:
        raise TargetBlockedError("URL has no host")
    validate_target(host)


def resolve_workspace_path(workspace: str | Path, relative: str) -> Path:
    """Resolve a path relative to the workspace, rejecting traversal/symlinks.

    Raises PermissionError if the path escapes the workspace or touches a symlink.
    """
    workspace_path = Path(workspace).resolve(strict=True)
    candidate = (workspace_path / relative).resolve(strict=False)
    if not candidate.is_relative_to(workspace_path):
        raise PermissionError(f"Path escapes workspace: {relative!r}")
    # Walk each component; reject symlinks anywhere along the way
    current = workspace_path
    parts = Path(relative).parts
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise PermissionError(f"Symlink in workspace path: {relative!r}")
    return candidate


def redact_command_for_audit(command: str) -> str:
    """Redact credential-like substrings from a command before audit logging."""
    value = command or ""
    for pattern in _REDACT_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def quote_shell_args(args: list[str]) -> str:
    """Quote a list of arguments for safe shell interpolation."""
    import shlex

    return " ".join(shlex.quote(str(a)) for a in args)


def validate_eth_address(address: str) -> bool:
    """Validate a 0x-prefixed 20-byte hex Ethereum address."""
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", address or ""))


def bound_hex_data(data: str, max_chars: int = 100_000) -> str:
    """Bound hex-string data to a maximum length."""
    value = (data or "").lstrip("0x")
    if len(value) > max_chars:
        raise ValueError(f"Hex data exceeds {max_chars} characters")
    return value
