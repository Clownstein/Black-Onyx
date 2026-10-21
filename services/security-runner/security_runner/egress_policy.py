"""Destination validation and literal-address policy generation for the runner.

These checks validate request scope and generate firewall configuration.
They do not independently prove the Docker/network boundary; public and lab
execution remain disabled until separate executor escape testing passes.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
from typing import Sequence

logger = logging.getLogger(__name__)

BLOCKED_TCP_PORTS = frozenset({
    53, 853, 5353, 5355,       # DNS, DNS-over-TLS, mDNS, LLMNR
    2375, 2376, 2379, 2380,   # Docker API and etcd
    6443, 10250, 10255, 10257, 10259,  # Kubernetes control services
})

# Hostnames: RFC 952 labels, no wildcards, no trailing dot.
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
# Bare IPv4 or IPv6 (no CIDR, no port).
_IP_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
    r"|"
    r"^\[?[0-9a-fA-F:]+\]?$"
)

# Ranges that the sandbox must never reach, regardless of the allowlist.
_BLOCKED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2001:db8::/32"),
]


class EgressDenied(ValueError):
    """Raised when a destination fails validation."""


def is_private_ip(addr: str) -> bool:
    """Return True if *addr* resolves to a blocked (private/reserved) range."""
    cleaned = addr.strip("[]")
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    return any(ip in net for net in _BLOCKED_NETS)


def validate_destination(dest: str, *, allow_private: bool = False) -> str:
    """Validate and normalise a single destination entry.

    Returns the cleaned destination string.  Raises ``EgressDenied`` if the
    destination is syntactically invalid, a wildcard, or a private address
    when private destinations are not part of a registered lab profile.
    """
    dest = dest.strip().lower()
    if not dest or len(dest) > 253:
        raise EgressDenied("Empty or oversized destination")
    if "*" in dest or "?" in dest:
        raise EgressDenied(f"Wildcards are not permitted: {dest}")
    if dest.startswith("http://") or dest.startswith("https://"):
        raise EgressDenied(f"Destinations must be hostnames or IPs, not URLs: {dest}")
    # Strip port suffix if present (host:port).
    host = dest.rsplit(":", 1)[0] if ":" in dest and not dest.startswith("[") else dest
    host = host.strip("[]")
    if _IP_RE.match(host):
        if is_private_ip(host) and not allow_private:
            raise EgressDenied(f"Private/reserved addresses are blocked: {host}")
        return host
    if _HOSTNAME_RE.match(host):
        if host.endswith(".local") or host.endswith(".localhost") or host.endswith(".internal"):
            raise EgressDenied(f"Local-only TLD is blocked: {host}")
        return host
    raise EgressDenied(f"Invalid destination: {dest}")


def validate_destinations(destinations: Sequence[str]) -> list[str]:
    """Validate a full destination list; returns cleaned entries."""
    if not destinations:
        raise EgressDenied("At least one destination is required for network access")
    if len(destinations) > 100:
        raise EgressDenied("Too many destinations (max 100)")
    seen: set[str] = set()
    result: list[str] = []
    for raw in destinations:
        clean = validate_destination(raw)
        if clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def resolve_hosts(destinations: list[str]) -> dict[str, list[str]]:
    """Resolve hostnames for a future per-job egress policy.

    Returns ``{hostname: [ip, ...]}``; bare IPs map to themselves.
    Any hostname that resolves entirely to private IPs is rejected.
    """
    pinned: dict[str, list[str]] = {}
    for dest in destinations:
        if _IP_RE.match(dest.strip("[]")):
            pinned[dest] = [dest.strip("[]")]
            continue
        try:
            results = socket.getaddrinfo(dest, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise EgressDenied(f"Cannot resolve destination: {dest}") from exc
        ips: list[str] = []
        for family, _type, _proto, _canon, sockaddr in results:
            ip_str = sockaddr[0]
            if is_private_ip(ip_str):
                logger.warning("DNS rebind blocked: %s resolved to private %s", dest, ip_str)
                continue
            ips.append(ip_str)
        if not ips:
            raise EgressDenied(
                f"All resolved addresses for {dest} are private/reserved (DNS rebinding blocked)"
            )
        pinned[dest] = sorted(set(ips))
    return pinned


def extra_hosts(pinned: dict[str, list[str]]) -> dict[str, str]:
    """Build DNS pinning hints; this does not restrict packet destinations.

    Each hostname maps to the first resolved public IP so the container's
    ``/etc/hosts`` pins the mapping and DNS cannot redirect after resolution.
    Bare IPs are not pinned they cannot be redirected by DNS.
    """
    hosts: dict[str, str] = {}
    for hostname, ips in pinned.items():
        if _IP_RE.match(hostname.strip("[]")):
            continue
        if _HOSTNAME_RE.match(hostname) and ips:
            hosts[hostname] = ips[0]
    return hosts


def parse_lab_profiles(raw: str) -> dict[str, dict[str, object]]:
    """Parse the operator-owned lab registry; request bodies cannot add entries."""
    if not raw or len(raw) > 65536:
        return {}
    try:
        source = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise EgressDenied("Registered lab profile configuration is invalid") from exc
    if not isinstance(source, dict) or len(source) > 64:
        raise EgressDenied("Registered lab profile configuration is invalid")
    profiles: dict[str, dict[str, object]] = {}
    for profile_id, profile in source.items():
        if (
            not isinstance(profile_id, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", profile_id)
            or not isinstance(profile, dict)
            or set(profile) != {"network", "cidrs", "ports"}
        ):
            raise EgressDenied("Registered lab profile configuration is invalid")
        network = profile.get("network")
        cidrs = profile.get("cidrs")
        ports = profile.get("ports")
        if (
            not isinstance(network, str)
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", network)
            or not isinstance(cidrs, list)
            or not 1 <= len(cidrs) <= 32
        ):
            raise EgressDenied("Registered lab profile configuration is invalid")
        parsed_networks: list[ipaddress.IPv4Network] = []
        for value in cidrs:
            if not isinstance(value, str):
                raise EgressDenied("Registered lab CIDR is invalid")
            try:
                network_value = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise EgressDenied("Registered lab CIDR is invalid") from exc
            if network_value.version != 4 or not network_value.is_private:
                raise EgressDenied("Lab profiles may register only private IPv4 CIDRs")
            parsed_networks.append(network_value)
        allow_all_tcp = False
        normalized_ports: set[int] = set()
        if ports == "all":
            allow_all_tcp = True
        elif (
            not isinstance(ports, list)
            or not 1 <= len(ports) <= 64
        ):
            raise EgressDenied("Registered lab profile configuration is invalid")
        else:
            for port in ports:
                if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                    raise EgressDenied("Registered lab port is invalid")
                normalized_ports.add(port)
        profiles[profile_id] = {
            "network": network,
            "cidrs": tuple(parsed_networks),
            "ports": None if allow_all_tcp else frozenset(normalized_ports),
        }
    return profiles


def resolve_ipv4_targets(
    destinations: Sequence[str],
    *,
    profile: str,
    lab_cidrs: Sequence[ipaddress.IPv4Network] = (),
    blocked_ips: Sequence[str] = (),
) -> tuple[dict[str, list[str]], list[str]]:
    """Resolve and pin IPv4 destinations allowed by a public or registered lab profile."""
    if profile not in {"public", "lab"}:
        raise EgressDenied("Network profile must be public or lab")
    if not destinations or len(destinations) > 100:
        raise EgressDenied("A bounded, non-empty destination list is required")
    blocked = {ipaddress.ip_address(value) for value in blocked_ips}
    pinned: dict[str, list[str]] = {}
    all_addresses: set[str] = set()
    for raw in destinations:
        if not isinstance(raw, str) or not raw or len(raw) > 253:
            raise EgressDenied("Destinations must be IPv4 addresses or hostnames; ports are separate")
        try:
            supplied_literal = ipaddress.ip_address(raw.strip())
        except ValueError:
            supplied_literal = None
        if supplied_literal is not None and supplied_literal.version == 6:
            raise EgressDenied("IPv6 is denied for sandbox jobs")
        if ":" in raw:
            raise EgressDenied("Destinations must be IPv4 addresses or hostnames; ports are separate")
        host = validate_destination(raw, allow_private=(profile == "lab"))
        if host != raw.strip().lower():
            raise EgressDenied("Destination entries must not contain a port")
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            try:
                answers = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise EgressDenied(f"Cannot resolve destination: {host}") from exc
            addresses = sorted({ipaddress.ip_address(answer[4][0]) for answer in answers})
        else:
            if literal.version != 4:
                raise EgressDenied("IPv6 is denied for sandbox jobs")
            addresses = [literal]
        if not addresses:
            raise EgressDenied(f"Destination has no IPv4 address: {host}")
        for address in addresses:
            if (
                address in blocked
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or address.is_reserved
            ):
                raise EgressDenied("Destination resolves to a blocked infrastructure address")
            if profile == "public" and not address.is_global:
                raise EgressDenied("Public jobs may reach only globally routed IPv4 addresses")
            if profile == "lab" and not any(address in cidr for cidr in lab_cidrs):
                raise EgressDenied("Destination is outside the registered lab profile")
        values = [str(address) for address in addresses]
        if len(values) > 16:
            raise EgressDenied("A destination resolved to too many IPv4 addresses")
        pinned[host] = values
        all_addresses.update(values)
        if len(all_addresses) > 100:
            raise EgressDenied("Resolved target set exceeds 100 IPv4 addresses")
    return pinned, sorted(all_addresses)


def validate_resolved_targets(
    destinations: Sequence[str],
    resolved_targets: dict[str, list[str]],
    *,
    profile: str,
    lab_cidrs: Sequence[ipaddress.IPv4Network] = (),
    blocked_ips: Sequence[str] = (),
) -> tuple[dict[str, list[str]], list[str]]:
    """Validate the exact previewed DNS answers without resolving them again."""
    if profile not in {"public", "lab"} or not isinstance(resolved_targets, dict):
        raise EgressDenied("Invalid resolved target scope")
    normalized = [
        validate_destination(value, allow_private=(profile == "lab"))
        for value in destinations
    ]
    expected = set(normalized)
    if not expected or len(expected) > 100 or set(resolved_targets) != expected:
        raise EgressDenied("Resolved targets do not match the previewed destinations")
    blocked = {ipaddress.ip_address(value) for value in blocked_ips}
    pinned: dict[str, list[str]] = {}
    all_addresses: set[str] = set()
    for host in sorted(expected):
        values = resolved_targets[host]
        if not isinstance(values, list) or not 1 <= len(values) <= 16:
            raise EgressDenied("Resolved target address list is invalid")
        parsed: set[ipaddress.IPv4Address] = set()
        for raw in values:
            try:
                address = ipaddress.ip_address(raw)
            except (TypeError, ValueError) as exc:
                raise EgressDenied("Resolved targets must be IPv4 addresses") from exc
            if address.version != 4 or address in blocked or address.is_reserved:
                raise EgressDenied("Resolved target is a blocked infrastructure address")
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                raise EgressDenied("Resolved target is a blocked infrastructure address")
            if profile == "public" and not address.is_global:
                raise EgressDenied("Public jobs may reach only globally routed IPv4 addresses")
            if profile == "lab" and not any(address in cidr for cidr in lab_cidrs):
                raise EgressDenied("Lab target is outside the registered lab profile")
            parsed.add(address)
        if len(parsed) != len(values):
            raise EgressDenied("Resolved target address list contains duplicates")
        pinned[host] = sorted(map(str, parsed))
        all_addresses.update(pinned[host])
        if len(all_addresses) > 100:
            raise EgressDenied("Resolved target set exceeds 100 IPv4 addresses")
    return pinned, sorted(all_addresses)


def nftables_policy_script(addresses: Sequence[str], ports: Sequence[int]) -> str:
    """Generate a default-deny namespace firewall using validated literal values."""
    parsed: set[ipaddress.IPv4Address] = set()
    for address in addresses:
        value = ipaddress.ip_address(address)
        if value.version != 4 or not value.is_global and not value.is_private:
            raise EgressDenied("Firewall policy contains an invalid IPv4 destination")
        parsed.add(value)
    all_tcp = list(ports) == [0]
    if all_tcp:
        valid_ports: list[int] = []
    else:
        if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
            raise EgressDenied("Firewall policy contains an invalid TCP port")
        if set(ports) & BLOCKED_TCP_PORTS:
            raise EgressDenied("Firewall policy includes a restricted DNS or control-service port")
        valid_ports = sorted(set(ports))
        if not valid_ports or len(valid_ports) > 64:
            raise EgressDenied("Firewall policy is empty or exceeds its bounds")
    if not parsed or len(parsed) > 100:
        raise EgressDenied("Firewall policy is empty or exceeds its bounds")
    address_set = ", ".join(str(value) for value in sorted(parsed))
    if all_tcp:
        blocked = ", ".join(str(value) for value in sorted(BLOCKED_TCP_PORTS))
        port_rule = (
            f"ip daddr {{ {address_set} }} tcp dport != {{ {blocked} }} ct state new accept"
        )
    else:
        port_set = ", ".join(str(value) for value in valid_ports)
        port_rule = f"ip daddr {{ {address_set} }} tcp dport {{ {port_set} }} ct state new accept"
    return (
        "table inet bo_egress {\n"
        " chain input { type filter hook input priority 0; policy drop;\n"
        "  iifname lo accept\n"
        "  ct state established,related accept\n"
        " }\n"
        " chain output { type filter hook output priority 0; policy drop;\n"
        "  ct state established,related accept\n"
        f"  {port_rule}\n"
        " }\n"
        "}\n"
    )


def nftables_deny_all_script() -> str:
    """Install a fresh input/output deny policy for capture-only namespaces."""
    return (
        "table inet bo_capture {\n"
        " chain input { type filter hook input priority 0; policy drop;\n"
        "  iifname lo accept\n"
        "  ct state established,related accept\n"
        " }\n"
        " chain output { type filter hook output priority 0; policy drop;\n"
        "  ct state established,related accept\n"
        " }\n"
        "}\n"
    )
