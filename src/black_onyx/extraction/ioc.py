"""IOC (Indicator of Compromise) extraction from text and HTML."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from black_onyx.extraction.patterns import (
    IOC_PATTERNS,
    DEFANGED_IP_PATTERN,
    DEFANGED_DOMAIN_PATTERN,
    DEFANGED_EMAIL_PATTERN,
)


@dataclass
class IOCResult:
    """Container for extracted IOCs."""

    md5: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    sha512: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    cidr_ranges: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    jarm_fingerprints: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    yara_rules: list[str] = field(default_factory=list)
    sigma_rules: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    defanged_iocs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict, excluding empty lists."""
        return {k: v for k, v in self.__dict__.items() if v}

    @property
    def total_count(self) -> int:
        """Total number of extracted IOCs across all types."""
        return sum(len(v) for v in self.__dict__.values() if isinstance(v, list))


def defang_ioc(ioc: str) -> str:
    """Defang an IOC for safe sharing (e.g., 1.2.3.4 -> 1[.]2[.]3[.]4)."""
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ioc):
        return ioc.replace(".", "[.]")
    if "@" in ioc and "." in ioc:
        return ioc.replace("@", "[@]").replace(".", "[.]")
    if "http" in ioc.lower():
        return ioc.replace("http", "hxxp").replace(".", "[.]")
    return ioc.replace(".", "[.]")


def refang_ioc(ioc: str) -> str:
    """Refang a defanged IOC back to its original form."""
    return (
        ioc.replace("[.]", ".")
        .replace("[@]", "@")
        .replace("hxxp", "http")
        .replace("[://]", "://")
        .replace("[:]", ":")
    )


def _dedup(items: list[str]) -> list[str]:
    """Deduplicate a list while preserving order."""
    return list(dict.fromkeys(items))


def extract_iocs(text: str, include_defanged: bool = True) -> IOCResult:
    """Extract all IOCs from a text string.

    Args:
        text: Input text to scan.
        include_defanged: Whether to also detect defanged IOCs and refang them.

    Returns:
        IOCResult with all extracted indicators.
    """
    result = IOCResult()

    # Standard IOC extraction
    result.md5 = IOC_PATTERNS["md5"].findall(text)
    result.sha1 = IOC_PATTERNS["sha1"].findall(text)
    result.sha256 = IOC_PATTERNS["sha256"].findall(text)
    result.sha512 = IOC_PATTERNS["sha512"].findall(text)
    result.cves = [c.upper() for c in IOC_PATTERNS["cve"].findall(text)]
    result.domains = IOC_PATTERNS["domain"].findall(text)
    result.urls = IOC_PATTERNS["url"].findall(text)
    result.ipv4 = IOC_PATTERNS["ipv4"].findall(text)
    result.ipv6 = IOC_PATTERNS["ipv6"].findall(text)
    result.mac_addresses = IOC_PATTERNS["mac"].findall(text)
    result.cidr_ranges = IOC_PATTERNS["cidr"].findall(text)
    result.asns = [a.upper() for a in IOC_PATTERNS["asn"].findall(text)]
    result.cpes = IOC_PATTERNS["cpe"].findall(text)
    result.jarm_fingerprints = IOC_PATTERNS["jarm"].findall(text)
    result.mitre_techniques = IOC_PATTERNS["mitre_technique"].findall(text)
    result.mitre_tactics = [t.upper() for t in IOC_PATTERNS["mitre_tactic"].findall(text)]
    result.yara_rules = IOC_PATTERNS["yara_rule"].findall(text)
    result.sigma_rules = IOC_PATTERNS["sigma_rule"].findall(text)
    result.user_agents = IOC_PATTERNS["user_agent"].findall(text)

    # Defanged IOC detection and refanging
    if include_defanged:
        defanged_ips = DEFANGED_IP_PATTERN.findall(text)
        defanged_domains = DEFANGED_DOMAIN_PATTERN.findall(text)
        defanged_emails = DEFANGED_EMAIL_PATTERN.findall(text)
        all_defanged = defanged_ips + defanged_domains + defanged_emails
        result.defanged_iocs = all_defanged

        # Refang and merge into standard fields
        for d in defanged_ips:
            refanged = refang_ioc(d)
            if refanged not in result.ipv4:
                result.ipv4.append(refanged)
        for d in defanged_domains:
            refanged = refang_ioc(d)
            if refanged not in result.domains:
                result.domains.append(refanged)

    # Deduplicate all lists
    for field_name in result.__dict__:
        val = getattr(result, field_name)
        if isinstance(val, list):
            setattr(result, field_name, _dedup(val))

    return result
