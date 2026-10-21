"""Map Semgrep / heuristic rule IDs to canonical CWE-NNN strings (CPU hot path).

# MITRE CWE notice
# This module references Common Weakness Enumeration (CWE) identifiers published by
# The MITRE Corporation (https://cwe.mitre.org/). CWE is sponsored by DHS CISA and
# managed by HSSEDI operated by The MITRE Corporation. Copyright © 2006–2026,
# The MITRE Corporation. CWE is a trademark of The MITRE Corporation. Use is subject
# to the CWE Terms of Use: https://cwe.mitre.org/about/termsofuse.html
"""

from __future__ import annotations

import re
from typing import Any

# Practical built-in map: normalized keyword / rule fragment → CWE-NNN
_RULE_FRAGMENT_TO_CWE: dict[str, str] = {
    "sql-injection": "CWE-89",
    "sqli": "CWE-89",
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "cross-site-scripting": "CWE-79",
    "path-traversal": "CWE-22",
    "path_traversal": "CWE-22",
    "directory-traversal": "CWE-22",
    "command-injection": "CWE-78",
    "os-command-injection": "CWE-78",
    "shell-injection": "CWE-78",
    "shell-true": "CWE-78",
    "hardcoded-secret": "CWE-798",
    "hardcoded-password": "CWE-259",
    "hardcoded-credentials": "CWE-798",
    "insecure-deserialization": "CWE-502",
    "pickle-loads": "CWE-502",
    "ssrf": "CWE-918",
    "server-side-request-forgery": "CWE-918",
    "xxe": "CWE-611",
    "xml-external-entity": "CWE-611",
    "csrf": "CWE-352",
    "open-redirect": "CWE-601",
    "insecure-random": "CWE-330",
    "weak-crypto": "CWE-327",
    "weak-hash": "CWE-328",
    "eval-call": "CWE-95",
    "code-injection": "CWE-94",
    "ldap-injection": "CWE-90",
    "xpath-injection": "CWE-643",
    "template-injection": "CWE-1336",
    "ssti": "CWE-1336",
    "buffer-overflow": "CWE-120",
    "use-after-free": "CWE-416",
    "null-pointer": "CWE-476",
    "race-condition": "CWE-362",
    "insecure-tmp": "CWE-377",
    "jwt-none": "CWE-347",
    "auth-bypass": "CWE-287",
    "broken-access": "CWE-284",
    "idor": "CWE-639",
}

_EXACT_RULE_TO_CWE: dict[str, str] = {
    "heuristic.shell-true": "CWE-78",
    "heuristic.eval-call": "CWE-95",
    "heuristic.pickle-loads": "CWE-502",
}

_CWE_IN_TEXT = re.compile(r"CWE[-_\s]?(\d+)", re.IGNORECASE)


def normalize_cwe_id(raw: str | None) -> str | None:
    """Normalize a CWE token to ``CWE-NNN`` or return None if unparseable."""
    if not raw or not str(raw).strip():
        return None
    text = str(raw).strip()
    match = _CWE_IN_TEXT.search(text)
    if match:
        return f"CWE-{int(match.group(1))}"
    if text.isdigit():
        n = int(text)
        if n > 0:
            return f"CWE-{n}"
    return None


def cwe_for_rule_id(rule_id: str | None) -> str | None:
    """Map a Semgrep/heuristic rule_id to a CWE, or extract an embedded CWE."""
    if not rule_id:
        return None
    rid = str(rule_id).strip()
    if not rid:
        return None

    embedded = normalize_cwe_id(rid)
    if embedded and rid.upper().startswith("CWE"):
        return embedded

    exact = _EXACT_RULE_TO_CWE.get(rid.lower())
    if exact:
        return exact

    # Semgrep check_ids are dotted: python.lang.security.audit.sql-injection.foo
    lowered = rid.lower().replace("_", "-")
    fragments = [p for p in re.split(r"[./:\s]+", lowered) if p]
    # Prefer longer / more specific fragments first
    for frag in sorted(fragments, key=len, reverse=True):
        mapped = _RULE_FRAGMENT_TO_CWE.get(frag)
        if mapped:
            return mapped
    # Substring fallback for compound tokens (e.g. avoid-sql-injection-query)
    for frag, cwe in _RULE_FRAGMENT_TO_CWE.items():
        if frag in lowered:
            return cwe
    return embedded


def attach_cwe_to_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a scanner finding dict with ``cwe_id`` / ``cwe_ids`` set."""
    out = dict(finding)
    existing = out.get("cwe_id") or (out.get("cwe_ids") or [None])[0]
    cwe = normalize_cwe_id(str(existing)) if existing else None
    if cwe is None:
        cwe = cwe_for_rule_id(out.get("rule_id"))
    if cwe is None and out.get("message"):
        cwe = normalize_cwe_id(str(out.get("message")))
    if cwe:
        out["cwe_id"] = cwe
        out["cwe_ids"] = list(dict.fromkeys([*(out.get("cwe_ids") or []), cwe]))
    return out


def enrich_scanner_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach CWE metadata to each scanner finding."""
    return [attach_cwe_to_finding(f) for f in findings]


def cwe_contributors(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build advisory contributor entries carrying CWE identifiers."""
    contributors: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in findings:
        cwe = item.get("cwe_id")
        if not cwe:
            continue
        rule_id = str(item.get("rule_id") or "unknown")
        key = (str(cwe), rule_id)
        if key in seen:
            continue
        seen.add(key)
        contributors.append(
            {
                "type": "cwe",
                "cwe_id": cwe,
                "rule_id": rule_id,
                "scanner": item.get("scanner"),
                "path": item.get("path"),
                "contribution": 1.0,
            }
        )
    return contributors


def collect_cwe_ids(findings: list[dict[str, Any]]) -> list[str]:
    """Unique ordered CWE-NNN list from enriched scanner findings."""
    out: list[str] = []
    seen: set[str] = set()
    for item in findings:
        cwe = item.get("cwe_id")
        if isinstance(cwe, str) and cwe not in seen:
            seen.add(cwe)
            out.append(cwe)
    return out
