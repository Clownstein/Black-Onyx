"""Build ThreatIntelMatchResult from store hits."""

from __future__ import annotations

from typing import Any

from black_onyx_contracts.threat_intel import ThreatIntelMatch, ThreatIntelMatchResult

from threat_intel_service.models import Indicator


_TLP_RANK = {"clear": 0, "white": 0, "green": 1, "amber": 2, "red": 3}


def indicator_to_match(row: Indicator) -> ThreatIntelMatch:
    return ThreatIntelMatch(
        id=row.indicator_id,
        type=row.observable_type,
        value=row.observable_value,
        confidence=int(row.confidence),
        source=row.source,
        tlp=row.tlp,
        mitre_techniques=list(row.mitre_techniques or []),
    )


def build_match_result(rows: list[Indicator]) -> ThreatIntelMatchResult:
    matches = [indicator_to_match(r) for r in rows]
    campaigns: list[str] = []
    seen: set[str] = set()
    for r in rows:
        for c in r.campaigns or []:
            if c not in seen:
                seen.add(c)
                campaigns.append(c)
    tlp: str | None = None
    best = -1
    for r in rows:
        if not r.tlp:
            continue
        rank = _TLP_RANK.get(str(r.tlp).lower(), -1)
        if rank > best:
            best = rank
            tlp = r.tlp
    return ThreatIntelMatchResult(matches=matches, campaigns=campaigns, tlp=tlp)


def match_result_to_dict(result: ThreatIntelMatchResult) -> dict[str, Any]:
    return result.model_dump(mode="json")
