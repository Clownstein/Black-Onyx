"""STIX 2.1 export — convert IOCs and enrichment data to STIX bundles."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


class STIXExporter:
    """Export IOCs, enrichment results, and relationships as STIX 2.1 bundles.

    Uses the `stix2` library if available, otherwise generates STIX-compliant
    dicts manually.
    """

    def __init__(self, identity_name: str = "Black Onyx") -> None:
        self._identity_name = identity_name
        self._identity_id = f"identity--{uuid.uuid4()}"

    def _identity_obj(self) -> dict[str, Any]:
        """Create a STIX Identity SDO."""
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": self._identity_id,
            "name": self._identity_name,
            "identity_class": "organization",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
        }

    def _make_indicator(
        self, ioc_type: str, ioc_value: str, labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a STIX Indicator SDO for an IOC."""
        pattern_map = {
            "ip": f"[ipv4-addr:value = '{ioc_value}']",
            "ipv4": f"[ipv4-addr:value = '{ioc_value}']",
            "ipv6": f"[ipv6-addr:value = '{ioc_value}']",
            "domain": f"[domain-name:value = '{ioc_value}']",
            "url": f"[url:value = '{ioc_value}']",
            "md5": f"[file:hashes.MD5 = '{ioc_value}']",
            "sha1": f"[file:hashes.'SHA-1' = '{ioc_value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{ioc_value}']",
            "sha512": f"[file:hashes.'SHA-512' = '{ioc_value}']",
            "hash": f"[file:hashes.'SHA-256' = '{ioc_value}']",
            "email": f"[email-addr:value = '{ioc_value}']",
            "cve": f"[vulnerability:name = '{ioc_value}']",
        }
        pattern = pattern_map.get(ioc_type, f"[x-qdrant-ioc:value = '{ioc_value}']")
        now = datetime.now(timezone.utc).isoformat()
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": ioc_value,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "labels": labels or ["malicious-activity"],
            "created_by_ref": self._identity_id,
        }

    def _make_relationship(
        self, source_ref: str, target_ref: str, rel_type: str,
    ) -> dict[str, Any]:
        """Create a STIX Relationship SRO."""
        now = datetime.now(timezone.utc).isoformat()
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "relationship_type": rel_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "created_by_ref": self._identity_id,
        }

    def _make_attack_pattern(
        self, technique_id: str, technique_name: str,
    ) -> dict[str, Any]:
        """Create a STIX Attack Pattern SDO."""
        now = datetime.now(timezone.utc).isoformat()
        return {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": technique_name,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            }],
            "created_by_ref": self._identity_id,
        }

    def export_bundle(
        self,
        iocs: list[dict[str, Any]],
        enrichments: list[dict[str, Any]] | None = None,
        techniques: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Export a complete STIX 2.1 bundle.

        Args:
            iocs: List of dicts with 'ioc_type' and 'ioc_value' keys.
            enrichments: Optional list of enrichment result dicts.
            techniques: Optional list of dicts with 'technique_id' and 'name' keys.

        Returns:
            STIX 2.1 bundle as a dict (can be serialized to JSON).
        """
        objects: list[dict[str, Any]] = [self._identity_obj()]

        indicators = []
        for ioc in iocs:
            ind = self._make_indicator(
                ioc.get("ioc_type", ""),
                ioc.get("ioc_value", ""),
                ioc.get("labels"),
            )
            indicators.append(ind)
            objects.append(ind)

        # Add attack patterns and relationships
        if techniques:
            for tech in techniques:
                ap = self._make_attack_pattern(
                    tech.get("technique_id", ""),
                    tech.get("name", ""),
                )
                objects.append(ap)
                for ind in indicators:
                    objects.append(
                        self._make_relationship(ind["id"], ap["id"], "indicates")
                    )

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }
