"""Build entity relationship graphs for visualization (vis.js / Cytoscape.js / D3.js)."""

from __future__ import annotations

from typing import Any, Iterable


class GraphBuilder:
    """Build node/edge graphs from Qdrant payloads, IOCs, and ATT&CK data.

    Produces JSON data compatible with vis.js, Cytoscape.js, or D3.js
    force-directed graphs.
    """

    #: payload field -> (node type, relationship, default-on)
    ENTITY_FIELDS: dict[str, tuple[str, str, bool]] = {
        "ip_addresses": ("ip", "contains", True),
        "domains": ("domain", "contains", True),
        "urls": ("url", "contains", True),
        "emails": ("email", "contains", True),
        "sha256_hashes": ("hash", "contains", True),
        "sha1_hashes": ("hash", "contains", True),
        "md5_hashes": ("hash", "contains", True),
        "sha512_hashes": ("hash", "contains", True),
        "cve_ids": ("cve", "references", True),
        "mitre_techniques": ("technique", "uses_technique", True),
        "mitre_tactics": ("tactic", "uses_tactic", False),
        "bitcoin_address": ("crypto", "contains", True),
        "ethereum_address": ("crypto", "contains", True),
        "monero_address": ("crypto", "contains", True),
        "litecoin_address": ("crypto", "contains", True),
        "zcash_address": ("crypto", "contains", True),
        "asns": ("asn", "contains", True),
        "cidr_ranges": ("cidr", "contains", True),
        "mac_addresses": ("mac", "contains", False),
        "user_agents": ("user_agent", "contains", False),
        "cpes": ("cpe", "references", False),
        "jarm_fingerprints": ("jarm", "contains", False),
        "social_profiles": ("social", "contains", False),
        "phone_numbers": ("phone", "contains", False),
        "person_name": ("person", "mentions", False),
        "business_name": ("organization", "mentions", False),
        "username": ("username", "mentions", False),
        "code_languages": ("language", "mentions", False),
    }

    @classmethod
    def entity_types(cls) -> list[dict[str, Any]]:
        """Selectable entity node types with the state they start in."""
        seen: dict[str, bool] = {}
        for node_type, _relationship, default_on in cls.ENTITY_FIELDS.values():
            seen[node_type] = seen.get(node_type, False) or default_on
        return [{"type": name, "default": enabled} for name, enabled in seen.items()]

    @staticmethod
    def document_label(payload: dict[str, Any]) -> str:
        """Human-readable label for the document node behind a payload."""
        title = (payload.get("title") or "").strip()
        if title:
            return title[:80]
        source = str(payload.get("source_file") or "unknown")
        name = source.split("/")[-1].split("\\")[-1]
        urls = payload.get("urls") or []
        if len(name) > 24 and not name.count(".") and urls:
            return str(urls[0])[:80]
        return name or source

    @staticmethod
    def _entity_label(node_type: str, value: str) -> str:
        if node_type == "hash" and len(value) > 20:
            return f"{value[:16]}…"
        if node_type in ("url", "social") and len(value) > 50:
            return f"{value[:50]}…"
        if len(value) > 60:
            return f"{value[:60]}…"
        return value

    def build_from_payloads(
        self,
        payloads: list[dict[str, Any]],
        entity_types: Iterable[str] | None = None,
        max_nodes: int | None = None,
    ) -> dict[str, Any]:
        """Build a relationship graph from Qdrant point payloads.

        Document nodes connect to every extracted entity they contain. Repeated
        entities across chunks collapse into a single node, and repeated links
        collapse into a single weighted edge.

        Args:
            payloads: Qdrant payload dicts.
            entity_types: Restrict to these node types; ``None`` allows all.
            max_nodes: Stop adding new nodes past this count.

        Returns:
            Dict with ``nodes``, ``edges``, ``type_counts``, and ``truncated``.
        """
        allowed = set(entity_types) if entity_types is not None else None
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        truncated = False

        def add_node(node_id: str, label: str, node_type: str, extra: dict | None = None) -> bool:
            nonlocal truncated
            existing = nodes.get(node_id)
            if existing is not None:
                existing["count"] = existing.get("count", 1) + 1
                return True
            if max_nodes is not None and len(nodes) >= max_nodes:
                truncated = True
                return False
            node = {"id": node_id, "label": label, "type": node_type, "count": 1}
            if extra:
                node.update(extra)
            nodes[node_id] = node
            return True

        def add_edge(source: str, target: str, relationship: str) -> None:
            key = (source, target, relationship)
            existing = edges.get(key)
            if existing is not None:
                existing["weight"] = existing.get("weight", 1) + 1
                return
            edges[key] = {
                "source": source,
                "target": target,
                "relationship": relationship,
                "weight": 1,
            }

        for payload in payloads:
            source_file = str(payload.get("source_file") or "unknown")
            document_id = f"doc::{source_file}"
            document_extra: dict[str, Any] = {}
            for key in ("collection", "indexed_at", "point_id"):
                if payload.get(key):
                    document_extra[key] = payload[key]
            # Documents are the hub nodes every entity attaches to, so they are
            # always present regardless of the entity-type selection.
            if not add_node(document_id, self.document_label(payload), "document", document_extra):
                continue

            for field, (node_type, relationship, _default) in self.ENTITY_FIELDS.items():
                if allowed is not None and node_type not in allowed:
                    continue
                values = payload.get(field) or []
                if isinstance(values, str):
                    values = [values]
                for raw in values:
                    value = str(raw).strip()
                    if not value:
                        continue
                    if not add_node(value, self._entity_label(node_type, value), node_type):
                        continue
                    add_edge(document_id, value, relationship)

        type_counts: dict[str, int] = {}
        for node in nodes.values():
            type_counts[node["type"]] = type_counts.get(node["type"], 0) + 1

        return {
            "nodes": list(nodes.values()),
            "edges": list(edges.values()),
            "type_counts": type_counts,
            "truncated": truncated,
        }

    def build_attack_graph(
        self, technique_ids: list[str], attack_mapper: Any,
    ) -> dict[str, Any]:
        """Build a MITRE ATT&CK network graph (techniques <-> tactics <-> groups)."""
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        seen: set[str] = set()

        def add_node(node_id: str, label: str, node_type: str) -> None:
            if node_id not in seen:
                nodes.append({"id": node_id, "label": label, "type": node_type})
                seen.add(node_id)

        for tid in technique_ids:
            tech = attack_mapper.get_technique(tid) or {}
            add_node(tid, tech.get("name", tid), "technique")
            for tactic in tech.get("tactic", []):
                add_node(tactic, tactic.replace("-", " ").title(), "tactic")
                edges.append({"source": tid, "target": tactic, "relationship": "belongs_to"})

        return {"nodes": nodes, "edges": edges}
