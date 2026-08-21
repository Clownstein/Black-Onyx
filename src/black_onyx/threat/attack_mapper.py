"""MITRE ATT&CK framework integration — technique mapping and heatmap generation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Embedded minimal fallback mapping of common techniques to tactics
_EMBEDDED_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": ["execution"], "platforms": ["Windows", "Linux", "macOS"]},
    "T1059.001": {"name": "PowerShell", "tactic": ["execution"], "platforms": ["Windows"]},
    "T1059.003": {"name": "Windows Command Shell", "tactic": ["execution"], "platforms": ["Windows"]},
    "T1059.004": {"name": "Unix Shell", "tactic": ["execution"], "platforms": ["Linux", "macOS"]},
    "T1071": {"name": "Application Layer Protocol", "tactic": ["command-and-control"], "platforms": []},
    "T1071.001": {"name": "Web Protocols", "tactic": ["command-and-control"], "platforms": []},
    "T1566": {"name": "Phishing", "tactic": ["initial-access"], "platforms": []},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": ["initial-access"], "platforms": []},
    "T1566.002": {"name": "Spearphishing Link", "tactic": ["initial-access"], "platforms": []},
    "T1053": {"name": "Scheduled Task/Job", "tactic": ["execution", "persistence", "privilege-escalation"], "platforms": ["Windows", "Linux", "macOS"]},
    "T1053.005": {"name": "Scheduled Task", "tactic": ["execution", "persistence", "privilege-escalation"], "platforms": ["Windows"]},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": ["persistence", "privilege-escalation"], "platforms": ["Windows"]},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": ["persistence", "privilege-escalation"], "platforms": ["Windows"]},
    "T1005": {"name": "Data from Local System", "tactic": ["collection"], "platforms": []},
    "T1119": {"name": "Automated Collection", "tactic": ["collection"], "platforms": []},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": ["exfiltration"], "platforms": []},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": ["exfiltration"], "platforms": []},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": ["impact"], "platforms": []},
    "T1490": {"name": "Inhibit System Recovery", "tactic": ["impact"], "platforms": ["Windows"]},
    "T1087": {"name": "Account Discovery", "tactic": ["discovery"], "platforms": []},
    "T1083": {"name": "File and Directory Discovery", "tactic": ["discovery"], "platforms": []},
    "T1018": {"name": "Remote System Discovery", "tactic": ["discovery"], "platforms": []},
    "T1046": {"name": "Network Service Discovery", "tactic": ["discovery"], "platforms": []},
    "T1049": {"name": "System Network Connections", "tactic": ["discovery"], "platforms": []},
    "T1057": {"name": "Process Discovery", "tactic": ["discovery"], "platforms": []},
    "T1069": {"name": "Permission Groups Discovery", "tactic": ["discovery"], "platforms": []},
    "T1082": {"name": "System Information Discovery", "tactic": ["discovery"], "platforms": []},
    "T1213": {"name": "Data from Information Repositories", "tactic": ["collection"], "platforms": []},
    "T1078": {"name": "Valid Accounts", "tactic": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"], "platforms": []},
    "T1133": {"name": "External Remote Services", "tactic": ["initial-access", "persistence"], "platforms": []},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": ["initial-access"], "platforms": []},
    "T1110": {"name": "Brute Force", "tactic": ["credential-access"], "platforms": []},
    "T1003": {"name": "OS Credential Dumping", "tactic": ["credential-access"], "platforms": []},
    "T1003.001": {"name": "LSASS Memory", "tactic": ["credential-access"], "platforms": ["Windows"]},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": ["credential-access", "defense-evasion"], "platforms": ["Windows"]},
    "T1098": {"name": "Account Manipulation", "tactic": ["persistence", "privilege-escalation"], "platforms": []},
    "T1136": {"name": "Create Account", "tactic": ["persistence"], "platforms": []},
    "T1071.004": {"name": "DNS", "tactic": ["command-and-control"], "platforms": []},
    "T1572": {"name": "Protocol Tunneling", "tactic": ["command-and-control"], "platforms": []},
    "T1573": {"name": "Encrypted Channel", "tactic": ["command-and-control"], "platforms": []},
    "T1090": {"name": "Proxy", "tactic": ["command-and-control", "defense-evasion"], "platforms": []},
    "T1090.002": {"name": "External Proxy", "tactic": ["command-and-control", "defense-evasion"], "platforms": []},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": ["command-and-control"], "platforms": []},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": ["defense-evasion"], "platforms": []},
    "T1036": {"name": "Masquerading", "tactic": ["defense-evasion"], "platforms": []},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": ["defense-evasion"], "platforms": []},
    "T1204": {"name": "User Execution", "tactic": ["execution"], "platforms": []},
    "T1204.002": {"name": "Malicious File", "tactic": ["execution"], "platforms": []},
    "T1055": {"name": "Process Injection", "tactic": ["defense-evasion", "privilege-escalation"], "platforms": []},
    "T1112": {"name": "Modify Registry", "tactic": ["defense-evasion"], "platforms": ["Windows"]},
    "T1562": {"name": "Impair Defenses", "tactic": ["defense-evasion"], "platforms": []},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": ["defense-evasion"], "platforms": []},
    "T1070": {"name": "Indicator Removal", "tactic": ["defense-evasion"], "platforms": []},
    "T1070.004": {"name": "File Deletion", "tactic": ["defense-evasion"], "platforms": []},
    "T1620": {"name": "Reflective Code Loading", "tactic": ["defense-evasion"], "platforms": []},
    "T1047": {"name": "WMI", "tactic": ["execution"], "platforms": ["Windows"]},
    "T1106": {"name": "Native API", "tactic": ["execution"], "platforms": []},
    "T1129": {"name": "Shared Modules", "tactic": ["execution"], "platforms": []},
    "T1059.009": {"name": "Cloud API", "tactic": ["execution"], "platforms": ["IaaS"]},
    "T1534": {"name": "Internal Spearphishing", "tactic": ["lateral-movement"], "platforms": []},
    "T1021": {"name": "Remote Services", "tactic": ["lateral-movement"], "platforms": []},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": ["lateral-movement"], "platforms": ["Windows"]},
    "T1021.006": {"name": "SSH", "tactic": ["lateral-movement"], "platforms": ["Linux", "macOS"]},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": ["lateral-movement"], "platforms": []},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": ["lateral-movement", "defense-evasion"], "platforms": []},
    "T1550.003": {"name": "Pass the Ticket", "tactic": ["lateral-movement", "defense-evasion"], "platforms": ["Windows"]},
    "T1550.001": {"name": "Application Access Token", "tactic": ["lateral-movement", "defense-evasion"], "platforms": []},
    "T1528": {"name": "Steal Application Access Token", "tactic": ["credential-access"], "platforms": []},
    "T1555": {"name": "Credentials from Password Stores", "tactic": ["credential-access"], "platforms": []},
    "T1555.003": {"name": "Credentials from Web Browsers", "tactic": ["credential-access"], "platforms": []},
    "T1539": {"name": "Steal Web Session Cookie", "tactic": ["credential-access"], "platforms": []},
    "T1505": {"name": "Server Software Component", "tactic": ["persistence"], "platforms": []},
    "T1505.003": {"name": "Web Shell", "tactic": ["persistence"], "platforms": []},
    "T1195": {"name": "Supply Chain Compromise", "tactic": ["initial-access"], "platforms": []},
    "T1195.002": {"name": "Compromise Software Supply Chain", "tactic": ["initial-access"], "platforms": []},
    "T1199": {"name": "Trusted Relationship", "tactic": ["initial-access"], "platforms": []},
    "T1134": {"name": "Access Token Manipulation", "tactic": ["privilege-escalation", "defense-evasion"], "platforms": ["Windows"]},
    "T1134.001": {"name": "Token Impersonation/Theft", "tactic": ["privilege-escalation", "defense-evasion"], "platforms": ["Windows"]},
    "T1134.002": {"name": "Create Process with Token", "tactic": ["privilege-escalation", "defense-evasion"], "platforms": ["Windows"]},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": ["privilege-escalation", "defense-evasion"], "platforms": []},
    "T1548.002": {"name": "Bypass User Account Control", "tactic": ["privilege-escalation", "defense-evasion"], "platforms": ["Windows"]},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": ["privilege-escalation"], "platforms": []},
    "T1211": {"name": "Exploitation for Defense Evasion", "tactic": ["defense-evasion"], "platforms": []},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": ["lateral-movement"], "platforms": []},
    "T1064": {"name": "Scripting", "tactic": ["execution", "defense-evasion"], "platforms": []},
    "T1086": {"name": "PowerShell", "tactic": ["execution", "defense-evasion"], "platforms": ["Windows"]},
    "T1127": {"name": "Trusted Developer Utilities Proxy Execution", "tactic": ["defense-evasion"], "platforms": ["Windows"]},
    "T1127.001": {"name": "MSBuild", "tactic": ["defense-evasion"], "platforms": ["Windows"]},
    "T1033": {"name": "System Owner/User Discovery", "tactic": ["discovery"], "platforms": []},
    "T1069.001": {"name": "Local Groups", "tactic": ["discovery"], "platforms": ["Windows"]},
    "T1069.002": {"name": "Domain Groups", "tactic": ["discovery"], "platforms": ["Windows"]},
    "T1087.001": {"name": "Local Account", "tactic": ["discovery"], "platforms": []},
    "T1087.002": {"name": "Domain Account", "tactic": ["discovery"], "platforms": []},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": ["discovery"], "platforms": []},
    "T1016.001": {"name": "Internet Connection Discovery", "tactic": ["discovery"], "platforms": []},
}


class AttackMapper:
    """Maps MITRE ATT&CK technique IDs to tactics, groups, and mitigations.

    Loads ATT&CK data from a local JSON cache (downloaded on first use from
    https://github.com/mitre/cti) or from an embedded fallback.
    """

    def __init__(self, data_dir: str | None = None) -> None:
        self._data_dir = Path(data_dir) if data_dir else None
        self._techniques: dict[str, dict[str, Any]] = {}
        self._tactics: dict[str, dict[str, Any]] = {}
        self._groups: dict[str, dict[str, Any]] = {}
        self._mitigations: dict[str, dict[str, Any]] = {}
        self._loaded = False

    def _load_data(self) -> None:
        """Load ATT&CK data from cache or use embedded fallback."""
        if self._loaded:
            return
        cache_path = self._data_dir / "mitre_attack.json" if self._data_dir else None
        if cache_path and cache_path.exists():
            try:
                with open(cache_path) as f:
                    data = json.load(f)
                self._parse_attack_data(data)
                self._loaded = True
                logger.info(f"Loaded ATT&CK data from {cache_path}")
                return
            except Exception as e:
                logger.warning(f"Failed to load ATT&CK cache: {e}, using embedded fallback")
        # Use embedded fallback
        self._techniques = dict(_EMBEDDED_TECHNIQUES)
        self._loaded = True
        logger.info("Using embedded ATT&CK fallback data")

    def _parse_attack_data(self, data: dict) -> None:
        """Parse STIX/JSON ATT&CK data into internal dicts."""
        for obj in data.get("objects", []):
            obj_type = obj.get("type", "")
            if obj_type == "attack-pattern":
                tech_id = self._extract_external_id(obj)
                if tech_id:
                    self._techniques[tech_id] = {
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "tactic": self._extract_kill_chain_phases(obj),
                        "url": self._get_external_url(obj),
                        "platforms": obj.get("x_mitre_platforms", []),
                        "detection": obj.get("x_mitre_detection", ""),
                    }
            elif obj_type == "x-mitre-tactic":
                tac_id = self._extract_external_id(obj)
                if tac_id:
                    self._tactics[tac_id] = {
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                    }
            elif obj_type == "intrusion-set":
                self._groups[obj.get("name", "")] = {
                    "aliases": obj.get("aliases", []),
                    "description": obj.get("description", ""),
                    "techniques": [],
                }
            elif obj_type == "course-of-action":
                mit_id = self._extract_external_id(obj)
                if mit_id:
                    self._mitigations[mit_id] = {
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                    }

    @staticmethod
    def _extract_external_id(obj: dict) -> str | None:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    @staticmethod
    def _get_external_url(obj: dict) -> str:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("url", "")
        return ""

    @staticmethod
    def _extract_kill_chain_phases(obj: dict) -> list[str]:
        return [phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", [])]

    def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Get details for a specific technique."""
        self._load_data()
        return self._techniques.get(technique_id)

    def get_tactics_for_technique(self, technique_id: str) -> list[str]:
        """Get the tactic(s) a technique belongs to."""
        tech = self.get_technique(technique_id)
        if tech:
            return tech.get("tactic", [])
        return []

    def extract_techniques_from_text(self, text: str) -> list[dict[str, Any]]:
        """Find all ATT&CK technique IDs in text and return enriched details."""
        from black_onyx.extraction.patterns import MITRE_TECHNIQUE_PATTERN
        self._load_data()
        ids = list(dict.fromkeys(MITRE_TECHNIQUE_PATTERN.findall(text)))
        results = []
        for tid in ids:
            tech = self._techniques.get(tid)
            if tech:
                results.append({"technique_id": tid, **tech})
            else:
                results.append({"technique_id": tid, "name": "Unknown", "tactic": []})
        return results

    def generate_heatmap_data(self, technique_ids: list[str]) -> dict[str, Any]:
        """Generate data for an ATT&CK heatmap/matrix visualization.

        Returns a stable list shape shared by the API and React client.
        """
        self._load_data()
        tactic_map: dict[str, list[dict[str, Any]]] = {}
        for tid in technique_ids:
            tech = self._techniques.get(tid)
            if tech:
                for tactic in tech.get("tactic", ["Unknown"]):
                    if tactic not in tactic_map:
                        tactic_map[tactic] = []
                    tactic_map[tactic].append({
                        "technique_id": tid,
                        "name": tech["name"],
                        "count": technique_ids.count(tid),
                    })
        return {
            "tactics": [
                {"tactic": tactic, "techniques": techniques}
                for tactic, techniques in sorted(tactic_map.items())
            ]
        }

    def generate_network_graph(self, technique_ids: list[str]) -> dict[str, Any]:
        """Generate node/edge data for a threat actor ↔ technique network graph."""
        self._load_data()
        nodes = []
        edges = []
        seen_nodes = set()

        def add_node(node_id: str, label: str, node_type: str) -> None:
            if node_id not in seen_nodes:
                nodes.append({"id": node_id, "label": label, "type": node_type})
                seen_nodes.add(node_id)

        for tid in technique_ids:
            tech = self._techniques.get(tid, {})
            add_node(tid, tech.get("name", tid), "technique")
            # Find groups that use this technique
            for group_name, group_data in self._groups.items():
                if tid in group_data.get("techniques", []):
                    add_node(group_name, group_name, "group")
                    edges.append({"source": group_name, "target": tid})

        return {"nodes": nodes, "edges": edges}

    def search_techniques(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Search techniques by name or description."""
        self._load_data()
        query_lower = query.lower()
        results = []
        for tid, tech in self._techniques.items():
            if (query_lower in tech.get("name", "").lower() or
                query_lower in tech.get("description", "").lower()):
                results.append({"technique_id": tid, **tech})
                if len(results) >= limit:
                    break
        return results
