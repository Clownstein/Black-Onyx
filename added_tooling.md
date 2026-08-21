# Black Onyx — Added Tooling for Cyber Defenders

> **Historical design notes.** Much of the gap analysis below has since shipped in the React + FastAPI product. For the current feature set, use [README.md](README.md) and [docs/FEATURES.md](docs/FEATURES.md). Package paths in this file use `src/black_onyx/…`.

## Current State Summary (original research snapshot)

Black Onyx began as a document ingestion and semantic search platform that extracts text, metadata, NER entities, crypto addresses, and social profiles from files, stores them in Qdrant, and exposes a web UI with dashboard, ingestion monitoring, search, collection browsing, and LLM chat with RAG. It already extracted a rich set of OSINT-relevant entities (30+ crypto address types, 35+ social media platforms, emails, phones, IPs, IRC, GPG/SSH keys, invite links, analytics IDs, code snippets).

**Original gap (now largely closed in-product):** the platform stopped at extraction and storage. The suggestions below were the roadmap for enrichment, ATT&CK, STIX/TAXII, Sigma/YARA, graphs, cases/watchlists, and analyst reports.

Research sources: OpenCTI, MISP, Optrasight, ThreatCluster, Cyware, OPTIX, ThreatClaw, Bitsight Darkfeed, CybelAngel, InQuest iocextract, text2ioc, IOCX, OASIS STIX 2.1 spec, OASIS cti-stix-visualization, SigmaForge, yar2sig, hunt.mlab.sh, MITRE ATT&CK Threat Defense Framework, SOC Hub, SOCINT, EclecticIQ, RinjaniAnalytics CTI dashboard, osint-automation-tool, ioc-pivot, IOC Enrichment Pipeline.

---

## 1. IOC Extraction Enhancement

### 1.1 File hash extraction

The current `patterns.py` extracts IPs, emails, crypto addresses, and social profiles but does **not** extract file hashes — one of the most fundamental IOC types. Add MD5, SHA1, SHA256, and SHA512 hash patterns.

**File:** `src/black_onyx/extraction/patterns.py`

```python
# ===========================
# File hash patterns (IOCs)
# ===========================

MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA512_PATTERN = re.compile(r"\b[a-fA-F0-9]{128}\b")

HASH_PATTERNS: dict[str, re.Pattern] = {
    "md5": MD5_PATTERN,
    "sha1": SHA1_PATTERN,
    "sha256": SHA256_PATTERN,
    "sha512": SHA512_PATTERN,
}
```

**DataModel additions** (`src/black_onyx/models/data_model.py`):

```python
# --- IOCs ---
file_hashes_md5: list[str] = Field(default_factory=list)
file_hashes_sha1: list[str] = Field(default_factory=list)
file_hashes_sha256: list[str] = Field(default_factory=list)
file_hashes_sha512: list[str] = Field(default_factory=list)
cve_ids: list[str] = Field(default_factory=list)
domains: list[str] = Field(default_factory=list)
yara_rules: list[str] = Field(default_factory=list)
```

Add these field names to `_LIST_FIELDS`.

### 1.2 CVE ID extraction

```python
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
```

### 1.3 Domain extraction

The current code extracts full URLs but not bare domains. Add a domain pattern that captures `example.com`, `sub.example.co.uk`, etc., using the Public Suffix List for TLD validation.

```python
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)
```

### 1.4 Defanged IOC extraction and refanging

Threat reports routinely "defang" IOCs to prevent accidental clicks (`hxxp://`, `example[.]com`, `192[.]168[.]1[.]1`). Use the [`iocextract`](https://github.com/InQuest/iocextract) library (or port its regex) to extract and optionally refang defanged IOCs.

```python
# pip install iocextract
import iocextract

def extract_defanged_iocs(text: str, refang: bool = True) -> dict[str, list[str]]:
    """Extract defanged IOCs and optionally refang them."""
    return {
        "urls": list(iocextract.extract_urls(text, refang=refang)),
        "ipv4s": list(iocextract.extract_ipv4s(text, refang=refang)),
        "emails": list(iocextract.extract_emails(text, refang=refang)),
        "hashes": list(iocextract.extract_hashes(text)),
        "yara_rules": list(iocextract.extract_yara_rules(text)),
    }
```

Add `iocextract` to `pyproject.toml` optional dependencies under a `[threat]` extra.

### 1.5 YARA rule extraction

YARA rules embedded in threat reports are structured text blocks. The `iocextract` library already handles this, but a standalone pattern also works:

```python
YARA_RULE_PATTERN = re.compile(
    r"(?:import\s+\"[^\"]+\"\s+)?rule\s+\w+\s*(?::\s*\w+\s+)?\{[^}]*\}",
    re.DOTALL,
)
```

---

## 2. IOC Enrichment via External APIs

### 2.1 Enrichment provider abstraction

Create a pluggable enrichment layer modeled after the existing `LLMProvider` abstraction. Each enricher queries an external threat-intelligence API and returns a normalized enrichment record.

**New file:** `src/black_onyx/enrichment/base.py`

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

@dataclass
class EnrichmentResult:
    ioc_value: str
    ioc_type: str  # "ip", "domain", "url", "hash", "email"
    source: str
    malicious: bool = False
    confidence: int = 0  # 0-100
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

class EnrichmentProvider(ABC):
    @abstractmethod
    def enrich(self, ioc_value: str, ioc_type: str) -> Optional[EnrichmentResult]: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def supports_types(self) -> set[str]: ...
```

### 2.2 VirusTotal enrichment

Queries the VirusTotal v3 API for IPs, domains, URLs, and file hashes. Returns multi-engine detection ratio as the confidence score.

**New file:** `src/black_onyx/enrichment/virustotal.py`

```python
import vt
from black_onyx.enrichment.base import EnrichmentProvider, EnrichmentResult

class VirusTotalProvider(EnrichmentProvider):
    def __init__(self, api_key: str):
        self._client = vt.Client(api_key)

    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def supports_types(self) -> set[str]:
        return {"ip", "domain", "url", "hash"}

    def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult | None:
        endpoint_map = {
            "ip": f"/ip_addresses/{ioc_value}",
            "domain": f"/domains/{ioc_value}",
            "hash": f"/files/{ioc_value}",
        }
        endpoint = endpoint_map.get(ioc_type)
        if not endpoint:
            return None
        try:
            obj = self._client.get_object(endpoint)
            stats = obj.last_analysis_stats
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            ratio = malicious / total if total > 0 else 0
            return EnrichmentResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source="virustotal",
                malicious=malicious > 0,
                confidence=int(ratio * 100),
                tags=obj.popularity_tags or [],
                raw={"malicious": malicious, "total": total, "stats": stats},
            )
        except Exception:
            return None
```

### 2.3 AbuseIPDB enrichment

Queries AbuseIPDB for IP abuse confidence scores and report counts.

```python
import httpx

class AbuseIPDBProvider(EnrichmentProvider):
    def __init__(self, api_key: str):
        self._api_key = api_key
        self._base_url = "https://api.abuseipdb.com/api/v2"

    @property
    def name(self) -> str:
        return "abuseipdb"

    @property
    def supports_types(self) -> set[str]:
        return {"ip"}

    def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult | None:
        if ioc_type != "ip":
            return None
        resp = httpx.get(
            f"{self._base_url}/check",
            params={"ipAddress": ioc_value, "maxAgeInDays": 90},
            headers={"Key": self._api_key, "Accept": "application/json"},
        )
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return EnrichmentResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            source="abuseipdb",
            malicious=score >= 50,
            confidence=score,
            tags=[data.get("usageType", "")] if data.get("usageType") else [],
            raw=data,
        )
```

### 2.4 Shodan enrichment

Queries Shodan InternetDB (free, no API key required for the `internetdb` endpoint) for exposed ports, services, and known CVEs on an IP.

```python
class ShodanProvider(EnrichmentProvider):
    def __init__(self, api_key: str | None = None):
        self._api_key = api_key

    @property
    def name(self) -> str:
        return "shodan"

    @property
    def supports_types(self) -> set[str]:
        return {"ip"}

    def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult | None:
        if ioc_type != "ip":
            return None
        # Free InternetDB endpoint — no key required
        resp = httpx.get(f"https://internetdb.shodan.io/{ioc_value}")
        if resp.status_code != 200:
            return None
        data = resp.json()
        vulns = data.get("vulns", [])
        return EnrichmentResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            source="shodan",
            malicious=len(vulns) > 0,
            confidence=min(len(vulns) * 20, 100),
            tags=vulns,
            raw=data,
        )
```

### 2.5 AlienVault OTX enrichment

Queries AlienVault OTX for pulse subscriptions, threat actor associations, and related indicators.

### 2.6 URLhaus (abuse.ch) enrichment

Queries URLhaus for known malware-distribution URLs associated with an IP, domain, or hash.

### 2.7 Composite threat scoring

Aggregate results from all configured enrichers into a single weighted score (0-100), similar to the approach used by `ioc-pivot` and `osint-automation-tool`:

| Signal | Max points |
|--------|-----------|
| VirusTotal malicious detection ratio | 60 |
| AbuseIPDB abuse confidence score | 35 |
| Shodan CVE count | 25 |
| OTX pulse count | 20 |

Verdict thresholds: 75-100 = CRITICAL, 50-74 = HIGH, 25-49 = MEDIUM, 0-24 = LOW.

### 2.8 Configuration

Add to `config.example.yaml`:

```yaml
# --- Threat Intelligence Enrichment ---
enrichment:
  enabled: false
  virustotal:
    api_key_env: "VIRUSTOTAL_API_KEY"
  abuseipdb:
    api_key_env: "ABUSEIPDB_API_KEY"
  shodan:
    api_key_env: "SHODAN_API_KEY"  # optional; InternetDB is keyless
  otx:
    api_key_env: "OTX_API_KEY"
  urlhaus:
    api_key_env: "URLHAUS_API_KEY"  # auth.abuse.ch key
  # Composite score thresholds
  score_thresholds:
    critical: 75
    high: 50
    medium: 25
```

Add `virustotal`, `abuseipdb`, `shodan`, `otx` to `pyproject.toml` under a `[threat]` optional dependency.

---

## 3. MITRE ATT&CK Integration

### 3.1 ATT&CK technique extraction

Extract MITRE ATT&CK technique IDs (e.g., `T1059.001`) from document text using regex, then map them to tactic/technique names using the ATT&CK STIX bundle or a local JSON cache.

```python
ATTACK_TECHNIQUE_PATTERN = re.compile(
    r"\b(T\d{4}(?:\.\d{3})?)\b"
)
ATTACK_TACTIC_PATTERN = re.compile(
    r"\b(TA\d{4})\b"
)
```

**New file:** `src/black_onyx/threat/attack.py`

```python
import json
from pathlib import Path

class AttackMapper:
    """Map ATT&CK technique IDs to tactic names and descriptions."""

    def __init__(self, knowledge_base_path: str | None = None):
        if knowledge_base_path and Path(knowledge_base_path).exists():
            self._kb = json.loads(Path(knowledge_base_path).read_text())
        else:
            self._kb = {}  # empty fallback

    def lookup(self, technique_id: str) -> dict | None:
        return self._kb.get(technique_id)

    def extract_techniques(self, text: str) -> list[dict]:
        from black_onyx.extraction.patterns import ATTACK_TECHNIQUE_PATTERN
        ids = set(ATTACK_TECHNIQUE_PATTERN.findall(text))
        results = []
        for tid in ids:
            info = self.lookup(tid)
            results.append({
                "technique_id": tid,
                "name": info.get("name", "") if info else "",
                "tactic": info.get("tactic", "") if info else "",
                "description": info.get("description", "") if info else "",
            })
        return results
```

### 3.2 ATT&CK coverage heatmap in the web UI

Add an **ATT&CK** view to the web UI that renders the MITRE Enterprise matrix as an interactive heatmap. Each cell is colored by the number of ingested documents referencing that technique. Clicking a cell navigates to a search query for all points containing that technique ID.

Implementation: Use the ATT&CK Navigator layer format (JSON) for the data model, and render the matrix as an HTML table with CSS coloring. Alternatively, use the [`qeeqbox/mitre-visualizer`](https://github.com/qeeqbox/mitre-visualizer) D3.js approach for an interactive network graph of APTs, malware, tools, techniques, and tactics.

### 3.3 DataModel additions

```python
# --- MITRE ATT&CK ---
attack_techniques: list[str] = Field(default_factory=list)  # e.g. ["T1059.001", "T1078"]
attack_tactics: list[str] = Field(default_factory=list)     # e.g. ["TA0002", "TA0006"]
attack_technique_names: list[str] = Field(default_factory=list)
```

---

## 4. STIX 2.1 Export

### 4.1 STIX bundle generation

Export extracted IOCs and entities as STIX 2.1 bundles for sharing with MISP, OpenCTI, Splunk, Microsoft Sentinel, and other STIX-compatible platforms. Use the [`stix2`](https://pypi.org/project/stix2/) Python library.

**New file:** `src/black_onyx/threat/stix_export.py`

```python
from stix2 import (
    Bundle, Indicator, Malware, ThreatActor, AttackPattern,
    Relationship, IPv4Address, DomainName, File, URL, EmailAddress
)
from datetime import datetime, timezone

class STIXExporter:
    """Export Black Onyx payloads as STIX 2.1 bundles."""

    def export_payload(self, payload: dict) -> Bundle:
        objects = []

        # Create indicators for each IOC type
        for ip in payload.get("ip_addresses", []):
            indicator = Indicator(
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                valid_from=datetime.now(timezone.utc),
                labels=["malicious-activity"],
            )
            objects.append(indicator)

        for email in payload.get("emails", []):
            indicator = Indicator(
                pattern=f"[email-addr:value = '{email}']",
                pattern_type="stix",
                valid_from=datetime.now(timezone.utc),
                labels=["malicious-activity"],
            )
            objects.append(indicator)

        for addr in payload.get("bitcoin_address", []):
            indicator = Indicator(
                pattern=f"[x-crypto-addr:value = '{addr}']",
                pattern_type="stix",
                valid_from=datetime.now(timezone.utc),
                labels=["malicious-activity"],
            )
            objects.append(indicator)

        # Map ATT&CK techniques to AttackPattern objects
        for tech_id in payload.get("attack_techniques", []):
            objects.append(AttackPattern(
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": tech_id,
                }],
                name=payload.get("attack_technique_names", [""])[0] or tech_id,
            ))

        # Create relationships
        # ... (indicator indicates attack-pattern, etc.)

        return Bundle(objects=objects)

    def export_collection(self, points: list[dict]) -> Bundle:
        """Export multiple Qdrant points as a single STIX bundle."""
        all_objects = []
        for point in points:
            bundle = self.export_payload(point.get("payload", {}))
            all_objects.extend(bundle.objects)
        return Bundle(objects=all_objects)
```

### 4.2 API endpoint

```
GET  /api/export/stix/{collection}          — Export all points in a collection as STIX 2.1 JSON
POST /api/export/stix                       — Export selected point IDs as STIX 2.1 JSON
GET  /api/export/stix/{collection}/point/{id} — Export a single point as STIX 2.1
```

### 4.3 TAXII 2.1 server (optional, future)

For machine-to-machine sharing, embed a lightweight TAXII 2.1 server that exposes Qdrant collections as TAXII data collections. Partners can poll and subscribe via the TAXII REST API. The [`taxii2-server`](https://pypi.org/project/taxii2-server/) library provides this.

---

## 5. Detection Rule Generation (Sigma / YARA)

### 5.1 Sigma rule generation from IOCs

Generate Sigma detection rules from extracted IOCs so analysts can deploy them directly to Splunk, Elastic, Microsoft Sentinel, QRadar, etc. Use the [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) or the [`pysigma`](https://github.com/SigmaHQ/pysigma) library.

**New file:** `src/black_onyx/threat/sigma_gen.py`

```python
import yaml
from datetime import datetime, timezone

class SigmaGenerator:
    """Generate Sigma detection rules from extracted IOCs."""

    def from_payload(self, payload: dict) -> str:
        """Generate a Sigma rule from a Qdrant payload's IOCs."""
        detection = {}
        for ip in payload.get("ip_addresses", []):
            detection.setdefault("DestinationIp", []).append(ip)
        for email in payload.get("emails", []):
            detection.setdefault("EmailRecipient", []).append(email)
        for domain in payload.get("domains", []):
            detection.setdefault("DestinationHostname", []).append(domain)
        for url in payload.get("urls", []):
            detection.setdefault("CommandLine", []).append(url)

        if not detection:
            return ""

        # Add condition
        condition_parts = [f"1 of {k}" for k in detection.keys()]
        detection["condition"] = " or ".join(condition_parts[:5])

        rule = {
            "title": f"IOCs from {payload.get('source_file', 'unknown')}",
            "status": "experimental",
            "description": f"Auto-generated from Black Onyx payload",
            "date": datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "logsource": {"product": "windows", "service": "sysmon"},
            "detection": detection,
            "tags": [f"attack.{t.lower()}" for t in payload.get("attack_techniques", [])],
            "level": "medium",
        }
        return yaml.dump(rule, default_flow_style=False, sort_keys=False)
```

### 5.2 YARA rule generation from strings

Generate YARA rules from extracted strings, crypto addresses, and known malware indicators.

```python
class YaraGenerator:
    """Generate YARA rules from extracted indicators."""

    def from_payload(self, payload: dict) -> str:
        strings = []
        for addr in payload.get("bitcoin_address", []):
            strings.append(f'$btc = "{addr}"')
        for addr in payload.get("monero_address", []):
            strings.append(f'$xmr = "{addr}"')
        for key in payload.get("gpg_keys", []):
            strings.append(f'$gpg = "{key[:80]}..." ascii')
        for url in payload.get("urls", [])[:10]:
            strings.append(f'$url = "{url}" ascii')

        if not strings:
            return ""

        rule_name = payload.get("source_file", "rule").replace(".", "_")[:50]
        return f"""
rule {rule_name} {{
    strings:
        {chr(10).join("        " + s for s in strings)}
    condition:
        any of them
}}
"""
```

### 5.3 Multi-SIEM backend conversion

Use `pysigma` backends to convert Sigma rules to platform-specific queries:

| Backend | Output format |
|---------|--------------|
| `pysigma-backend-splunk` | Splunk SPL |
| `pysigma-backend-elasticsearch` | Elastic DSL / Lucene |
| `pysigma-backend-qradar` | IBM QRadar AQL |
| `pysigma-backend-microsoft` | Microsoft Sentinel KQL / Defender KQL |

### 5.4 API endpoints

```
POST /api/rules/sigma          — Generate Sigma rule from point IDs or payload
POST /api/rules/yara           — Generate YARA rule from point IDs or payload
POST /api/rules/convert        — Convert a Sigma rule to a SIEM-specific query
                                   (body: {sigma_rule, backend: "splunk"|"elastic"|"kql"|"qradar"})
GET  /api/rules/backends       — List available SIEM backends
```

### 5.5 Web UI integration

Add a **Rules** view to the sidebar:
- Select a collection or specific search results
- Click "Generate Sigma" or "Generate YARA"
- View the generated rule in a code editor (CodeMirror or `<pre>` block)
- Select a SIEM backend and click "Convert" to see the platform-specific query
- Download the rule as a `.yml` (Sigma) or `.yar` (YARA) file

---

## 6. Graph Visualization

### 6.1 Entity relationship graph

Add an interactive force-directed graph that visualizes relationships between extracted entities across all Qdrant points. Nodes are entities (IPs, domains, crypto addresses, emails, social profiles, threat actors, ATT&CK techniques); edges represent co-occurrence in the same document or explicit relationships.

**Technology:** [vis.js](https://visjs.org/) (used by OASIS cti-stix-visualization) or [Cytoscape.js](https://js.cytoscape.org/) (used by Quantickle and SOCINT). Both are browser-only, no server backend needed, and work with Alpine.js.

**New file:** `web/js/components/graph.js`

```javascript
// vis.js network graph for entity relationships
function renderGraph(containerId, nodes, edges) {
    const container = document.getElementById(containerId);
    const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
    const options = {
        nodes: { shape: 'dot', size: 16 },
        edges: { arrows: 'to' },
        physics: { stabilization: { iterations: 200 } },
        interaction: { hover: true, tooltipDelay: 200 },
    };
    return new vis.Network(container, data, options);
}
```

### 6.2 Graph data API endpoint

```
GET  /api/graph/{collection}           — Get all entity nodes and edges in a collection
POST /api/graph                         — Get subgraph for specific point IDs
GET  /api/graph/{collection}/entity/{type}/{value} — Get all points and relationships for a specific entity
```

The backend traverses Qdrant points, extracts all entity fields, and builds a node/edge JSON structure:

```json
{
  "nodes": [
    {"id": "ip:192.168.1.1", "label": "192.168.1.1", "type": "ip", "count": 5},
    {"id": "btc:1abc...", "label": "1abc...", "type": "bitcoin", "count": 2},
    {"id": "email:user@example.com", "label": "user@example.com", "type": "email", "count": 3}
  ],
  "edges": [
    {"from": "ip:192.168.1.1", "to": "btc:1abc...", "label": "co-occurs in page3.html"},
    {"from": "email:user@example.com", "to": "btc:1abc...", "label": "co-occurs in forum_post.txt"}
  ]
}
```

### 6.3 STIX visualization integration

For STIX-exported bundles, integrate the [OASIS cti-stix-visualization](https://github.com/oasis-open/cti-stix-visualization) library (vis.js-based) to render STIX objects and their relationships directly in the browser. This is a drop-in JavaScript module that processes STIX JSON client-side with no server interaction.

### 6.4 ATT&CK network graph

Use the [qeeqbox/mitre-visualizer](https://github.com/qeeqbox/mitre-visualizer) approach: an interactive D3.js network graph showing APTs, malware, tools, techniques, and tactics from the MITRE ATT&CK framework, with search and zoom controls. Overlay the project's own data to show which techniques appear in the ingested documents.

---

## 7. Case Management & Investigation Workflow

### 7.1 Cases

Add a lightweight case management system inspired by TheHive and SOC Hub. A case groups related Qdrant points, IOCs, analyst notes, and timeline events into a single investigation unit.

**New file:** `src/black_onyx/cases/models.py`

```python
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone

class Case(BaseModel):
    case_id: str
    title: str
    description: str = ""
    status: str = "open"  # open, in_progress, closed
    severity: str = "medium"  # low, medium, high, critical
    assigned_to: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    point_ids: list[str] = Field(default_factory=list)  # Qdrant point IDs
    ioc_values: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CaseNote(BaseModel):
    note_id: str
    case_id: str
    author: str = "analyst"
    content: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CaseTimelineEvent(BaseModel):
    event_id: str
    case_id: str
    timestamp: datetime
    description: str
    event_type: str = "observation"  # observation, action, finding
```

### 7.2 Case storage

Store cases in SQLite (already used for chat sessions via `llm/session.py`). Create a `CaseManager` class that mirrors the `SessionManager` pattern.

**New file:** `src/black_onyx/cases/manager.py`

```python
import sqlite3
from pathlib import Path

class CaseManager:
    """SQLite-backed case management."""

    def __init__(self, db_path: str = "cases.db"):
        self._db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT, description TEXT, status TEXT,
                    severity TEXT, assigned_to TEXT, tags TEXT,
                    point_ids TEXT, ioc_values TEXT,
                    created_at TEXT, updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS case_notes (
                    note_id TEXT PRIMARY KEY, case_id TEXT,
                    author TEXT, content TEXT, created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS case_timeline (
                    event_id TEXT PRIMARY KEY, case_id TEXT,
                    timestamp TEXT, description TEXT, event_type TEXT
                );
            """)
```

### 7.3 API endpoints

```
POST   /api/cases                    — Create a case
GET    /api/cases                    — List all cases (filter by status, severity, assignee)
GET    /api/cases/{id}               — Get case detail
PUT    /api/cases/{id}               — Update case (status, severity, assignment, tags)
DELETE /api/cases/{id}               — Delete a case
POST   /api/cases/{id}/points        — Add Qdrant point IDs to a case
POST   /api/cases/{id}/iocs          — Add IOC values to a case
GET    /api/cases/{id}/notes         — List notes for a case
POST   /api/cases/{id}/notes         — Add a note
GET    /api/cases/{id}/timeline      — Get timeline events
POST   /api/cases/{id}/timeline      — Add a timeline event
GET    /api/cases/{id}/graph         — Get entity graph for all points in the case
```

### 7.4 Web UI — Cases view

Add a **Cases** view to the sidebar:
- List of cases as cards with status badge, severity color, assignee, tag chips
- Click a case to open the detail view with:
  - Description and metadata
  - Linked Qdrant points (clickable to view full payload)
  - IOC list with enrichment status (click to enrich)
  - Notes section (add/edit notes)
  - Timeline view (chronological events)
  - Entity graph (vis.js visualization of all entities in the case)
  - "Generate Sigma" / "Generate YARA" / "Export STIX" buttons
  - "Create from Search Results" action on the Search page

---

## 8. Watchlists & Alerting

### 8.1 Watchlists

Allow analysts to define watchlists for specific indicator values (IPs, domains, crypto addresses, emails). When new documents are ingested, any matching indicators are flagged and an alert is generated.

**New file:** `src/black_onyx/threat/watchlist.py`

```python
from pydantic import BaseModel, Field
from typing import Optional

class WatchlistEntry(BaseModel):
    entry_id: str
    ioc_type: str  # "ip", "domain", "email", "crypto", "url", "hash"
    ioc_value: str
    label: str = ""  # e.g., "APT29 C2", "Ransomware wallet"
    created_at: str = ""
    alert_on_match: bool = True

class WatchlistManager:
    """Manage watchlist entries and check new ingestions against them."""

    def __init__(self, db_path: str = "watchlist.db"):
        self._db_path = db_path
        self._init_db()

    def check_payload(self, payload: dict) -> list[dict]:
        """Check a Qdrant payload against the watchlist. Returns matches."""
        matches = []
        # Check all IOC fields in the payload against watchlist entries
        ioc_fields = ["ip_addresses", "emails", "domains", "urls",
                      "bitcoin_address", "ethereum_address", "monero_address"]
        for field in ioc_fields:
            for value in payload.get(field, []):
                entry = self._lookup(value)
                if entry:
                    matches.append({"entry": entry, "field": field, "value": value})
        return matches
```

### 8.2 Alert generation

When a watchlist match is found during ingestion, create an alert record and push a WebSocket event to the UI:

```json
{
  "event": "watchlist_alert",
  "alert_id": "abc123",
  "matched_value": "192.168.1.1",
  "watchlist_label": "APT29 C2",
  "source_file": "darkweb_forum_page7.html",
  "severity": "high"
}
```

### 8.3 API endpoints

```
GET    /api/watchlist                — List all watchlist entries
POST   /api/watchlist                — Add a watchlist entry
DELETE /api/watchlist/{entry_id}     — Remove a watchlist entry
GET    /api/alerts                   — List alerts (filter by severity, status)
PUT    /api/alerts/{alert_id}        — Update alert status (new, acknowledged, resolved)
```

### 8.4 Web UI integration

- **Watchlist** panel in the System or a dedicated **Alerts** view
- Add any extracted IOC to the watchlist directly from search results or point detail view (one-click "Watch this IOC" button)
- Alert badge in the navbar showing count of unacknowledged alerts
- Real-time alert notifications via the existing WebSocket infrastructure

---

## 9. Intelligence Reporting

### 9.1 Report generation

Generate analyst-ready intelligence reports from Qdrant points, cases, or search results. Reports include:
- Executive summary (LLM-generated via the existing RAG chat)
- IOC table with enrichment status
- MITRE ATT&CK technique mapping
- Entity graph image
- Source citations (filename, chunk index, similarity score)
- Recommended actions / detection rules

**New file:** `src/black_onyx/threat/report.py`

```python
class ReportGenerator:
    """Generate intelligence reports from Qdrant data."""

    def __init__(self, rag_engine, enrichment_service, attack_mapper):
        self.rag = rag_engine
        self.enrichment = enrichment_service
        self.attack = attack_mapper

    def generate(self, point_ids: list[str], collection: str,
                 title: str = "Threat Intelligence Report") -> str:
        """Generate a markdown intelligence report."""
        # 1. Fetch points from Qdrant
        # 2. Extract and deduplicate IOCs
        # 3. Enrich IOCs (if enabled)
        # 4. Map ATT&CK techniques
        # 5. Use LLM to generate executive summary
        # 6. Assemble markdown report
        ...
```

### 9.2 Report export formats

- **Markdown** — primary format, viewable in the UI
- **PDF** — via `weasyprint` or `markdown-pdf`
- **HTML** — standalone HTML report with embedded graph visualization
- **STIX 2.1 Bundle** — machine-readable export for sharing

### 9.3 API endpoints

```
POST /api/reports/generate           — Generate a report from point IDs or case ID
GET  /api/reports                    — List saved reports
GET  /api/reports/{id}               — Get report content
GET  /api/reports/{id}/download      — Download report as PDF/HTML/Markdown/STIX
```

---

## 10. Feed Ingestion

### 10.1 RSS/Atom feed ingestion

Ingest threat intelligence from RSS/Atom feeds (CERT advisories, security blogs, vendor bulletins). Each feed item is processed through the existing extraction pipeline (text extraction, chunking, embedding, NER, IOC extraction) and stored in Qdrant.

**New file:** `src/black_onyx/feeds/rss.py`

```python
import feedparser

class RSSFeedIngestor:
    """Ingest threat intelligence from RSS/Atom feeds."""

    def __init__(self, feed_urls: list[str]):
        self._feed_urls = feed_urls

    def fetch_entries(self) -> list[dict]:
        entries = []
        for url in self._feed_urls:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                entries.append({
                    "title": entry.get("title", ""),
                    "body_text": entry.get("summary", "") + entry.get("content", [{}])[0].get("value", ""),
                    "source_file": url,
                    "url": entry.get("link", ""),
                    "published": entry.get("published", ""),
                })
        return entries
```

### 10.2 TAXII feed ingestion

Ingest STIX 2.1 content from TAXII 2.1 servers (ISAC feeds, government feeds, commercial TIPs). Parse STIX objects and store indicators as Qdrant points.

### 10.3 Configuration

```yaml
# --- Feed Ingestion ---
feeds:
  enabled: false
  rss:
    urls:
      - "https://www.cisa.gov/cybersecurity-advisories/all.xml"
      - "https://feeds.feedburner.com/TheHackersNews"
    poll_interval_minutes: 60
  taxii:
    servers:
      - name: "CISA"
        discovery_url: "https://limo.anomali.com/api/v1/taxii/taxii-discovery-service/"
        collection: "CISA"
        api_key_env: "TAXII_API_KEY"
```

### 10.4 API endpoints

```
GET    /api/feeds                     — List configured feeds and their status
POST   /api/feeds/poll                — Manually trigger a feed poll
GET    /api/feeds/{name}/entries      — List entries from a specific feed
```

---

## 11. Analyst Collaboration

### 11.1 Annotations and tags

Allow analysts to annotate any Qdrant point with:
- **Tags** — free-form labels (e.g., "confirmed-malicious", "false-positive", "APT29")
- **Notes** — analyst commentary attached to a specific point
- **Confidence rating** — analyst-assigned confidence level (1-5 stars)
- **Status** — triage status (new, reviewed, escalated, resolved)

Store annotations in SQLite, keyed by `(collection, point_id)`.

### 11.2 Bookmarks

Allow analysts to bookmark points for later review. Bookmarked points appear in a dedicated **Bookmarks** panel in the UI.

### 11.3 API endpoints

```
POST   /api/points/{collection}/{id}/tags      — Add tags to a point
DELETE /api/points/{collection}/{id}/tags/{tag} — Remove a tag
POST   /api/points/{collection}/{id}/notes      — Add a note
GET    /api/points/{collection}/{id}/notes      — List notes
POST   /api/points/{collection}/{id}/bookmark   — Bookmark a point
DELETE /api/points/{collection}/{id}/bookmark   — Remove bookmark
GET    /api/bookmarks                            — List all bookmarks
```

---

## 12. IOC Decay & Freshness Tracking

### 12.1 Decay scoring

IOCs have a limited shelf life. An IP that was malicious 6 months ago may be repurposed. Implement decay scoring based on the time since first observed:

| Age | Confidence multiplier |
|-----|----------------------|
| 0-30 days | 1.0 |
| 30-90 days | 0.8 |
| 90-180 days | 0.5 |
| 180-365 days | 0.3 |
| > 365 days | 0.1 |

Display decay status as a colored badge on each IOC in the UI (green = fresh, yellow = aging, red = stale).

### 12.2 First-seen / last-seen tracking

Track when each IOC was first and last observed across all ingested documents. Store this in a dedicated SQLite table:

```sql
CREATE TABLE ioc_tracking (
    ioc_value TEXT,
    ioc_type TEXT,
    first_seen TEXT,
    last_seen TEXT,
    occurrence_count INTEGER,
    collections TEXT,  -- comma-separated collection names
    PRIMARY KEY (ioc_value, ioc_type)
);
```

---

## 13. Web UI Improvements

### 13.1 New sidebar views

Add the following views to the sidebar navigation in `web/index.html`:

| View | Description |
|------|-------------|
| **IOCs** | Dedicated IOC browser with type filters, enrichment status, decay badges, watchlist toggle |
| **ATT&CK** | MITRE ATT&CK coverage heatmap showing which techniques appear in ingested data |
| **Graph** | Interactive entity relationship graph (vis.js or Cytoscape.js) |
| **Cases** | Case management with linked points, notes, timeline, and entity graph |
| **Rules** | Sigma/YARA rule generation and SIEM query conversion |
| **Alerts** | Watchlist alerts and notification center |
| **Reports** | Intelligence report generation and export |
| **Feeds** | RSS/TAXII feed management and polling |

### 13.2 Enhanced search results

Enhance the existing Search view to:
- Highlight extracted entities (emails, IPs, crypto addresses) in result snippets with color-coded badges
- Show enrichment status inline (VirusTotal badge with detection count, AbuseIPDB score)
- Add "Add to Case" and "Add to Watchlist" buttons on each result
- Add "Generate Sigma" button on search result sets
- Add "Export as STIX" button on search result sets
- Show ATT&CK technique tags as chips on results

### 13.3 IOC dashboard widget

Add an IOC summary widget to the Dashboard:
- Total IOCs by type (pie chart)
- Recently enriched IOCs (table with source, verdict, confidence)
- Watchlist alert count
- Top 10 most common IOCs across collections

### 13.4 Dark theme for analyst workspaces

The UI already has a theme toggle. Ensure the new views (graph, ATT&CK matrix, case detail) are fully styled in both light and dark themes. Analysts typically work in dark theme.

---

## 14. CLI Additions

Extend `src/black_onyx/cli.py` with new subcommands:

```bash
# IOC extraction from a file or directory
black-onyx iocs extract --input /path/to/data --output iocs.json

# Enrich a single IOC
black-onyx enrich --ioc 192.168.1.1 --type ip --all

# Enrich IOCs from a collection
black-onyx enrich-collection --collection all-knowledge --type ip

# Export a collection as STIX 2.1
black-onyx export stix --collection all-knowledge --output bundle.json

# Generate a Sigma rule from a point
black-onyx rules sigma --collection all-knowledge --point-id 12345 --output rule.yml

# Convert a Sigma rule to a SIEM query
black-onyx rules convert --input rule.yml --backend splunk

# Check watchlist for matches in a collection
black-onyx watchlist check --collection all-knowledge

# Generate an intelligence report
black-onyx report --collection all-knowledge --point-ids 1,2,3 --output report.md
```

---

## 15. Dependency Additions

Add to `pyproject.toml`:

```toml
[project.optional-dependencies]
threat = [
    "iocextract>=1.0.0",
    "stix2>=3.0.0",
    "taxii2-client>=2.3.0",
    "pysigma>=0.11.0",
    "pysigma-backend-splunk>=1.0.0",
    "pysigma-backend-elasticsearch>=1.0.0",
    "vt-py>=0.18.0",
    "feedparser>=6.0.0",
]
threat-advanced = [
    "taxii2-server>=2.1.0",   # for hosting a TAXII server
    "weasyprint>=62.0",       # for PDF report export
]
```

---

## 16. Proposed Directory Structure for New Tooling

```
src/black_onyx/
├── enrichment/               # NEW — IOC enrichment
│   ├── __init__.py
│   ├── base.py               # EnrichmentProvider ABC, EnrichmentResult
│   ├── virustotal.py
│   ├── abuseipdb.py
│   ├── shodan.py
│   ├── otx.py
│   ├── urlhaus.py
│   ├── scorer.py             # Composite threat scoring
│   └── factory.py            # Provider factory (like llm/factory.py)
├── threat/                   # NEW — Threat intelligence tooling
│   ├── __init__.py
│   ├── attack.py             # MITRE ATT&CK mapper
│   ├── stix_export.py        # STIX 2.1 bundle generation
│   ├── sigma_gen.py          # Sigma rule generation
│   ├── yara_gen.py           # YARA rule generation
│   ├── watchlist.py          # Watchlist manager
│   ├── report.py             # Intelligence report generator
│   └── ioc_tracker.py        # IOC decay & freshness tracking
├── cases/                    # NEW — Case management
│   ├── __init__.py
│   ├── models.py             # Case, CaseNote, CaseTimelineEvent
│   └── manager.py            # SQLite-backed CaseManager
├── feeds/                    # NEW — Feed ingestion
│   ├── __init__.py
│   ├── rss.py                # RSS/Atom feed ingestor
│   └── taxii.py              # TAXII 2.1 client
└── ... (existing modules)
```

---

## 17. Implementation Priority

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| P0 | IOC extraction (hashes, CVEs, domains, defanged) | Low | High — fundamental capability gap |
| P0 | MITRE ATT&CK technique extraction | Low | High — immediate value for defenders |
| P0 | STIX 2.1 export | Medium | High — enables sharing with MISP/OpenCTI/SIEM |
| P1 | VirusTotal + AbuseIPDB + Shodan enrichment | Medium | High — transforms raw data into actionable intel |
| P1 | Composite threat scoring | Low | High — prioritization for analysts |
| P1 | Sigma rule generation | Medium | High — direct path to SIEM deployment |
| P1 | YARA rule generation | Low | Medium — useful for malware analysts |
| P1 | Entity relationship graph (vis.js) | Medium | High — visual analysis is critical for defenders |
| P1 | ATT&CK coverage heatmap | Medium | High — shows defensive coverage gaps |
| P2 | Case management | Medium | High — investigation workflow |
| P2 | Watchlists & alerting | Medium | High — proactive monitoring |
| P2 | Analyst annotations & tags | Low | Medium — collaboration |
| P2 | IOC decay & freshness tracking | Low | Medium — data quality |
| P2 | Intelligence report generation | Medium | Medium — finished intel product |
| P3 | RSS/Atom feed ingestion | Medium | Medium — continuous monitoring |
| P3 | TAXII feed ingestion | Medium | Medium — community sharing |
| P3 | Multi-SIEM backend conversion | Low | Medium — broader SIEM support |
| P3 | TAXII 2.1 server hosting | High | Low — only needed for outbound sharing |
| P3 | PDF report export | Low | Low — nice-to-have format |

---

## 18. Key Design Principles

1. **Local-first** — All tooling runs locally. No data leaves the analyst's machine unless they explicitly configure an external API (VirusTotal, etc.). This is critical for sensitive dark-web/OSINT data.
2. **Pluggable** — Enrichment providers, feed sources, and export formats follow the same provider abstraction pattern already established by `llm/base.py`. Adding a new source is a single file.
3. **API keys via env vars** — All external API keys are read from environment variables (following the existing `api_key_env` pattern in `config.example.yaml`). Never hardcoded.
4. **No build step** — All new web UI components use vanilla JS or CDN-loaded libraries (vis.js, Cytoscape.js, D3.js). No Node.js, no webpack, no React. Consistent with the existing Alpine.js + Pico.css approach.
5. **SQLite for metadata** — Cases, watchlists, alerts, annotations, and IOC tracking use SQLite, consistent with the existing chat session storage in `llm/session.py`. No additional infrastructure required.
6. **STIX 2.1 native** — All exports follow the OASIS STIX 2.1 standard, ensuring interoperability with MISP, OpenCTI, Splunk, Microsoft Sentinel, and the broader CTI ecosystem.
7. **MITRE ATT&CK aligned** — Technique extraction, coverage heatmaps, and detection rule tagging all reference the ATT&CK framework, which is the de facto standard for defender communication.
8. **Progressive adoption** — Each feature is independently useful. An analyst can use IOC extraction without enrichment, or Sigma generation without case management. No all-or-nothing deployment.
