"""Generate fine-tune tool-use examples (OpenAI messages + tool_calls JSONL)."""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent

SYSTEM = (
    "You are a Black Onyx SOC analyst assistant. Use Black Onyx MCP tools to investigate "
    "threats, draft cases/rules, and query detection. Prefer read-only tools first. "
    "Mutating tools require confirm=true only when the analyst explicitly asks to apply "
    "changes. Never approve SOAR containment. Never invent detection JWTs or browser keys. "
    "After tools return, summarize findings in concise analyst language with IDs cited."
)

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "black_onyx_evidence_search",
            "description": "Semantic evidence search over Qdrant collections; optional local image CLIP search.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "collection": {"type": "string", "default": "all-knowledge"},
                    "limit": {"type": "integer", "default": 10},
                    "score_threshold": {"type": "number", "default": 0.0},
                    "image_path": {"type": "string", "description": "Optional local image path for CLIP search"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_ioc_enrich",
            "description": "Extract IOCs from text and enrich via TIP providers; optional STIX export.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "iocs": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "ioc_type": {"type": "string"},
                                "ioc_value": {"type": "string"},
                            },
                        },
                    },
                    "export_stix": {"type": "boolean", "default": False},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_case_assist",
            "description": "List/get/create/update cases, attach notes/points/IOCs, or promote triage (confirm=true for mutations).",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "get", "list", "create_draft", "update", "add_note",
                            "add_point", "add_ioc", "delete", "promote",
                        ],
                    },
                    "case_id": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "priority": {"type": "string"},
                    "note": {"type": "string"},
                    "confirm": {"type": "boolean", "default": False},
                    "promote_kind": {
                        "type": "string",
                        "enum": ["alert", "detection", "webhook", "detection_incident", ""],
                    },
                    "alert_id": {"type": "string"},
                    "detection_key": {"type": "string"},
                    "incident_id": {"type": "string"},
                },
                "required": ["action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_rule_draft",
            "description": "Generate Sigma or YARA rule text from IOC JSON (generate-only; no telemetry execution).",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_type": {"type": "string", "enum": ["sigma", "yara"]},
                    "iocs": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "level": {"type": "string"},
                    "rule_name": {"type": "string"},
                },
                "required": ["rule_type", "iocs"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_attack_map",
            "description": "Extract ATT&CK techniques from text and map org coverage/heatmap.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "technique_ids": {"type": "array", "items": {"type": "string"}},
                    "coverage_range": {"type": "string", "default": "30d"},
                    "include_graph": {"type": "boolean", "default": True},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_hunt",
            "description": "Run OpenSearch, federated, or vector hunt via detection BFF.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "mode": {"type": "string", "enum": ["search", "federated", "vector"], "default": "search"},
                    "size": {"type": "integer", "default": 50},
                    "limit": {"type": "integer", "default": 25},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_incident_brief",
            "description": "Build an InvestigationAssist markdown brief from an incident and linked findings.",
            "parameters": {
                "type": "object",
                "properties": {"incident_id": {"type": "string"}},
                "required": ["incident_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_asset_context",
            "description": "Resolve asset by id/hostname/IP; return topology, baseline, related incidents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset_id": {"type": "string"},
                    "hostname": {"type": "string"},
                    "ip_address": {"type": "string"},
                    "window_days": {"type": "integer", "default": 7},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_response_draft",
            "description": "Draft a response-orchestrator request (suggest-only). Never approves actions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string"},
                    "playbook_id": {"type": "string"},
                    "action": {"type": "string", "default": "execute"},
                    "dry_run": {"type": "boolean", "default": True},
                    "confirm": {"type": "boolean", "default": False},
                },
                "required": ["incident_id", "playbook_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_ti_match",
            "description": "Match observables via threat-intel-service; optional TIP sync publish with confirm+case_id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "observables": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string"},
                                "value": {"type": "string"},
                            },
                        },
                    },
                    "mode": {"type": "string", "enum": ["exact", "semantic"], "default": "exact"},
                    "publish": {"type": "boolean", "default": False},
                    "confirm": {"type": "boolean", "default": False},
                    "case_id": {"type": "string"},
                },
                "required": ["observables"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_watchlist_decay",
            "description": "IOC decay summary or propose watchlist adds (confirm=true to mutate).",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["summary", "list_watchlists", "propose_add"]},
                    "watchlist_id": {"type": "string"},
                    "watchlist_name": {"type": "string"},
                    "items": {"type": "array", "items": {"type": "object"}},
                    "confirm": {"type": "boolean", "default": False},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_misp_taxii_draft",
            "description": "Draft or publish MISP/TAXII packages from case IOCs (confirm=true to publish).",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": ["misp", "taxii"]},
                    "case_id": {"type": "string"},
                    "collection_id": {"type": "string"},
                    "iocs": {"type": "array", "items": {"type": "object"}},
                    "info": {"type": "string"},
                    "confirm": {"type": "boolean", "default": False},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_connector_pulse",
            "description": "Connector health + recent detections / triage pulse.",
            "parameters": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "default": 20}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_feed_digest",
            "description": "List feeds and optionally poll (poll requires confirm=true).",
            "parameters": {
                "type": "object",
                "properties": {
                    "feed_name": {"type": "string"},
                    "poll": {"type": "boolean", "default": False},
                    "confirm": {"type": "boolean", "default": False},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "black_onyx_model_ops",
            "description": "Read-only model-gateway and training-orchestrator readiness.",
            "parameters": {
                "type": "object",
                "properties": {"job_id": {"type": "string"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "passive_dns_whois",
            "description": "Structured DNS + WHOIS pivots for a domain (ingestible fields).",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "query_types": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "url_screenshot_sandbox",
            "description": "Lab-gated URL fetch/screenshot (disabled unless sandbox env enabled); SSRF-hardened.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_bytes": {"type": "integer", "default": 65536},
                    "case_id": {"type": "string"},
                    "confirm": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "certificate_transparency",
            "description": "Query CT logs (crt.sh) for domain pivots.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "limit": {"type": "integer", "default": 25},
                },
                "required": ["domain"],
            },
        },
    },
]


def ex(
    example_id: str,
    tool: str,
    user: str,
    arguments: dict,
    tool_result: dict | str,
    assistant_final: str,
    *,
    tags: list[str] | None = None,
) -> dict:
    call_id = f"call_{example_id}"
    return {
        "id": example_id,
        "tool": tool,
        "tags": tags or [tool],
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": tool,
                            "arguments": json.dumps(arguments, separators=(",", ":")),
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": call_id,
                "name": tool,
                "content": tool_result if isinstance(tool_result, str) else json.dumps(tool_result),
            },
            {"role": "assistant", "content": assistant_final},
        ],
        "tools": TOOLS,
    }


EXAMPLES: list[dict] = [
    ex(
        "evidence_search_01",
        "black_onyx_evidence_search",
        "Search our evidence for Cobalt Strike beaconing notes from the last campaign.",
        {"query": "Cobalt Strike beaconing C2", "collection": "all-knowledge", "limit": 5},
        {
            "mode": "text",
            "total": 2,
            "citations": [
                {"point_id": "pt-a1", "collection": "all-knowledge", "score": 0.91, "snippet": "Beacon sleep 60s to 185.199.108.153"},
                {"point_id": "pt-a2", "collection": "all-knowledge", "score": 0.84, "snippet": "CS malleable profile notes"},
            ],
        },
        "Found 2 evidence hits for Cobalt Strike beaconing. Top citation `pt-a1` (score 0.91) mentions C2 `185.199.108.153`. I can enrich that IOC or open a case if you want.",
    ),
    ex(
        "ioc_enrich_01",
        "black_onyx_ioc_enrich",
        "Enrich this paste and optionally give me STIX: evil.example resolves to 203.0.113.50 and hash sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        {
            "text": "evil.example 203.0.113.50 sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "export_stix": True,
        },
        {
            "extracted": {"domain": ["evil.example"], "ip": ["203.0.113.50"], "hash": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},
            "enrichment": {"evil.example": [{"provider": "otx", "score": 2}]},
            "stix": {"type": "bundle", "id": "bundle--demo"},
        },
        "Extracted domain `evil.example`, IP `203.0.113.50`, and one SHA-256. OTX scored the domain at 2. A STIX 2.1 bundle draft is ready (`bundle--demo`).",
    ),
    ex(
        "case_assist_01",
        "black_onyx_case_assist",
        "Draft a new investigation case titled 'Phish to BEC — finance' with high priority. Do not create it yet.",
        {
            "action": "create_draft",
            "title": "Phish to BEC — finance",
            "description": "Suspected business email compromise after phishing.",
            "priority": "high",
            "confirm": False,
        },
        {
            "draft": True,
            "action": "create_case",
            "payload": {"title": "Phish to BEC — finance", "priority": "high"},
            "message": "Set confirm=True to create the case.",
        },
        "Prepared a case draft titled **Phish to BEC — finance** (priority high). It is not created yet — say the word and I will call again with `confirm=true`.",
        tags=["black_onyx_case_assist", "confirm_gate"],
    ),
    ex(
        "rule_draft_01",
        "black_onyx_rule_draft",
        "Generate a Sigma rule for IP 203.0.113.50 and domain evil.example.",
        {
            "rule_type": "sigma",
            "iocs": {"ip": ["203.0.113.50"], "domain": ["evil.example"]},
            "title": "Suspicious egress to evil.example",
            "level": "high",
        },
        {"rule_type": "sigma", "rule": "title: Suspicious egress to evil.example\nlogsource:\n  product: windows\ndetection:\n  selection:\n    DestinationIp: 203.0.113.50\n  condition: selection\nlevel: high\n", "dry_run": True},
        "Generated a **Sigma** draft (generate-only, not executed against telemetry). It keys on destination IP `203.0.113.50` at level high. Review before deploying to your SIEM.",
    ),
    ex(
        "attack_map_01",
        "black_onyx_attack_map",
        "Map ATT&CK for: adversary used PowerShell (T1059.001) then lateral movement via remote services.",
        {"text": "PowerShell T1059.001 lateral movement remote services T1021", "coverage_range": "30d"},
        {
            "techniques": ["T1059.001", "T1021"],
            "coverage": {"T1059.001": {"detections": 3}, "T1021": {"detections": 1}},
            "heatmap": {"tactics": [{"tactic": "Execution", "techniques": [{"technique_id": "T1059.001"}]}]},
        },
        "Techniques in play: `T1059.001` (Command and Scripting Interpreter: PowerShell) and `T1021` (Remote Services). Org coverage last 30d shows 3 detections for T1059.001 and 1 for T1021.",
    ),
    ex(
        "hunt_01",
        "black_onyx_hunt",
        "Hunt OpenSearch for powershell encoded command activity.",
        {"query": "powershell -enc OR EncodedCommand", "mode": "search", "size": 25},
        {"hits": [{"id": "log-991", "source": {"host": "ws-42", "process": "powershell.exe"}}], "total": 1},
        "Hunt returned 1 hit: host `ws-42` running `powershell.exe` (doc `log-991`). I can pull asset context for ws-42 or draft a response playbook next.",
    ),
    ex(
        "incident_brief_01",
        "black_onyx_incident_brief",
        "Write an investigation brief for incident inc-7f3a.",
        {"incident_id": "inc-7f3a"},
        {
            "incident_id": "inc-7f3a",
            "incident": {"incident_id": "inc-7f3a", "title": "Suspicious PowerShell", "severity": "high", "status": "open", "finding_ids": ["fnd-1"]},
            "findings": [{"finding_id": "fnd-1", "model_name": "log-model", "calibrated_score": 0.92}],
            "brief_markdown": "# Incident brief: Suspicious PowerShell\n- **Severity:** high\n## Findings (1)\n- `fnd-1` — model `log-model`, score `0.92`",
        },
        "Brief for **inc-7f3a** (*Suspicious PowerShell*, high/open): one linked finding `fnd-1` from `log-model` at calibrated score 0.92. Full markdown brief is in the tool result if you want it pasted into the case.",
    ),
    ex(
        "asset_context_01",
        "black_onyx_asset_context",
        "What do we know about hostname finance-laptop-12?",
        {"hostname": "finance-laptop-12", "window_days": 7},
        {
            "asset_id": "ast-12",
            "asset": {"asset_id": "ast-12", "name": "finance-laptop-12", "criticality": "high", "ip_address": "10.20.30.40"},
            "topology": {"nodes": [{"id": "ast-12"}], "edges": []},
            "baseline": {"window_days": 7, "process_count_p95": 120},
            "related_incidents": [{"incident_id": "inc-7f3a"}],
        },
        "`finance-laptop-12` → asset `ast-12` (criticality high, IP 10.20.30.40). Baseline p95 process count over 7d is 120. Related open incident: `inc-7f3a`.",
    ),
    ex(
        "response_draft_01",
        "black_onyx_response_draft",
        "Draft an isolate-host response for incident inc-7f3a. Do not approve or execute anything.",
        {
            "incident_id": "inc-7f3a",
            "playbook_id": "isolate-host",
            "confirm": False,
            "dry_run": True,
        },
        {
            "draft": {
                "incident_id": "inc-7f3a",
                "playbook_id": "isolate-host",
                "dry_run": True,
                "payload": {"response_mode": "suggest_only", "auto_execute": False},
                "message": "Draft only. Approval is never performed by this tool.",
            },
            "submitted": False,
        },
        "Prepared a **suggest-only** response draft for playbook `isolate-host` on `inc-7f3a`. Nothing was submitted or approved. An analyst must approve in the response queue UI if you want action.",
        tags=["black_onyx_response_draft", "safety_no_approve"],
    ),
    ex(
        "ti_match_01",
        "black_onyx_ti_match",
        "Do we have TI hits for 203.0.113.50?",
        {"observables": [{"type": "ipv4", "value": "203.0.113.50"}], "mode": "exact", "publish": False},
        {"mode": "exact", "matches": {"matches": [{"value": "203.0.113.50", "source": "otx"}]}, "published": False},
        "Exact TI match on `203.0.113.50` from source `otx`. Nothing was published to the match SoR.",
    ),
    ex(
        "watchlist_decay_01",
        "black_onyx_watchlist_decay",
        "Give me a quick IOC decay summary — what is stale vs fresh?",
        {"action": "summary"},
        {"summary": {"tracked": 120, "stale": 14, "fresh": 40}, "stale": {"items": [{"ioc": "old.example"}]}, "fresh": {"items": []}},
        "Decay summary: 120 tracked IOCs — 14 stale (including `old.example`) and 40 fresh. I can propose watchlist adds if you want, but that needs `confirm=true`.",
    ),
    ex(
        "misp_taxii_draft_01",
        "black_onyx_misp_taxii_draft",
        "Draft a MISP event from case case-99 IOCs. Do not publish yet.",
        {
            "target": "misp",
            "case_id": "case-99",
            "iocs": [{"ioc_type": "domain", "ioc_value": "evil.example"}],
            "confirm": False,
        },
        {
            "draft": {"target": "misp", "case_id": "case-99", "iocs": [{"ioc_type": "domain", "ioc_value": "evil.example"}]},
            "published": False,
            "message": "Set confirm=True to publish to MISP.",
        },
        "MISP draft ready for case `case-99` with domain `evil.example`. Not published — confirm explicitly if you want it sent.",
        tags=["black_onyx_misp_taxii_draft", "confirm_gate"],
    ),
    ex(
        "connector_pulse_01",
        "black_onyx_connector_pulse",
        "How are our detection connectors looking right now?",
        {"limit": 10},
        {
            "health": {"healthy": 2, "degraded": 0},
            "recent_detections": [{"connector": "splunk", "title": "Rare process"}],
            "markdown": "# Connector pulse\n- healthy: 2\n- Recent: splunk — Rare process",
        },
        "Connector pulse: 2 healthy, 0 degraded. Recent detection from **splunk**: *Rare process*. I can promote that detection into a case if you provide the detection key.",
    ),
    ex(
        "feed_digest_01",
        "black_onyx_feed_digest",
        "List our configured threat intel feeds. Do not poll yet.",
        {"poll": False},
        {
            "feeds": [{"name": "cisa-kev"}, {"name": "otx-pulse"}],
            "poll_results": [],
            "digest_markdown": "# Feed digest\n\n- **cisa-kev**\n- **otx-pulse**",
        },
        "Configured feeds: `cisa-kev`, `otx-pulse`. No poll was run. Polling would require `poll=true` and `confirm=true`.",
    ),
    ex(
        "model_ops_01",
        "black_onyx_model_ops",
        "Are the detection models and training orchestrator ready?",
        {"job_id": ""},
        {
            "models_ready": {"status": "ready", "models": {"log-model": "http://log-model:8080"}},
            "training_ready": {"status": "ready"},
            "ops_models": {"models": []},
            "read_only": True,
        },
        "Model gateway reports **ready** (log-model registered). Training orchestrator is also ready. This is read-only status — no jobs were started.",
    ),
    ex(
        "passive_dns_whois_01",
        "passive_dns_whois",
        "Get DNS and WHOIS structure for evil.example for the IOC workbench.",
        {"domain": "evil.example", "query_types": ["A", "MX", "NS"]},
        {
            "domain": "evil.example",
            "dns": {"A": ["203.0.113.50"], "MX": ["mail.evil.example."], "NS": ["ns1.evil.example."]},
            "whois": {"registrar": "Example Registrar", "creation_date": "2024-01-02"},
        },
        "`evil.example` A=`203.0.113.50`, MX=`mail.evil.example`, NS=`ns1.evil.example`. WHOIS registrar Example Registrar, created 2024-01-02. Fields are ready to attach as IOCs.",
    ),
    ex(
        "url_screenshot_sandbox_01",
        "url_screenshot_sandbox",
        "Sandbox-fetch https://phish.example/login for metadata (lab only).",
        {"url": "https://phish.example/login", "confirm": False},
        {
            "enabled": False,
            "message": "URL screenshot sandbox is disabled. Set BLACK_ONYX_TOOLS_ALLOW_SANDBOX=true to enable lab-gated fetches.",
            "url": "https://phish.example/login",
        },
        "Sandbox is **disabled** in this environment (`BLACK_ONYX_TOOLS_ALLOW_SANDBOX` not set). I will not fetch the URL until lab sandbox is explicitly enabled. You can still enrich the domain/URL as IOCs.",
        tags=["url_screenshot_sandbox", "lab_gated"],
    ),
    ex(
        "certificate_transparency_01",
        "certificate_transparency",
        "CT pivot on evil.example — any related hostnames?",
        {"domain": "evil.example", "limit": 5},
        {
            "domain": "evil.example",
            "returned": 2,
            "entries": [
                {"name_value": "evil.example\nwww.evil.example", "issuer_name": "Let's Encrypt"},
                {"name_value": "api.evil.example", "issuer_name": "Let's Encrypt"},
            ],
        },
        "CT returned 2 entries for `evil.example`, including `www.evil.example` and `api.evil.example` (Let's Encrypt). Useful pivots for the IOC workbench.",
    ),
    # Extra safety / confirm examples (still counts per-tool coverage above; these deepen safety)
    ex(
        "case_assist_promote_01",
        "black_onyx_case_assist",
        "Promote watchlist alert alt-55 into a case — draft only.",
        {
            "action": "promote",
            "promote_kind": "alert",
            "alert_id": "alt-55",
            "title": "Promoted watchlist alert",
            "confirm": False,
        },
        {
            "draft": True,
            "action": "promote",
            "promote_kind": "alert",
            "path": "/api/v1/alerts/alt-55/promote",
            "message": "Set confirm=True to promote into a TIP case.",
        },
        "Promotion draft for alert `alt-55` is ready (not applied). Confirm to create the TIP case.",
        tags=["black_onyx_case_assist", "promote", "confirm_gate"],
    ),
    ex(
        "response_draft_submit_01",
        "black_onyx_response_draft",
        "Submit a pending isolate-host request for inc-7f3a to the queue, but still do not approve it.",
        {
            "incident_id": "inc-7f3a",
            "playbook_id": "isolate-host",
            "confirm": True,
            "dry_run": True,
        },
        {
            "submitted": True,
            "request": {"request_id": "rr-1", "status": "pending"},
            "approval_note": "Analyst must approve or reject in the response queue UI.",
            "draft": {"dry_run": True, "payload": {"auto_execute": False}},
        },
        "Submitted pending response request `rr-1` for `isolate-host` on `inc-7f3a` (still dry-run / suggest-only). **Not approved** — an analyst must act in the response queue.",
        tags=["black_onyx_response_draft", "safety_no_approve"],
    ),
    # Distinct scenarios (not duplicates of the _01 rows above)
    ex(
        "hunt_vector_02",
        "black_onyx_hunt",
        "Run a vector hunt for ransomware note language mentioning encrypted files and bitcoin payment.",
        {
            "query": "encrypted your files bitcoin ransom note",
            "mode": "vector",
            "limit": 15,
        },
        {
            "hits": [
                {
                    "finding_id": "fnd-ransom-22",
                    "score": 0.88,
                    "snippet": "YOUR FILES HAVE BEEN ENCRYPTED. Send BTC to bc1qdemo…",
                    "host": "fileserver-03",
                }
            ],
            "total": 1,
            "mode": "vector",
        },
        "Vector hunt returned 1 strong hit (`fnd-ransom-22`, score 0.88) on host `fileserver-03` with classic ransom-note wording and a BTC address. I can pull an incident brief if this is already ticketed, or enrich the wallet string.",
        tags=["black_onyx_hunt", "vector"],
    ),
    ex(
        "rule_draft_yara_02",
        "black_onyx_rule_draft",
        "Draft a YARA rule named lockbit_dropper_hash for SHA256 deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.",
        {
            "rule_type": "yara",
            "iocs": {
                "hash": ["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]
            },
            "rule_name": "lockbit_dropper_hash",
            "tags": ["ransomware", "lockbit"],
        },
        {
            "rule_type": "yara",
            "dry_run": True,
            "rule": (
                "rule lockbit_dropper_hash {\n"
                "  meta:\n"
                "    author = \"black_onyx\"\n"
                "    tags = \"ransomware,lockbit\"\n"
                "  strings:\n"
                "    $h = { DE AD BE EF DE AD BE EF DE AD BE EF DE AD BE EF DE AD BE EF DE AD BE EF DE AD BE EF DE AD BE EF }\n"
                "  condition:\n"
                "    $h\n"
                "}\n"
            ),
        },
        "Generated a **YARA** draft `lockbit_dropper_hash` (generate-only) matching the provided SHA-256. Tags: ransomware, lockbit. Not executed against production telemetry.",
        tags=["black_onyx_rule_draft", "yara"],
    ),
    ex(
        "case_assist_add_ioc_02",
        "black_onyx_case_assist",
        "On case case-441, go ahead and attach domain payload-cdn.badactor[.]net as an IOC. Confirm the write.",
        {
            "action": "add_ioc",
            "case_id": "case-441",
            "ioc_type": "domain",
            "ioc_value": "payload-cdn.badactor.net",
            "confirm": True,
        },
        {
            "status": "ok",
            "case_id": "case-441",
            "ioc_type": "domain",
            "ioc_value": "payload-cdn.badactor.net",
        },
        "Attached domain IOC `payload-cdn.badactor.net` to case `case-441`. Defanging was normalized to the live FQDN for storage.",
        tags=["black_onyx_case_assist", "confirm_true"],
    ),
    ex(
        "ti_match_semantic_draft_02",
        "black_onyx_ti_match",
        "Semantically match URL https://login-secure-update.example/oauth and show me a publish draft only — do not sync yet.",
        {
            "observables": [{"type": "url", "value": "https://login-secure-update.example/oauth"}],
            "mode": "semantic",
            "publish": True,
            "confirm": False,
            "case_id": "case-441",
        },
        {
            "mode": "semantic",
            "matches": {
                "matches": [
                    {
                        "value": "https://login-secure-update.example/oauth",
                        "score": 0.81,
                        "source": "urlhaus",
                        "related": ["phish-kit-oauth-v3"],
                    }
                ]
            },
            "draft": True,
            "action": "sync-indicators",
            "iocs": [{"ioc_type": "url", "ioc_value": "https://login-secure-update.example/oauth"}],
            "case_id": "case-441",
            "published": False,
            "message": "Publishing to TIP→threat-intel sync requires confirm=True and a case_id.",
        },
        "Semantic TI matched the OAuth phishing URL (score 0.81, source urlhaus, related `phish-kit-oauth-v3`). Publish remains a **draft** for case `case-441` — not synced. Say confirm if you want the TIP→threat-intel sync.",
        tags=["black_onyx_ti_match", "semantic", "confirm_gate"],
    ),
    ex(
        "watchlist_decay_propose_02",
        "black_onyx_watchlist_decay",
        "Propose adding IP 198.51.100.77 and domain staging-update.badactor.net to the 'egress-suspicious' watchlist. Do not write yet.",
        {
            "action": "propose_add",
            "watchlist_name": "egress-suspicious",
            "items": [
                {"ioc_type": "ip", "ioc_value": "198.51.100.77"},
                {"ioc_type": "domain", "ioc_value": "staging-update.badactor.net"},
            ],
            "confirm": False,
        },
        {
            "draft": True,
            "proposal": {
                "watchlist_name": "egress-suspicious",
                "items": [
                    {"ioc_type": "ip", "ioc_value": "198.51.100.77"},
                    {"ioc_type": "domain", "ioc_value": "staging-update.badactor.net"},
                ],
            },
            "message": "Set confirm=True to add watchlist items.",
        },
        "Watchlist add proposal for **egress-suspicious**: IP `198.51.100.77` and domain `staging-update.badactor.net`. Not written — re-run with `confirm=true` to apply.",
        tags=["black_onyx_watchlist_decay", "confirm_gate"],
    ),
    # Distinct from prior rows (image search, federated hunt, TAXII, feed poll, asset-by-IP)
    ex(
        "evidence_search_image_03",
        "black_onyx_evidence_search",
        "CLIP-search this screenshot against evidence: C:/lab/captures/login_phish_panel.png — collection visual-evidence, top 3.",
        {
            "query": "credential harvest login panel",
            "collection": "visual-evidence",
            "limit": 3,
            "image_path": "C:/lab/captures/login_phish_panel.png",
        },
        {
            "mode": "image",
            "total": 2,
            "citations": [
                {
                    "point_id": "pt-img-9",
                    "collection": "visual-evidence",
                    "score": 0.93,
                    "snippet": "Captured OAuth lookalike login chrome",
                },
                {
                    "point_id": "pt-img-11",
                    "collection": "visual-evidence",
                    "score": 0.79,
                    "snippet": "Earlier kit screenshot — similar form layout",
                },
            ],
        },
        "Image CLIP search over `visual-evidence` returned 2 hits. Top: `pt-img-9` (0.93) — OAuth lookalike login chrome matching the panel screenshot. Second hit `pt-img-11` (0.79) is an earlier kit with similar layout.",
        tags=["black_onyx_evidence_search", "image"],
    ),
    ex(
        "hunt_federated_03",
        "black_onyx_hunt",
        "Run a federated hunt across connectors for rare scheduled-task creation by SYSTEM.",
        {
            "query": "scheduled task created by SYSTEM rare",
            "mode": "federated",
            "size": 40,
        },
        {
            "mode": "federated",
            "hits": [
                {
                    "connector": "crowdstrike",
                    "host": "dc-west-02",
                    "event": "schtasks.exe /Create /RU SYSTEM",
                    "score": 0.76,
                },
                {
                    "connector": "splunk",
                    "host": "jump-box-7",
                    "event": "Task Scheduler Operational 106",
                    "score": 0.71,
                },
            ],
            "total": 2,
        },
        "Federated hunt returned 2 hits: CrowdStrike on `dc-west-02` (`schtasks.exe /Create /RU SYSTEM`) and Splunk on `jump-box-7` (Task Scheduler 106). I can pull asset context for either host next.",
        tags=["black_onyx_hunt", "federated"],
    ),
    ex(
        "misp_taxii_taxii_03",
        "black_onyx_misp_taxii_draft",
        "Draft a TAXII package for case case-512 into collection shared-ti-outbound. Include IP 203.0.113.88. Do not publish.",
        {
            "target": "taxii",
            "case_id": "case-512",
            "collection_id": "shared-ti-outbound",
            "iocs": [{"ioc_type": "ip", "ioc_value": "203.0.113.88"}],
            "confirm": False,
        },
        {
            "draft": {
                "target": "taxii",
                "case_id": "case-512",
                "collection_id": "shared-ti-outbound",
                "iocs": [{"ioc_type": "ip", "ioc_value": "203.0.113.88"}],
            },
            "published": False,
            "message": "Set confirm=True to publish to TAXII.",
        },
        "TAXII draft ready for case `case-512` → collection `shared-ti-outbound` with IP `203.0.113.88`. Not published — confirm if you want it pushed.",
        tags=["black_onyx_misp_taxii_draft", "taxii", "confirm_gate"],
    ),
    ex(
        "feed_digest_poll_draft_03",
        "black_onyx_feed_digest",
        "Poll only the cisa-kev feed for a digest preview. Do not actually poll yet — draft the request.",
        {"feed_name": "cisa-kev", "poll": True, "confirm": False},
        {
            "feeds": [{"name": "cisa-kev"}],
            "poll": True,
            "draft": True,
            "poll_results": [],
            "message": "Set confirm=True to poll feeds.",
        },
        "Prepared a poll draft for feed `cisa-kev` only. No poll ran — confirm to execute the feed pull.",
        tags=["black_onyx_feed_digest", "confirm_gate"],
    ),
    ex(
        "asset_context_ip_03",
        "black_onyx_asset_context",
        "Resolve asset context for IP 10.40.12.88 over the last 14 days.",
        {"ip_address": "10.40.12.88", "window_days": 14},
        {
            "asset_id": "ast-88",
            "asset": {
                "asset_id": "ast-88",
                "name": "build-agent-east",
                "criticality": "medium",
                "ip_address": "10.40.12.88",
            },
            "topology": {
                "nodes": [{"id": "ast-88"}, {"id": "ast-gw-1"}],
                "edges": [{"src": "ast-88", "dst": "ast-gw-1"}],
            },
            "baseline": {"window_days": 14, "outbound_conn_p95": 340},
            "related_incidents": [],
        },
        "IP `10.40.12.88` → asset `ast-88` (`build-agent-east`, criticality medium). 14d baseline outbound p95 is 340. Topology links to gateway `ast-gw-1`. No related incidents in this window.",
        tags=["black_onyx_asset_context", "ip"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_get_04",
        "black_onyx_case_assist",
        "Pull the full record for investigation case case-441.",
        {"action": "get", "case_id": "case-441"},
        {
            "case_id": "case-441",
            "title": "OAuth phish kit — finance",
            "priority": "high",
            "status": "open",
            "iocs": [
                {"ioc_type": "domain", "ioc_value": "payload-cdn.badactor.net"},
                {"ioc_type": "url", "ioc_value": "https://login-secure-update.example/oauth"},
            ],
            "notes_count": 3,
        },
        "Case `case-441` is open/high: **OAuth phish kit — finance**. Two IOCs on file (domain + OAuth URL) and 3 notes. Ready for enrichment or a response draft if you want next steps.",
        tags=["black_onyx_case_assist", "get"],
    ),
    ex(
        "attack_map_ids_04",
        "black_onyx_attack_map",
        "Map coverage for techniques T1078.004 and T1566.002 over the last 90 days. Skip free-text extraction.",
        {
            "technique_ids": ["T1078.004", "T1566.002"],
            "coverage_range": "90d",
            "include_graph": False,
        },
        {
            "techniques": ["T1078.004", "T1566.002"],
            "coverage": {
                "T1078.004": {"detections": 0, "gap": True},
                "T1566.002": {"detections": 12, "gap": False},
            },
            "heatmap": None,
        },
        "Coverage (90d): `T1566.002` (Spearphishing Link) has 12 detections; `T1078.004` (Cloud Accounts) shows **0 detections / gap**. Graph omitted per request.",
        tags=["black_onyx_attack_map", "technique_ids"],
    ),
    ex(
        "ioc_enrich_structured_04",
        "black_onyx_ioc_enrich",
        "Enrich these structured IOCs only — no text extraction, no STIX: URL https://cdn.mirror-update.example/payload.bin and email ops-alert@mirror-update.example.",
        {
            "iocs": [
                {"ioc_type": "url", "ioc_value": "https://cdn.mirror-update.example/payload.bin"},
                {"ioc_type": "email", "ioc_value": "ops-alert@mirror-update.example"},
            ],
            "export_stix": False,
        },
        {
            "extracted": {},
            "enrichment": {
                "https://cdn.mirror-update.example/payload.bin": [
                    {"provider": "urlhaus", "status": "online", "threat": "malware_download"}
                ],
                "ops-alert@mirror-update.example": [
                    {"provider": "otx", "pulses": 1, "tags": ["phishing"]}
                ],
            },
            "stix": None,
        },
        "Structured enrich (no STIX): URL flagged malware_download on urlhaus (online); email `ops-alert@mirror-update.example` hit 1 OTX pulse tagged phishing.",
        tags=["black_onyx_ioc_enrich", "structured"],
    ),
    ex(
        "watchlist_list_04",
        "black_onyx_watchlist_decay",
        "List the configured TIP watchlists — names and IDs only, no mutations.",
        {"action": "list_watchlists"},
        {
            "watchlists": [
                {"watchlist_id": "wl-egress", "name": "egress-suspicious", "item_count": 42},
                {"watchlist_id": "wl-phish", "name": "phishing-domains", "item_count": 118},
                {"watchlist_id": "wl-hash", "name": "malware-hashes", "item_count": 67},
            ]
        },
        "Three watchlists: `egress-suspicious` (wl-egress, 42), `phishing-domains` (wl-phish, 118), `malware-hashes` (wl-hash, 67). I can propose adds to any of these with confirm.",
        tags=["black_onyx_watchlist_decay", "list"],
    ),
    ex(
        "sandbox_fetch_ok_04",
        "url_screenshot_sandbox",
        "Lab sandbox is enabled — fetch https://cdn.mirror-update.example/payload.bin metadata and a screenshot hash for case case-512. Confirm the lab fetch.",
        {
            "url": "https://cdn.mirror-update.example/payload.bin",
            "max_bytes": 65536,
            "case_id": "case-512",
            "confirm": True,
        },
        {
            "enabled": True,
            "url": "https://cdn.mirror-update.example/payload.bin",
            "final_url": "https://cdn.mirror-update.example/payload.bin",
            "status_code": 200,
            "content_type": "application/octet-stream",
            "sha256": "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00",
            "byte_length": 18432,
            "screenshot": {
                "format": "png",
                "sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                "byte_length": 90210,
                "engine": "playwright-chromium",
            },
            "case_id": "case-512",
        },
        "Sandbox fetch OK for case `case-512`: HTTP 200, `application/octet-stream`, 18432 bytes, content SHA-256 `c0ffee00…`. Playwright screenshot hash `aabbccdd…`. Attach either hash to the case if useful.",
        tags=["url_screenshot_sandbox", "lab_gated", "enabled"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_add_note_05",
        "black_onyx_case_assist",
        "On case case-512, add this analyst note and confirm the write: Sandbox fetch of payload.bin completed; SHA-256 c0ffee00… attached for hashing.",
        {
            "action": "add_note",
            "case_id": "case-512",
            "note": "Sandbox fetch of payload.bin completed; SHA-256 c0ffee00… attached for hashing.",
            "confirm": True,
        },
        {
            "status": "ok",
            "case_id": "case-512",
            "note_id": "note-77",
        },
        "Added note `note-77` on case `case-512` documenting the sandbox fetch and content hash.",
        tags=["black_onyx_case_assist", "add_note", "confirm_true"],
    ),
    ex(
        "case_assist_promote_detection_05",
        "black_onyx_case_assist",
        "Promote detection key det-crowdstrike-9912 into a TIP case titled 'Rare schtask SYSTEM — dc-west-02'. Draft only.",
        {
            "action": "promote",
            "promote_kind": "detection",
            "detection_key": "det-crowdstrike-9912",
            "title": "Rare schtask SYSTEM — dc-west-02",
            "confirm": False,
        },
        {
            "draft": True,
            "action": "promote",
            "promote_kind": "detection",
            "path": "/api/v1/detections/det-crowdstrike-9912/promote",
            "title": "Rare schtask SYSTEM — dc-west-02",
            "message": "Set confirm=True to promote into a TIP case.",
        },
        "Promotion draft ready for detection `det-crowdstrike-9912` → case title *Rare schtask SYSTEM — dc-west-02*. Not applied — confirm to create the TIP case.",
        tags=["black_onyx_case_assist", "promote", "detection", "confirm_gate"],
    ),
    ex(
        "misp_publish_confirm_05",
        "black_onyx_misp_taxii_draft",
        "Publish the MISP event for case case-512 with IP 203.0.113.88 and hash sha256:c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00. Confirm publish.",
        {
            "target": "misp",
            "case_id": "case-512",
            "iocs": [
                {"ioc_type": "ip", "ioc_value": "203.0.113.88"},
                {
                    "ioc_type": "hash",
                    "ioc_value": "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00",
                },
            ],
            "info": "case-512 malware download",
            "confirm": True,
        },
        {
            "published": True,
            "target": "misp",
            "case_id": "case-512",
            "event_id": "misp-ev-334",
            "attribute_count": 2,
        },
        "Published MISP event `misp-ev-334` for case `case-512` (2 attributes: IP + SHA-256). Info: case-512 malware download.",
        tags=["black_onyx_misp_taxii_draft", "misp", "confirm_true"],
    ),
    ex(
        "ti_match_publish_confirm_05",
        "black_onyx_ti_match",
        "Exact-match domain cdn.mirror-update.example and sync the indicators into TIP for case case-512. Confirm the publish.",
        {
            "observables": [{"type": "domain", "value": "cdn.mirror-update.example"}],
            "mode": "exact",
            "publish": True,
            "confirm": True,
            "case_id": "case-512",
        },
        {
            "mode": "exact",
            "matches": {
                "matches": [
                    {"value": "cdn.mirror-update.example", "source": "urlhaus", "tags": ["malware"]}
                ]
            },
            "published": True,
            "case_id": "case-512",
            "iocs": [{"ioc_type": "domain", "ioc_value": "cdn.mirror-update.example"}],
            "sync": {"status": "ok", "synced": 1},
        },
        "Exact TI hit on `cdn.mirror-update.example` (urlhaus/malware). Synced 1 indicator to TIP for case `case-512`.",
        tags=["black_onyx_ti_match", "publish", "confirm_true"],
    ),
    ex(
        "model_ops_job_05",
        "black_onyx_model_ops",
        "Check model readiness and pull training job tj-2026-0812-a status.",
        {"job_id": "tj-2026-0812-a"},
        {
            "models_ready": {"status": "ready", "models": {"log-model": "http://log-model:8080"}},
            "training_ready": {"status": "ready"},
            "ops_models": {"models": [{"name": "log-model", "version": "1.4.2"}]},
            "training_job": {
                "job_id": "tj-2026-0812-a",
                "status": "succeeded",
                "model_name": "log-model",
                "finished_at": "2026-08-12T14:22:00Z",
            },
            "read_only": True,
            "note": "Read-only. Pass job_id to fetch a training job; there is no training-jobs list endpoint.",
        },
        "Models and training orchestrator are ready. Job `tj-2026-0812-a` **succeeded** for `log-model` at 2026-08-12T14:22:00Z. Read-only — no jobs started.",
        tags=["black_onyx_model_ops", "job_id"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_list_06",
        "black_onyx_case_assist",
        "List open investigation cases so I can pick one to work.",
        {"action": "list"},
        {
            "cases": [
                {"case_id": "case-441", "title": "OAuth phish kit — finance", "status": "open", "priority": "high"},
                {"case_id": "case-512", "title": "Malware download — mirror-update", "status": "open", "priority": "high"},
                {"case_id": "case-318", "title": "Stale watchlist cleanup", "status": "open", "priority": "low"},
            ],
            "total": 3,
        },
        "3 open cases: `case-441` (OAuth phish, high), `case-512` (malware download, high), `case-318` (watchlist cleanup, low). Say which ID to open next.",
        tags=["black_onyx_case_assist", "list"],
    ),
    ex(
        "case_assist_add_point_06",
        "black_onyx_case_assist",
        "Attach evidence point pt-img-9 from collection visual-evidence to case case-512. Confirm the write.",
        {
            "action": "add_point",
            "case_id": "case-512",
            "collection": "visual-evidence",
            "point_id": "pt-img-9",
            "confirm": True,
        },
        {
            "status": "ok",
            "case_id": "case-512",
            "collection": "visual-evidence",
            "point_id": "pt-img-9",
        },
        "Attached evidence point `pt-img-9` (`visual-evidence`) to case `case-512`.",
        tags=["black_onyx_case_assist", "add_point", "confirm_true"],
    ),
    ex(
        "watchlist_add_confirm_06",
        "black_onyx_watchlist_decay",
        "Add hash c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00 to the malware-hashes watchlist (wl-hash). Confirm the write.",
        {
            "action": "propose_add",
            "watchlist_id": "wl-hash",
            "watchlist_name": "malware-hashes",
            "items": [
                {
                    "ioc_type": "hash",
                    "ioc_value": "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00",
                }
            ],
            "confirm": True,
        },
        {
            "watchlist_id": "wl-hash",
            "proposal": {
                "watchlist_id": "wl-hash",
                "watchlist_name": "malware-hashes",
                "items": [
                    {
                        "ioc_type": "hash",
                        "ioc_value": "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00",
                    }
                ],
            },
            "result": {"added": 1, "skipped": 0},
        },
        "Added 1 hash IOC to watchlist `malware-hashes` (`wl-hash`). Nothing skipped.",
        tags=["black_onyx_watchlist_decay", "confirm_true"],
    ),
    ex(
        "feed_digest_poll_confirm_06",
        "black_onyx_feed_digest",
        "Go ahead and poll the otx-pulse feed now. Confirm the poll.",
        {"feed_name": "otx-pulse", "poll": True, "confirm": True},
        {
            "feeds": [{"name": "otx-pulse"}],
            "poll": True,
            "poll_results": [
                {
                    "feed": "otx-pulse",
                    "status": "ok",
                    "new_indicators": 17,
                    "pulses": ["APT29 infrastructure refresh", "Phish kit OAuth v3"],
                }
            ],
            "digest_markdown": "# Feed digest\n\n## otx-pulse\n- new indicators: 17\n- pulses: APT29 infrastructure refresh; Phish kit OAuth v3",
        },
        "Polled `otx-pulse`: 17 new indicators. Notable pulses — *APT29 infrastructure refresh*, *Phish kit OAuth v3*. Digest markdown is in the tool result.",
        tags=["black_onyx_feed_digest", "confirm_true"],
    ),
    ex(
        "response_draft_disable_user_06",
        "black_onyx_response_draft",
        "Draft a disable-user response for incident inc-9c21 targeting the compromised mailbox. Do not submit or approve.",
        {
            "incident_id": "inc-9c21",
            "playbook_id": "disable-user",
            "confirm": False,
            "dry_run": True,
        },
        {
            "draft": {
                "incident_id": "inc-9c21",
                "playbook_id": "disable-user",
                "dry_run": True,
                "payload": {"response_mode": "suggest_only", "auto_execute": False},
                "message": "Draft only. Approval is never performed by this tool.",
            },
            "submitted": False,
        },
        "Prepared a **suggest-only** draft for playbook `disable-user` on `inc-9c21`. Not submitted and not approved — an analyst must act in the response queue if you want this queued.",
        tags=["black_onyx_response_draft", "safety_no_approve"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_update_draft_07",
        "black_onyx_case_assist",
        "Change case case-318 priority to medium and status to investigating. Draft the update only — do not apply.",
        {
            "action": "update",
            "case_id": "case-318",
            "priority": "medium",
            "status": "investigating",
            "confirm": False,
        },
        {
            "draft": True,
            "case_id": "case-318",
            "updates": {"priority": "medium", "status": "investigating"},
            "message": "Set confirm=True to apply.",
        },
        "Update draft for `case-318`: priority → medium, status → investigating. Not applied — confirm to patch the case.",
        tags=["black_onyx_case_assist", "update", "confirm_gate"],
    ),
    ex(
        "case_assist_promote_webhook_07",
        "black_onyx_case_assist",
        "Promote webhook event evt-phish-881 into a TIP case titled 'External phish report — OAuth lure'. Draft only.",
        {
            "action": "promote",
            "promote_kind": "webhook",
            "event_id": "evt-phish-881",
            "title": "External phish report — OAuth lure",
            "priority": "high",
            "confirm": False,
        },
        {
            "draft": True,
            "action": "promote",
            "promote_kind": "webhook",
            "path": "/api/v1/webhook-events/evt-phish-881/promote",
            "title": "External phish report — OAuth lure",
            "message": "Set confirm=True to promote into a TIP case.",
        },
        "Promotion draft for webhook `evt-phish-881` → *External phish report — OAuth lure* (high). Not applied — confirm to create the TIP case.",
        tags=["black_onyx_case_assist", "promote", "webhook", "confirm_gate"],
    ),
    ex(
        "asset_context_asset_id_07",
        "black_onyx_asset_context",
        "Resolve topology and baseline for asset ast-12 over the last 7 days.",
        {
            "asset_id": "ast-12",
            "window_days": 7,
        },
        {
            "asset_id": "ast-12",
            "asset": {
                "asset_id": "ast-12",
                "name": "finance-laptop-12",
                "criticality": "high",
                "ip_address": "10.20.30.40",
            },
            "topology": {
                "nodes": [{"id": "ast-12"}, {"id": "ast-sw-3"}],
                "edges": [{"src": "ast-12", "dst": "ast-sw-3"}],
            },
            "baseline": {"window_days": 7, "process_count_p95": 120},
            "related_incidents": [{"incident_id": "inc-7f3a"}],
        },
        "Asset `ast-12` is `finance-laptop-12` (high, 10.20.30.40). 7d process p95 = 120. Linked to switch `ast-sw-3`. Related incident: `inc-7f3a`.",
        tags=["black_onyx_asset_context", "asset_id"],
    ),
    ex(
        "passive_dns_mx_07",
        "passive_dns_whois",
        "Pull MX records only for mirror-update.example — I need mail-routing pivots, not full DNS.",
        {
            "domain": "mirror-update.example",
            "query_types": ["MX"],
        },
        {
            "domain": "mirror-update.example",
            "dns": {
                "MX": [
                    "10 mail.mirror-update.example.",
                    "20 backup-mail.mirror-update.example.",
                ]
            },
            "whois": {"registrar": "Example Registrar", "updated_date": "2026-06-01"},
        },
        "`mirror-update.example` MX: `mail.mirror-update.example` (10), `backup-mail.mirror-update.example` (20). WHOIS updated 2026-06-01. Good pivots for phish/malware mail infra.",
        tags=["passive_dns_whois", "mx"],
    ),
    ex(
        "certificate_transparency_subdomain_07",
        "certificate_transparency",
        "CT pivot on cdn.mirror-update.example — list related hostnames, limit 10.",
        {
            "domain": "cdn.mirror-update.example",
            "limit": 10,
        },
        {
            "domain": "cdn.mirror-update.example",
            "returned": 3,
            "entries": [
                {
                    "name_value": "cdn.mirror-update.example",
                    "issuer_name": "Let's Encrypt",
                },
                {
                    "name_value": "static.cdn.mirror-update.example",
                    "issuer_name": "Let's Encrypt",
                },
                {
                    "name_value": "api.cdn.mirror-update.example",
                    "issuer_name": "Let's Encrypt",
                },
            ],
        },
        "CT returned 3 names for `cdn.mirror-update.example`: apex CDN host plus `static.cdn…` and `api.cdn…` (all Let's Encrypt). Useful subdomain pivots for case work.",
        tags=["certificate_transparency", "subdomain"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_create_confirm_08",
        "black_onyx_case_assist",
        "Create the case now: title 'Malware CDN — mirror-update', priority high, description 'Payload host from sandbox fetch'. Confirm the write.",
        {
            "action": "create_draft",
            "title": "Malware CDN — mirror-update",
            "description": "Payload host from sandbox fetch",
            "priority": "high",
            "confirm": True,
        },
        {
            "case_id": "case-601",
            "title": "Malware CDN — mirror-update",
            "priority": "high",
            "status": "open",
        },
        "Created case `case-601` — **Malware CDN — mirror-update** (high/open). Ready for IOC attach or TI sync.",
        tags=["black_onyx_case_assist", "create", "confirm_true"],
    ),
    ex(
        "case_assist_promote_incident_08",
        "black_onyx_case_assist",
        "Promote detection incident inc-9c21 into a TIP case titled 'Compromised mailbox — disable-user path'. Draft only.",
        {
            "action": "promote",
            "promote_kind": "detection_incident",
            "incident_id": "inc-9c21",
            "title": "Compromised mailbox — disable-user path",
            "priority": "high",
            "confirm": False,
        },
        {
            "draft": True,
            "action": "promote",
            "promote_kind": "detection_incident",
            "path": "/api/v1/detection-incidents/promote",
            "payload": {
                "incident_id": "inc-9c21",
                "title": "Compromised mailbox — disable-user path",
                "priority": "high",
            },
            "message": "Set confirm=True to promote into a TIP case.",
        },
        "Promotion draft for detection incident `inc-9c21` → *Compromised mailbox — disable-user path*. Not applied — confirm to create the TIP case.",
        tags=["black_onyx_case_assist", "promote", "detection_incident", "confirm_gate"],
    ),
    ex(
        "case_assist_delete_draft_08",
        "black_onyx_case_assist",
        "Delete duplicate case case-318. Show me the delete request first — do not execute.",
        {
            "action": "delete",
            "case_id": "case-318",
            "confirm": False,
        },
        {
            "draft": True,
            "case_id": "case-318",
            "message": "Set confirm=True to delete case.",
        },
        "Delete draft for `case-318` only — nothing removed. Confirm explicitly if you want the case deleted.",
        tags=["black_onyx_case_assist", "delete", "confirm_gate"],
    ),
    ex(
        "taxii_publish_confirm_08",
        "black_onyx_misp_taxii_draft",
        "Publish TAXII package for case case-601 into collection shared-ti-outbound with domain cdn.mirror-update.example. Confirm publish.",
        {
            "target": "taxii",
            "case_id": "case-601",
            "collection_id": "shared-ti-outbound",
            "iocs": [{"ioc_type": "domain", "ioc_value": "cdn.mirror-update.example"}],
            "confirm": True,
        },
        {
            "published": True,
            "target": "taxii",
            "case_id": "case-601",
            "collection_id": "shared-ti-outbound",
            "package_id": "taxii-pkg-19",
            "object_count": 1,
        },
        "Published TAXII package `taxii-pkg-19` to `shared-ti-outbound` for case `case-601` (1 object: domain `cdn.mirror-update.example`).",
        tags=["black_onyx_misp_taxii_draft", "taxii", "confirm_true"],
    ),
    ex(
        "evidence_search_threshold_08",
        "black_onyx_evidence_search",
        "Search collection incident-notes for 'OAuth phishing kit redirect' with score threshold 0.75, return top 4.",
        {
            "query": "OAuth phishing kit redirect",
            "collection": "incident-notes",
            "limit": 4,
            "score_threshold": 0.75,
        },
        {
            "mode": "text",
            "total": 1,
            "citations": [
                {
                    "point_id": "pt-note-44",
                    "collection": "incident-notes",
                    "score": 0.86,
                    "snippet": "Kit used login-secure-update.example/oauth redirect to steal tokens",
                }
            ],
        },
        "Thresholded search (`>=0.75`) on `incident-notes` returned 1 hit: `pt-note-44` (0.86) describing the OAuth redirect kit on `login-secure-update.example`. I can attach that point to a case if you want.",
        tags=["black_onyx_evidence_search", "score_threshold"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_update_confirm_09",
        "black_onyx_case_assist",
        "Apply the update on case case-318: set priority medium and status investigating. Confirm the write.",
        {
            "action": "update",
            "case_id": "case-318",
            "priority": "medium",
            "status": "investigating",
            "confirm": True,
        },
        {
            "case_id": "case-318",
            "priority": "medium",
            "status": "investigating",
        },
        "Updated `case-318`: priority is now medium, status investigating.",
        tags=["black_onyx_case_assist", "update", "confirm_true"],
    ),
    ex(
        "case_assist_add_ioc_draft_09",
        "black_onyx_case_assist",
        "Prepare attaching hash sha256:c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00 to case case-601. Do not write yet.",
        {
            "action": "add_ioc",
            "case_id": "case-601",
            "ioc_type": "hash",
            "ioc_value": "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00",
            "confirm": False,
        },
        {
            "draft": True,
            "case_id": "case-601",
            "ioc_type": "hash",
            "ioc_value": "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00",
            "message": "Set confirm=True to attach IOC.",
        },
        "IOC attach draft for case `case-601`: SHA-256 `c0ffee00…`. Not written — confirm to attach.",
        tags=["black_onyx_case_assist", "add_ioc", "confirm_gate"],
    ),
    ex(
        "incident_brief_mailbox_09",
        "black_onyx_incident_brief",
        "Write an investigation brief for mailbox compromise incident inc-9c21.",
        {"incident_id": "inc-9c21"},
        {
            "incident_id": "inc-9c21",
            "incident": {
                "incident_id": "inc-9c21",
                "title": "Compromised mailbox — finance ops",
                "severity": "critical",
                "status": "open",
                "finding_ids": ["fnd-mail-3", "fnd-mail-4"],
                "assets": ["finance-laptop-12"],
                "summary": "Suspicious OAuth consent and mailbox rule creation.",
            },
            "findings": [
                {
                    "finding_id": "fnd-mail-3",
                    "model_name": "identity-model",
                    "calibrated_score": 0.97,
                },
                {
                    "finding_id": "fnd-mail-4",
                    "model_name": "log-model",
                    "calibrated_score": 0.88,
                },
            ],
            "timeline": [
                {
                    "created_at": "2026-08-06T12:01:00Z",
                    "event_type": "oauth_consent",
                    "summary": "Unusual app consent for mail.read",
                }
            ],
            "brief_markdown": (
                "# Incident brief: Compromised mailbox — finance ops\n"
                "- **Severity:** critical\n"
                "## Findings (2)\n"
                "- `fnd-mail-3` — model `identity-model`, score `0.97`\n"
                "- `fnd-mail-4` — model `log-model`, score `0.88`"
            ),
        },
        "Brief for **inc-9c21** (*Compromised mailbox — finance ops*, critical/open): findings `fnd-mail-3` (identity-model 0.97) and `fnd-mail-4` (log-model 0.88). Timeline starts with unusual OAuth consent. Asset: `finance-laptop-12`.",
        tags=["black_onyx_incident_brief"],
    ),
    ex(
        "response_draft_submit_disable_09",
        "black_onyx_response_draft",
        "Queue a pending disable-user request for incident inc-9c21. Submit to the response queue but do not approve.",
        {
            "incident_id": "inc-9c21",
            "playbook_id": "disable-user",
            "confirm": True,
            "dry_run": True,
        },
        {
            "submitted": True,
            "request": {"request_id": "rr-44", "status": "pending"},
            "approval_note": "Analyst must approve or reject in the response queue UI.",
            "draft": {
                "incident_id": "inc-9c21",
                "playbook_id": "disable-user",
                "dry_run": True,
                "payload": {"response_mode": "suggest_only", "auto_execute": False},
            },
        },
        "Submitted pending response request `rr-44` for `disable-user` on `inc-9c21` (suggest-only). **Not approved** — an analyst must act in the response queue.",
        tags=["black_onyx_response_draft", "safety_no_approve"],
    ),
    ex(
        "connector_pulse_degraded_09",
        "black_onyx_connector_pulse",
        "Give me a connector pulse with the last 5 detections — call out anything degraded.",
        {"limit": 5},
        {
            "health": {"healthy": 1, "degraded": 1},
            "recent_detections": [
                {"connector": "crowdstrike", "title": "Rare schtask SYSTEM"},
                {"connector": "splunk", "title": "Mailbox forwarding rule"},
            ],
            "markdown": (
                "# Connector pulse\n"
                "- healthy: 1\n"
                "- degraded: 1 (splunk — ingest lag)\n"
                "- Recent: crowdstrike — Rare schtask SYSTEM; "
                "splunk — Mailbox forwarding rule"
            ),
        },
        "Connector pulse: 1 healthy, **1 degraded** (splunk ingest lag). Recent: CrowdStrike *Rare schtask SYSTEM*, Splunk *Mailbox forwarding rule*. Worth promoting either into a case if not already ticketed.",
        tags=["black_onyx_connector_pulse", "degraded"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_promote_alert_confirm_10",
        "black_onyx_case_assist",
        "Promote watchlist alert alt-88 into a TIP case titled 'Egress to staging-update'. Confirm the promote.",
        {
            "action": "promote",
            "promote_kind": "alert",
            "alert_id": "alt-88",
            "title": "Egress to staging-update",
            "priority": "high",
            "confirm": True,
        },
        {
            "case_id": "case-710",
            "promoted_from": "alt-88",
            "title": "Egress to staging-update",
            "status": "open",
        },
        "Promoted alert `alt-88` into TIP case `case-710` — *Egress to staging-update* (open). Ready for IOC attach or watchlist follow-up.",
        tags=["black_onyx_case_assist", "promote", "alert", "confirm_true"],
    ),
    ex(
        "case_assist_add_note_draft_10",
        "black_onyx_case_assist",
        "Draft a note on case case-710: 'Confirmed egress to staging-update.badactor.net from jump-box-7'. Do not write yet.",
        {
            "action": "add_note",
            "case_id": "case-710",
            "note": "Confirmed egress to staging-update.badactor.net from jump-box-7.",
            "confirm": False,
        },
        {
            "draft": True,
            "case_id": "case-710",
            "note": "Confirmed egress to staging-update.badactor.net from jump-box-7.",
            "message": "Set confirm=True to add note.",
        },
        "Note draft ready for `case-710`. Not written — confirm to attach.",
        tags=["black_onyx_case_assist", "add_note", "confirm_gate"],
    ),
    ex(
        "ioc_enrich_text_nostix_10",
        "black_onyx_ioc_enrich",
        "Extract and enrich IOCs from this alert text only — no STIX: host jump-box-7 connected to staging-update.badactor.net (198.51.100.77).",
        {
            "text": "host jump-box-7 connected to staging-update.badactor.net (198.51.100.77)",
            "export_stix": False,
        },
        {
            "extracted": {
                "domain": ["staging-update.badactor.net"],
                "ip": ["198.51.100.77"],
            },
            "enrichment": {
                "staging-update.badactor.net": [{"provider": "otx", "score": 3, "tags": ["c2"]}],
                "198.51.100.77": [{"provider": "otx", "score": 2}],
            },
            "stix": None,
        },
        "Extracted domain `staging-update.badactor.net` (OTX score 3, c2) and IP `198.51.100.77` (OTX score 2). No STIX export. Hostname `jump-box-7` is not an IOC type from extract — use asset context for that.",
        tags=["black_onyx_ioc_enrich", "no_stix"],
    ),
    ex(
        "rule_draft_sigma_url_10",
        "black_onyx_rule_draft",
        "Generate a critical Sigma rule for URL https://cdn.mirror-update.example/payload.bin titled 'Malware CDN payload URL'.",
        {
            "rule_type": "sigma",
            "iocs": {"url": ["https://cdn.mirror-update.example/payload.bin"]},
            "title": "Malware CDN payload URL",
            "level": "critical",
            "description": "Detect network access to known malware CDN payload URL",
        },
        {
            "rule_type": "sigma",
            "dry_run": True,
            "rule": (
                "title: Malware CDN payload URL\n"
                "description: Detect network access to known malware CDN payload URL\n"
                "logsource:\n"
                "  category: proxy\n"
                "detection:\n"
                "  selection:\n"
                "    c-uri: https://cdn.mirror-update.example/payload.bin\n"
                "  condition: selection\n"
                "level: critical\n"
            ),
        },
        "Generated a **critical Sigma** draft (generate-only) matching proxy URI `https://cdn.mirror-update.example/payload.bin`. Review before SIEM deploy.",
        tags=["black_onyx_rule_draft", "sigma", "url"],
    ),
    ex(
        "ti_match_multi_exact_10",
        "black_onyx_ti_match",
        "Exact-match these observables together — do not publish: domain staging-update.badactor.net and IP 198.51.100.77.",
        {
            "observables": [
                {"type": "domain", "value": "staging-update.badactor.net"},
                {"type": "ipv4", "value": "198.51.100.77"},
            ],
            "mode": "exact",
            "publish": False,
        },
        {
            "mode": "exact",
            "matches": {
                "matches": [
                    {"value": "staging-update.badactor.net", "source": "otx", "tags": ["c2"]},
                    {"value": "198.51.100.77", "source": "otx"},
                ]
            },
            "published": False,
        },
        "Exact TI hits on both: domain `staging-update.badactor.net` (otx/c2) and IP `198.51.100.77` (otx). Nothing published.",
        tags=["black_onyx_ti_match", "multi"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_add_point_draft_11",
        "black_onyx_case_assist",
        "Prepare attaching evidence point pt-note-44 from collection incident-notes to case case-710. Draft only.",
        {
            "action": "add_point",
            "case_id": "case-710",
            "collection": "incident-notes",
            "point_id": "pt-note-44",
            "confirm": False,
        },
        {
            "draft": True,
            "case_id": "case-710",
            "collection": "incident-notes",
            "point_id": "pt-note-44",
            "message": "Set confirm=True to attach evidence point.",
        },
        "Evidence-point attach draft for `case-710`: `pt-note-44` in `incident-notes`. Not written — confirm to attach.",
        tags=["black_onyx_case_assist", "add_point", "confirm_gate"],
    ),
    ex(
        "case_assist_delete_confirm_11",
        "black_onyx_case_assist",
        "Delete duplicate case case-318 now. Confirm the delete.",
        {
            "action": "delete",
            "case_id": "case-318",
            "confirm": True,
        },
        {
            "status": "deleted",
            "case_id": "case-318",
        },
        "Deleted case `case-318`.",
        tags=["black_onyx_case_assist", "delete", "confirm_true"],
    ),
    ex(
        "attack_map_with_graph_11",
        "black_onyx_attack_map",
        "Map ATT&CK for ransomware with data encrypted for impact (T1486) and inhibit system recovery (T1490). Include the attack graph. Coverage window 60d.",
        {
            "text": "ransomware encrypted files for impact T1486 and deleted volume shadow copies T1490",
            "coverage_range": "60d",
            "include_graph": True,
        },
        {
            "techniques": ["T1486", "T1490"],
            "coverage": {
                "T1486": {"detections": 2},
                "T1490": {"detections": 0, "gap": True},
            },
            "heatmap": {
                "tactics": [
                    {
                        "tactic": "Impact",
                        "techniques": [
                            {"technique_id": "T1486"},
                            {"technique_id": "T1490"},
                        ],
                    }
                ]
            },
            "graph": {
                "nodes": [
                    {"id": "T1486", "label": "Data Encrypted for Impact"},
                    {"id": "T1490", "label": "Inhibit System Recovery"},
                ],
                "edges": [{"src": "T1490", "dst": "T1486", "rel": "enables"}],
            },
        },
        "Techniques: `T1486` (Data Encrypted for Impact) and `T1490` (Inhibit System Recovery). 60d coverage: 2 detections for T1486; **gap** on T1490. Graph links T1490 → T1486 (enables).",
        tags=["black_onyx_attack_map", "graph"],
    ),
    ex(
        "feed_digest_poll_all_11",
        "black_onyx_feed_digest",
        "Poll all configured threat intel feeds now. Confirm the poll.",
        {"poll": True, "confirm": True},
        {
            "feeds": [{"name": "cisa-kev"}, {"name": "otx-pulse"}],
            "poll": True,
            "poll_results": [
                {
                    "feed": "all",
                    "status": "ok",
                    "results": [
                        {"feed": "cisa-kev", "new_indicators": 3},
                        {"feed": "otx-pulse", "new_indicators": 11},
                    ],
                }
            ],
            "digest_markdown": (
                "# Feed digest\n\n- **cisa-kev**\n- **otx-pulse**\n\n"
                "## Poll results\n- cisa-kev: 3 new\n- otx-pulse: 11 new"
            ),
        },
        "Polled all feeds: `cisa-kev` +3 indicators, `otx-pulse` +11. Digest markdown is in the tool result.",
        tags=["black_onyx_feed_digest", "poll_all", "confirm_true"],
    ),
    ex(
        "sandbox_attach_draft_11",
        "url_screenshot_sandbox",
        "Lab sandbox is on — fetch https://staging-update.badactor.net/login for case case-710 but only draft the case-note attach; do not confirm the note write.",
        {
            "url": "https://staging-update.badactor.net/login",
            "max_bytes": 32768,
            "case_id": "case-710",
            "confirm": False,
        },
        {
            "enabled": True,
            "url": "https://staging-update.badactor.net/login",
            "status_code": 200,
            "content_type": "text/html",
            "content_length": 8192,
            "sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            "screenshot": {
                "format": "png",
                "sha256": "99aabbccddeeff00112233445566778899aabbccddeeff001122334455667788",
                "byte_length": 54012,
                "engine": "playwright-chromium",
            },
            "evidence_attach": {
                "draft": True,
                "message": "Pass confirm=True to attach a case note with fetch metadata.",
            },
            "case_id": "case-710",
        },
        "Sandbox fetch OK (HTTP 200, HTML, sha256 `11223344…`). Screenshot captured. Case-note attach for `case-710` remains a **draft** — confirm to write the note.",
        tags=["url_screenshot_sandbox", "lab_gated", "confirm_gate"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_promote_detection_confirm_12",
        "black_onyx_case_assist",
        "Promote detection key det-splunk-mailbox-44 into a TIP case titled 'Mailbox forwarding rule — finance'. Confirm the promote.",
        {
            "action": "promote",
            "promote_kind": "detection",
            "detection_key": "det-splunk-mailbox-44",
            "connector": "splunk",
            "title": "Mailbox forwarding rule — finance",
            "priority": "high",
            "confirm": True,
        },
        {
            "case_id": "case-802",
            "promoted_from": "det-splunk-mailbox-44",
            "title": "Mailbox forwarding rule — finance",
            "status": "open",
        },
        "Promoted detection `det-splunk-mailbox-44` (splunk) into TIP case `case-802` — *Mailbox forwarding rule — finance* (open).",
        tags=["black_onyx_case_assist", "promote", "detection", "confirm_true"],
    ),
    ex(
        "passive_dns_a_12",
        "passive_dns_whois",
        "Get A records and WHOIS for staging-update.badactor.net — no MX or NS needed.",
        {
            "domain": "staging-update.badactor.net",
            "query_types": ["A"],
        },
        {
            "domain": "staging-update.badactor.net",
            "dns": {"A": ["198.51.100.77"]},
            "whois": {
                "registrar": "Example Registrar",
                "creation_date": "2025-11-14",
                "updated_date": "2026-07-22",
            },
        },
        "`staging-update.badactor.net` A=`198.51.100.77`. WHOIS created 2025-11-14, updated 2026-07-22. Good pivot for egress case `case-710`.",
        tags=["passive_dns_whois", "a"],
    ),
    ex(
        "ti_match_cve_exact_12",
        "black_onyx_ti_match",
        "Do we have TI hits for CVE-2024-3400? Exact match only, no publish.",
        {
            "observables": [{"type": "cve", "value": "CVE-2024-3400"}],
            "mode": "exact",
            "publish": False,
        },
        {
            "mode": "exact",
            "matches": {
                "matches": [
                    {
                        "value": "CVE-2024-3400",
                        "source": "cisa-kev",
                        "tags": ["kev", "palo_alto"],
                    }
                ]
            },
            "published": False,
        },
        "Exact TI match on `CVE-2024-3400` from **cisa-kev** (kev, palo_alto). Nothing published.",
        tags=["black_onyx_ti_match", "cve"],
    ),
    ex(
        "response_draft_block_ip_12",
        "black_onyx_response_draft",
        "Draft a block-ip response for incident inc-9c21 targeting egress IP 198.51.100.77. Do not submit or approve.",
        {
            "incident_id": "inc-9c21",
            "playbook_id": "block-ip",
            "confirm": False,
            "dry_run": True,
        },
        {
            "draft": {
                "incident_id": "inc-9c21",
                "playbook_id": "block-ip",
                "dry_run": True,
                "payload": {"response_mode": "suggest_only", "auto_execute": False},
                "message": "Draft only. Approval is never performed by this tool.",
            },
            "submitted": False,
        },
        "Prepared a **suggest-only** block-ip draft for `198.51.100.77` on `inc-9c21`. Not submitted and not approved.",
        tags=["black_onyx_response_draft", "safety_no_approve"],
    ),
    ex(
        "sandbox_attach_confirm_12",
        "url_screenshot_sandbox",
        "Lab sandbox enabled — fetch https://staging-update.badactor.net/login for case case-710 and attach fetch metadata as a case note. Confirm the note write.",
        {
            "url": "https://staging-update.badactor.net/login",
            "max_bytes": 32768,
            "case_id": "case-710",
            "confirm": True,
        },
        {
            "enabled": True,
            "url": "https://staging-update.badactor.net/login",
            "status_code": 200,
            "content_type": "text/html",
            "content_length": 8192,
            "sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            "screenshot": {
                "format": "png",
                "sha256": "99aabbccddeeff00112233445566778899aabbccddeeff001122334455667788",
                "byte_length": 54012,
                "engine": "playwright-chromium",
            },
            "evidence_attach": {
                "note_id": "note-910",
                "case_id": "case-710",
                "status": "ok",
            },
        },
        "Sandbox fetch OK and attached note `note-910` on `case-710` with status 200 / HTML metadata and content hash `11223344…`.",
        tags=["url_screenshot_sandbox", "lab_gated", "confirm_true"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_promote_webhook_confirm_13",
        "black_onyx_case_assist",
        "Promote webhook event evt-phish-881 into a TIP case titled 'External phish report — OAuth lure'. Confirm the promote.",
        {
            "action": "promote",
            "promote_kind": "webhook",
            "event_id": "evt-phish-881",
            "title": "External phish report — OAuth lure",
            "priority": "high",
            "confirm": True,
        },
        {
            "case_id": "case-881",
            "promoted_from": "evt-phish-881",
            "title": "External phish report — OAuth lure",
            "status": "open",
        },
        "Promoted webhook `evt-phish-881` into TIP case `case-881` — *External phish report — OAuth lure* (open/high).",
        tags=["black_onyx_case_assist", "promote", "webhook", "confirm_true"],
    ),
    ex(
        "ioc_enrich_structured_stix_13",
        "black_onyx_ioc_enrich",
        "Enrich structured IOCs and export STIX: IP 198.51.100.77 and domain staging-update.badactor.net.",
        {
            "iocs": [
                {"ioc_type": "ip", "ioc_value": "198.51.100.77"},
                {"ioc_type": "domain", "ioc_value": "staging-update.badactor.net"},
            ],
            "export_stix": True,
        },
        {
            "extracted": {},
            "enrichment": {
                "198.51.100.77": [{"provider": "otx", "score": 2}],
                "staging-update.badactor.net": [
                    {"provider": "otx", "score": 3, "tags": ["c2"]}
                ],
            },
            "stix": {
                "type": "bundle",
                "id": "bundle--egress-77",
                "objects": [
                    {"type": "ipv4-addr", "value": "198.51.100.77"},
                    {"type": "domain-name", "value": "staging-update.badactor.net"},
                ],
            },
        },
        "Structured enrich: IP `198.51.100.77` (OTX 2) and domain `staging-update.badactor.net` (OTX 3, c2). STIX bundle `bundle--egress-77` ready.",
        tags=["black_onyx_ioc_enrich", "stix", "structured"],
    ),
    ex(
        "hunt_search_dns_13",
        "black_onyx_hunt",
        "Hunt OpenSearch for unusually long DNS queries that look like tunneling.",
        {
            "query": "dns.question.name:* AND length(dns.question.name) > 60",
            "mode": "search",
            "size": 30,
        },
        {
            "hits": [
                {
                    "id": "log-dns-4401",
                    "source": {
                        "host": "jump-box-7",
                        "dns.question.name": "a1b2c3d4e5f6.staging-update.badactor.net",
                        "query_len": 72,
                    },
                }
            ],
            "total": 1,
            "mode": "search",
        },
        "OpenSearch hunt returned 1 long DNS query from `jump-box-7` to `a1b2c3d4e5f6.staging-update.badactor.net` (len 72). Doc `log-dns-4401`.",
        tags=["black_onyx_hunt", "search", "dns"],
    ),
    ex(
        "model_ops_degraded_13",
        "black_onyx_model_ops",
        "Are detection models ready right now? Training job check not needed.",
        {"job_id": ""},
        {
            "models_ready": {
                "status": "degraded",
                "models": {"log-model": "http://log-model:8080"},
                "detail": "identity-model unreachable",
            },
            "training_ready": {"status": "ready"},
            "ops_models": {
                "models": [
                    {"name": "log-model", "version": "1.4.2", "status": "ready"},
                    {"name": "identity-model", "status": "unreachable"},
                ]
            },
            "training_job": None,
            "read_only": True,
        },
        "Model gateway is **degraded**: `log-model` ready, `identity-model` unreachable. Training orchestrator still ready. Read-only — no jobs started.",
        tags=["black_onyx_model_ops", "degraded"],
    ),
    ex(
        "ti_match_semantic_publish_confirm_13",
        "black_onyx_ti_match",
        "Semantically match URL https://login-secure-update.example/oauth and sync indicators to TIP for case case-881. Confirm the publish.",
        {
            "observables": [
                {
                    "type": "url",
                    "value": "https://login-secure-update.example/oauth",
                }
            ],
            "mode": "semantic",
            "publish": True,
            "confirm": True,
            "case_id": "case-881",
        },
        {
            "mode": "semantic",
            "matches": {
                "matches": [
                    {
                        "value": "https://login-secure-update.example/oauth",
                        "score": 0.84,
                        "source": "urlhaus",
                        "related": ["phish-kit-oauth-v3"],
                    }
                ]
            },
            "published": True,
            "case_id": "case-881",
            "iocs": [
                {
                    "ioc_type": "url",
                    "ioc_value": "https://login-secure-update.example/oauth",
                }
            ],
            "sync": {"status": "ok", "synced": 1},
        },
        "Semantic TI hit on the OAuth URL (0.84, urlhaus / `phish-kit-oauth-v3`). Synced 1 indicator to TIP for case `case-881`.",
        tags=["black_onyx_ti_match", "semantic", "publish", "confirm_true"],
    ),
    # Distinct from all prior rows
    ex(
        "case_assist_promote_incident_confirm_14",
        "black_onyx_case_assist",
        "Promote detection incident inc-9c21 into a TIP case titled 'Compromised mailbox — disable-user path'. Confirm the promote.",
        {
            "action": "promote",
            "promote_kind": "detection_incident",
            "incident_id": "inc-9c21",
            "title": "Compromised mailbox — disable-user path",
            "priority": "critical",
            "confirm": True,
        },
        {
            "case_id": "case-921",
            "promoted_from": "inc-9c21",
            "title": "Compromised mailbox — disable-user path",
            "status": "open",
            "priority": "critical",
        },
        "Promoted detection incident `inc-9c21` into TIP case `case-921` — *Compromised mailbox — disable-user path* (critical/open).",
        tags=["black_onyx_case_assist", "promote", "detection_incident", "confirm_true"],
    ),
    ex(
        "response_draft_submit_block_ip_14",
        "black_onyx_response_draft",
        "Queue a pending block-ip request for incident inc-9c21 targeting 198.51.100.77. Submit but do not approve.",
        {
            "incident_id": "inc-9c21",
            "playbook_id": "block-ip",
            "confirm": True,
            "dry_run": True,
        },
        {
            "submitted": True,
            "request": {"request_id": "rr-61", "status": "pending"},
            "approval_note": "Analyst must approve or reject in the response queue UI.",
            "draft": {
                "incident_id": "inc-9c21",
                "playbook_id": "block-ip",
                "dry_run": True,
                "payload": {"response_mode": "suggest_only", "auto_execute": False},
            },
        },
        "Submitted pending response request `rr-61` for `block-ip` on `inc-9c21` (suggest-only). **Not approved** — analyst action required in the response queue.",
        tags=["black_onyx_response_draft", "safety_no_approve"],
    ),
    ex(
        "rule_draft_yara_strings_14",
        "black_onyx_rule_draft",
        "Draft a YARA rule named oauth_phish_kit_strings using these string IOCs: 'login-secure-update' and 'oauth?client_id='. Tags: phishing, oauth.",
        {
            "rule_type": "yara",
            "iocs": {
                "string": ["login-secure-update", "oauth?client_id="]
            },
            "rule_name": "oauth_phish_kit_strings",
            "tags": ["phishing", "oauth"],
        },
        {
            "rule_type": "yara",
            "dry_run": True,
            "rule": (
                "rule oauth_phish_kit_strings {\n"
                "  meta:\n"
                "    author = \"black_onyx\"\n"
                "    tags = \"phishing,oauth\"\n"
                "  strings:\n"
                "    $s1 = \"login-secure-update\" ascii wide\n"
                "    $s2 = \"oauth?client_id=\" ascii wide\n"
                "  condition:\n"
                "    all of them\n"
                "}\n"
            ),
        },
        "Generated **YARA** draft `oauth_phish_kit_strings` (generate-only) matching both kit strings. Tags: phishing, oauth. Not executed against telemetry.",
        tags=["black_onyx_rule_draft", "yara", "strings"],
    ),
    ex(
        "watchlist_propose_phish_14",
        "black_onyx_watchlist_decay",
        "Propose adding domain login-secure-update.example and URL https://login-secure-update.example/oauth to the phishing-domains watchlist. Do not write yet.",
        {
            "action": "propose_add",
            "watchlist_id": "wl-phish",
            "watchlist_name": "phishing-domains",
            "items": [
                {"ioc_type": "domain", "ioc_value": "login-secure-update.example"},
                {
                    "ioc_type": "url",
                    "ioc_value": "https://login-secure-update.example/oauth",
                },
            ],
            "confirm": False,
        },
        {
            "draft": True,
            "proposal": {
                "watchlist_id": "wl-phish",
                "watchlist_name": "phishing-domains",
                "items": [
                    {"ioc_type": "domain", "ioc_value": "login-secure-update.example"},
                    {
                        "ioc_type": "url",
                        "ioc_value": "https://login-secure-update.example/oauth",
                    },
                ],
            },
            "message": "Set confirm=True to add watchlist items.",
        },
        "Watchlist add proposal for **phishing-domains** (`wl-phish`): domain + OAuth URL. Not written — confirm to apply.",
        tags=["black_onyx_watchlist_decay", "confirm_gate"],
    ),
    ex(
        "passive_dns_ns_14",
        "passive_dns_whois",
        "Pull NS records only for badactor.net — I need nameserver pivots.",
        {
            "domain": "badactor.net",
            "query_types": ["NS"],
        },
        {
            "domain": "badactor.net",
            "dns": {
                "NS": ["ns1.badactor.net.", "ns2.badactor.net."]
            },
            "whois": {
                "registrar": "Example Registrar",
                "name_servers": ["ns1.badactor.net", "ns2.badactor.net"],
            },
        },
        "`badactor.net` NS: `ns1.badactor.net`, `ns2.badactor.net`. Useful parent-zone pivots for staging-update / payload-cdn hosts.",
        tags=["passive_dns_whois", "ns"],
    ),
]


def main() -> None:
    tools_path = OUT / "tools.json"
    examples_path = OUT / "examples.jsonl"
    tools_path.write_text(json.dumps(TOOLS, indent=2) + "\n", encoding="utf-8")
    with examples_path.open("w", encoding="utf-8") as fh:
        for row in EXAMPLES:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    covered = {row["tool"] for row in EXAMPLES}
    catalog = {t["function"]["name"] for t in TOOLS}
    missing = sorted(catalog - covered)
    print(f"Wrote {tools_path} ({len(TOOLS)} tools)")
    print(f"Wrote {examples_path} ({len(EXAMPLES)} examples)")
    print(f"Tools covered: {len(covered)}/{len(catalog)}")
    if missing:
        raise SystemExit(f"Missing examples for: {missing}")


if __name__ == "__main__":
    main()
