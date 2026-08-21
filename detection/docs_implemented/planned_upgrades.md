# Planned Upgrades: Professional Cyber Defender Platform

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).
>
> **Note:** Gap / “current state” tables below are historical. Do not treat ❌ rows as the live platform inventory.


**Document version:** 1.0  
**Date:** July 26, 2026  
**Audience:** Platform, security engineering, SOC operations  
**Scope:** Roadmap to evolve AutoAnalyzer from a four-modality anomaly pipeline into a deployable, monitorable platform suitable for professional cyber defenders across heterogeneous environments.

---

## Executive summary

AutoAnalyzer today is a strong **centralized anomaly detection spine**: logs, network flows, metrics, and code changes flow through Kafka, are scored by specialist models, correlated into incidents, and surfaced in a React ops UI. Authentication, tenant isolation, RBAC, and containerized deployment (Docker Compose + Helm) are in place.

To serve **professional cyber defenders** at scale, the platform needs to grow in five directions that modern SOC platforms treat as baseline:

1. **Collection at the edge** — lightweight agents and forwarders for Linux, Windows, and macOS hosts, plus network sensors and application telemetry.
2. **Threat intelligence enrichment** — STIX/TAXII and curated feed ingestion, IOC matching, confidence/TLP filtering, and indicator lifecycle management.
3. **Operational context** — asset inventory, process/service state, firewall posture, and MITRE ATT&CK mapping so alerts are actionable, not just anomalous.
4. **Controlled response** — SOAR-style playbooks with human approval gates for firewall blocks, host isolation, account disable, and ticket creation.
5. **Production-grade operations** — multi-site deployment topologies, platform observability (metrics/logs/traces/SLOs), and air-gapped update paths.

This document maps industry patterns (SIEM/SOAR, OSA Security Monitoring and Response, MITRE ATT&CK coverage workflows, TAXII 2.1 ingestion) to concrete upgrades that extend—not replace—the existing architecture.

**References consulted:**

- [Australian Cyber Security Centre — Implementing SIEM and SOAR platforms](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/implementing-siem-soar-platforms/implementing-siem-and-soar-platforms-practitioner-guidance)
- [Canadian Centre for Cyber Security — Using SIEM solutions (ITSM.80.024)](https://www.cyber.gov.ca/sites/default/files/itsm80024-e.pdf)
- [Open Security Architecture — Security Monitoring and Response (SP-031)](https://www.opensecurityarchitecture.org/patterns/sp-031/)
- [osquery documentation — deployment and configuration](https://osquery.readthedocs.io/en/stable/deployment/configuration/)
- [Microsoft Sentinel — Connect STIX/TAXII threat intelligence feeds](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-taxii)
- [AuroraSOC deployment topologies](https://docs.aurorasoc.ahmeddwalid.me/docs/user/concepts/deployment-topologies)
- [MITRE ATT&CK + AI for SOC teams (ObsidianOne)](https://obsidianone.ai/blog/mitre-ai-guide.html)

---

## Current state (baseline)

| Capability | Status | Notes |
|---|---|---|
| Log anomaly detection | ✅ Implemented | `log-processor` → `log-model` |
| Network flow anomaly | ✅ Implemented | `flow-processor` → `network-model` |
| Metrics anomaly | ✅ Implemented | `metrics-processor` → `metrics-model` |
| Code change risk | ✅ Implemented | `code-processor` → `code-model` |
| Multi-model correlation | ✅ Implemented | `correlation-engine` + Redis buckets |
| Incident API + RBAC | ✅ Implemented | OIDC JWT, service keys, roles |
| Docker Compose + Helm | ✅ Partial | App tier only; data plane external in Helm |
| OpenTelemetry tracing | ⚠️ Partial | 3 services; collector exports to `debug` only |
| Endpoint agents | ❌ Missing | Collectors documented as external only |
| Process / EDR telemetry | ❌ Missing | No modality, schema, or model |
| Threat intel feeds | ❌ Missing | No STIX/TAXII, IOC store, or enrichment |
| Firewall control | ❌ Out of scope (MVP) | Explicit non-goal in spec §2.2 |
| SOAR / response playbooks | ❌ Missing | Notifications only (webhook/email) |
| MITRE ATT&CK mapping | ❌ Missing | Findings lack technique IDs |
| Cross-platform host deployment | ❌ Missing | Server-side containers only |
| Platform metrics/SLO dashboard | ❌ Missing | No bundled Prometheus/Grafana |

---

## 1. Deployment and multi-environment operations

Professional defenders need the platform to run reliably across **single-site labs, multi-office enterprises, hybrid cloud, MSSP tenants, and air-gapped environments**. Industry guidance emphasizes establishing a network baseline before go-live, synchronizing all log sources to a central time server, and monitoring for **telemetry gaps** (systems that stop sending logs).

### 1.1 Deployment topologies to support

| Topology | Use case | AutoAnalyzer changes |
|---|---|---|
| **Standalone single-site** | Small SOC, pilot | Hardened Compose profile with bundled infra (Postgres, Redpanda, Redis, OpenSearch) |
| **Enterprise + existing SIEM** | Splunk/Elastic/QRadar already deployed | Add **SIEM bridge connectors** (syslog, HEC, Logstash output) into `ingestion-gateway` |
| **Multi-site federation** | Branch offices + HQ | Per-site Kafka ingest + federated incident search from HQ `incident-api` |
| **Hybrid cloud + on-prem** | Cloud audit logs + datacenter hosts | Cloud ingest workers (AWS CloudTrail, Azure Activity, GCP Audit) as new processors |
| **Air-gapped / classified** | No outbound internet | Offline TI bundles, signed model artifacts, USB-based rule updates |
| **MSSP multi-tenant** | Managed SOC for customers | Stronger tenant isolation, per-tenant quotas, rollup dashboards, billing metrics |

**Suggested implementation:**

- **Deployment packaging** — Keep Docker Compose and `deploy/detection/helm/` as the supported deployment paths.
- **`infrastructure/helm/anomaly-platform/`** — Add optional subcharts or external dependency docs for Redpanda, Postgres, Redis, OpenSearch (today Helm assumes external brokers). Stub Terraform inputs: `deploy/detection/terraform/`.
- **Environment profiles** — `values-dev.yaml`, `values-prod.yaml`, `values-airgap.yaml` with feature flags (OIDC required, API keys mandatory, no external TI polling).
- **Site identity** — Add `site_id` to event envelope (`contracts/common/event_envelope.schema.json`) for federated search and incident provenance.

### 1.2 Cross-platform host and server deployment

Today all services are Linux containers. Defenders monitor **Windows servers, Linux servers, macOS endpoints, and network appliances**. Recommended approach: **do not rebuild a full EDR**; ship **thin collectors** and a **config distribution service**.

| OS | Collector strategy | Telemetry path |
|---|---|---|
| **Linux** | osqueryd + Vector/Fluent Bit | Scheduled queries (processes, sockets, crontab, packages) + journald/app logs → gateway |
| **Windows** | osqueryd + OpenTelemetry Collector or Winlogbeat | Event Log (Security, Sysmon, PowerShell), process events → gateway |
| **macOS** | osqueryd (EndpointSecurity) + Unified Logging forwarder | Process/file/socket events → gateway |
| **Network appliances** | Syslog/NetFlow/IPFIX receivers | Zeek, Suricata EVE, firewall syslog → `network.raw` / new `security.raw` |

**New components:**

```
collectors/
  osquery/
    packs/                    # Scheduled query packs (incident-response, vuln, hardware)
    config/                   # Platform-specific fragments (linux, windows, darwin)
  vector/
    profiles/                 # Per-OS ship configs → ingestion-gateway
  installer/
    linux/install.sh
    windows/install.ps1
    macos/install.sh
services/
  agent-config-service/       # TLS config distribution for osquery (optional Phase 2)
```

**osquery integration pattern** (industry standard):

- **osqueryi** — Ad-hoc triage on a single host.
- **osqueryd** — Scheduled fleet queries; diffs shipped to log pipeline.
- **TLS config plugin** — Central policy distribution (AiSOC and Wazuh ecosystems use similar patterns).
- **Event tables** — Enable `process_events`, `socket_events`, `file_events` where OS audit backends allow (Linux audit, macOS EndpointSecurity, Windows ETW).

Reference: [osquery configuration](https://osquery.readthedocs.io/en/stable/deployment/configuration/)

### 1.3 Time synchronization and telemetry health

CCCS and ACSC guidance both require **consistent timestamps** across sources. Add:

- **NTP requirement** documented in deployment guide (all collectors and servers).
- **`data-health` service enhancements** — Per-source last-seen timestamps, expected EPS/rates, gap alerts when a tenant/asset stops reporting.
- **Ingestion lag metrics** — Kafka consumer lag per topic exposed to Prometheus.

---

## 2. Endpoint and process monitoring

Process visibility is essential for detecting persistence, lateral movement, and credential abuse. AutoAnalyzer currently has **no host-state or process modality**.

### 2.1 New modality: `host-state` (recommended)

Add a fifth pipeline parallel to logs/network/metrics/code:

```
host-state.raw → host-state-processor → host-state.features → host-state-model → findings.host-state
```

**Canonical schema** (`contracts/host-state/`):

| Event type | Source | Example fields |
|---|---|---|
| `process_snapshot` | osquery `processes` | pid, name, path, user, start_time, parent |
| `process_event` | osquery events / Sysmon EID 1 | action, cmdline, hashes |
| `socket_snapshot` | `listening_ports`, `process_open_sockets` | local/remote, protocol, state |
| `autorun_snapshot` | services, scheduled_tasks, launchd, registry | persistence paths |
| `user_session` | logon events | user, logon_type, source_ip |

**Detection approaches (layered):**

1. **Deterministic rules** (Phase 1) — Sigma-style checks in processor: suspicious parent-child (e.g., `winword.exe` → `powershell.exe`), rare binaries, new listening ports.
2. **Unsupervised anomaly model** (Phase 2) — Baseline process/service graphs per asset; sequence model on process create chains.
3. **TI correlation** (Phase 3) — Match process hashes, domains, IPs against STIX indicators.

### 2.2 Sysmon and Windows Event Log integration

For Windows-heavy environments, **Sysmon** is the de facto standard for process, network, and file telemetry. Recommended path:

- Document a **reference Sysmon config** (SwiftOnSecurity-style, tuned for noise).
- Add `windows-events-processor` or extend `log-processor` with a **Sysmon/Security channel normalizer** that maps EIDs 1, 3, 10, 11, 22 into `host-state` events.
- Do **not** replace Microsoft Defender or CrowdStrike; integrate via webhooks/API for isolation actions (see §6).

### 2.3 Relationship to EDR

Per MVP non-goals, AutoAnalyzer is **not** a full EDR replacement. Position it as:

- **Detection + correlation layer** that ingests EDR alerts (CrowdStrike, SentinelOne, Defender) as a supplemental finding source.
- **Triage accelerator** using osquery for live response queries initiated from the incident UI.
- **Gap filler** for assets without commercial EDR (OT, legacy servers, lab VMs).

---

## 3. Network monitoring enhancements

Network monitoring is partially implemented via flow features. Professional defenders also need **IDS alerts, DNS analytics, firewall logs, and east-west visibility**.

### 3.1 Extend network telemetry sources

| Source | Ingest path | Value |
|---|---|---|
| **Zeek** | Already referenced in spec | conn.log, dns.log, http.log → enrich `network.features` |
| **Suricata EVE JSON** | New ingest endpoint | Signature and anomaly alerts with SID, severity |
| **DNS query logs** | New `dns.raw` topic | Tunneling, DGA, rare domains |
| **Firewall syslog** | New `firewall.raw` topic | Allow/deny decisions, rule hits, geo context |
| **Proxy / SWG logs** | Extend `logs.raw` or new topic | URL categorization, blocked downloads |
| **Cloud VPC flow logs** | Cloud ingest worker | AWS VPC Flow Logs, Azure NSG flow logs |

**Processor upgrades (`flow-processor`):**

- Add **deterministic detectors** already started in `detectors.py`: port scan, beaconing, rare JA3/SNI (if TLS metadata available).
- **Cross-flow correlation**: same external IP touching multiple internal hosts within a window → escalate correlation-engine score.
- **Baseline peer graphs** per service: flag new outbound destinations after deployment freeze periods.

### 3.2 Network sensor deployment

For defenders who cannot span-tap everything:

- **Zeek on mirror/ TAP** at datacenter edge and critical VLANs.
- **NetFlow/IPFIX** from routers and switches (lower fidelity, lower cost).
- **Host-based flow visibility** via osquery `process_open_sockets` where network taps are unavailable.

Document reference architectures in `docs/deployment/network-sensors.md`.

---

## 4. Application monitoring

Application monitoring bridges SRE and security use cases. Metrics and logs exist; add **application-aware context** so defenders can distinguish a deploy regression from an attack.

### 4.1 OpenTelemetry application signals

Extend optional OTEL overlay (`docker-compose.otel.yml`):

| Signal | Use for defenders |
|---|---|
| **Traces** | Attack path reconstruction (which service handled a suspicious request) |
| **Metrics** | Error rate spikes, auth failure rates, latency anomalies |
| **Logs** | Structured app logs with trace correlation |

**Implementation:**

- Ship **OTEL Collector configs** for app teams (`infrastructure/otel/app-instrumentation/`).
- Add `service_id` / `deployment_id` propagation from OTEL resource attributes into event envelope (partially supported via deployment events).
- **`application-processor`** — Normalize OTEL logs/metrics/traces into existing modalities or a dedicated `application.features` topic.

### 4.2 Application security events

Ingest security-relevant app events as first-class data:

- Authentication failures, lockouts, privilege elevation.
- WAF blocks (ModSecurity, Cloudflare, AWS WAF).
- API gateway anomalies (rate limit hits, invalid tokens).
- Database audit logs (sensitive table access).

Map these to **MITRE techniques** (e.g., T1110 Brute Force, T1078 Valid Accounts) in the correlation engine.

### 4.3 Dependency and runtime posture

Complement code-model (diff risk) with **runtime application posture**:

- Exposed admin endpoints discovered by periodic scanning.
- Unexpected outbound connections from app containers.
- Certificate expiry and TLS version drift.

Consider integrating **OWASP Dependency-Track** or **GitHub Dependabot** webhooks as supplemental code/deploy context (not a replacement for Semgrep).

---

## 5. Threat intelligence integration

CCCS guidance explicitly calls out matching telemetry against **indicators of compromise from threat feeds**. Today AutoAnalyzer has no TI layer.

### 5.1 Threat intel service (new)

```
services/threat-intel-service/
  app/
    ingest/          # TAXII 2.1 pollers, MISP sync, static STIX bundles
    store/           # Indicator DB (Postgres or Redis + OpenSearch)
    enrich/          # Match IPs, domains, hashes, URLs against events
    expire/          # Indicator lifecycle / valid_until enforcement
    api/             # CRUD, search, manual upload, feed health
```

**Feed types to support (priority order):**

| Feed | Protocol | Notes |
|---|---|---|
| **CISA KEV** | JSON/STIX bundle | Known exploited vulns; high-confidence prioritization |
| **MISP** | REST / STIX export | Common in ISACs and enterprise SOCs |
| **TAXII 2.1** | Standard collections | AlienVault OTX, SOCRadar, commercial ISAC feeds |
| **Commercial TIP** | Vendor API | Recorded Future, VirusTotal Intelligence (API enrichment) |
| **Internal TI** | Manual / CSV / STIX upload | Analyst-curated blocklists |

**Implementation standards:**

- Parse STIX 2.1 `indicator` objects; extract observables (IPv4/6, domain, URL, file hash, email).
- Handle TAXII pagination via `next` cursor; track `added_after` for incremental poll.
- Apply **TLP and confidence filters** before ingestion (drop TLP:RED in wrong tenant, low-confidence noise).
- **Deduplicate on observable pattern**, not STIX object ID (Elastic/Sentinel best practice).
- **Auto-expire** indicators when `valid_until` passes; propagate removal to firewall block lists.

References: [Microsoft Sentinel TAXII connector](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-taxii), [STIX/TAXII integration guide](https://clawgrc.com/skills/implementing-stix-taxii-feed-integration)

### 5.2 Enrichment pipeline integration

TI enrichment should occur at **two points**:

1. **Ingest-time (fast path)** — `ingestion-gateway` or processors tag events with `ti_matches[]` if observable hits active indicator.
2. **Correlation-time (deep path)** — `correlation-engine` boosts incident `risk_score` when multiple findings match same campaign/threat-actor object from STIX `relationship`.

**Finding/incident schema additions:**

```json
{
  "threat_intel": {
    "matched_indicators": [{"id": "...", "type": "ipv4", "value": "...", "confidence": 90, "source": "cisa-kev"}],
    "campaigns": [],
    "tlp": "amber"
  }
}
```

### 5.3 Air-gapped threat intel

For classified/disconnected sites (AuroraSOC Topology 4 pattern):

- **`tools/scripts/airgap/generate-ti-bundle.sh`** — Download feeds on connected staging machine, sign bundle (cosign/minisign), transfer via USB.
- **`threat-intel-service` airgap mode** — Import signed bundles only; disable outbound TAXII polling.
- Version and audit every bundle import.

---

## 6. Firewall configuration, monitoring, and controlled response

MVP explicitly excluded automatic blocking. For **professional defenders**, the upgrade is **monitored posture + optional, gated response**—not autonomous blocking on every anomaly score.

### 6.1 Firewall telemetry (monitor)

Ingest and normalize:

| Vendor | Method | Events |
|---|---|---|
| **pfSense / OPNsense** | Syslog | Block/pass, rule number, interface |
| **iptables/nftables** | syslog or ulogd | Dropped packets, rate limits |
| **Palo Alto / Fortinet / Cisco** | Syslog CEF/LEEF | Threat IDs, app-id, user-id |
| **Cloud SG / NACL / WAF** | API poll or flow logs | Rule changes, deny counts |

New topic: `firewall.raw` → `firewall-processor` → `firewall.features` + deterministic findings (e.g., spike in denied connections from single source, rule change outside change window).

### 6.2 Firewall control (respond — gated)

Add **`services/response-orchestrator/`** (SOAR-lite):

```yaml
# playbooks/block-ip-pfSense.yaml
trigger:
  incident_severity: [high, critical]
  mitre: [T1071, T1048]
  ti_confidence_min: 80
approval: required   # human-in-the-loop for production
steps:
  - enrich: virustotal_ip
  - condition: "ti.confidence >= 80 and asset.criticality >= 7"
  - action: pfsense_add_alias
    params: { alias: "autoanalyzer-block", ip: "{{ finding.context.remote_ip }}", ttl: 24h }
  - notify: webhook
  - audit: true
```

**Supported action adapters (Phase 1):**

| Action | Integration |
|---|---|
| `block_ip` | pfSense/OPNsense API, iptables script (local agent) |
| `unblock_ip` | TTL-based rollback job |
| `disable_user` | Active Directory / Azure AD / Okta API |
| `isolate_host` | Defender API, CrowdStrike API, Wazuh active response |
| `create_ticket` | Jira, ServiceNow, PagerDuty |
| `notify` | Existing `notification-service` |

**Safety requirements (industry SOAR best practice):**

- **Human approval gate** for all containment actions in production (`approval: required`).
- **Dry-run mode** default in dev/staging.
- **Full audit trail** — who approved, what changed, rollback timestamp.
- **Scope limits** — blocklist max size, TTL on all blocks, never block RFC1918 management ranges.
- **Confidence thresholds** — only high-confidence TI or multi-model correlated incidents trigger auto-suggest, not raw anomaly alone.

References: [AiSOC playbook types](https://github.com/beenuar/AiSOC/tree/main/playbooks), [SOC playbooks (YAML)](https://github.com/cramir/soc-playbooks), [Chronicle SOAR playbook patterns](https://oneuptime.com/blog/post/2026-02-17-how-to-use-chronicle-soar-playbooks-for-automated-incident-response/view)

### 6.3 Policy drift detection

Monitor firewall **configuration changes**, not just traffic:

- Poll API for rule diffs on schedule.
- Correlate rule changes with change-management tickets.
- Alert when `any/any` rules appear or logging is disabled on a segment.

---

## 7. Detection, correlation, and MITRE ATT&CK

Professional SOC workflows require **common language** for incidents. MITRE ATT&CK is the industry standard for classifying techniques and measuring detection coverage.

### 7.1 ATT&CK mapping for findings and incidents

Add to `correlation-engine` and finding schemas:

- `mitre_tactics: ["TA0001"]`
- `mitre_techniques: ["T1059.001", "T1071.004"]`
- `mitre_confidence: 0.0–1.0`

**Mapping sources (layered):**

1. **Rule-based** — Map deterministic detectors (port scan → T1046, brute force → T1110).
2. **Model metadata** — Train code/log/network models with weak labels where feasible.
3. **LLM enrichment (optional, offline)** — Local LLM explains technique and suggests investigation steps (air-gap friendly with Ollama); never auto-execute responses from LLM output alone.

Reference: [MITRE ATT&CK + AI guide](https://obsidianone.ai/blog/mitre-ai-guide.html)

### 7.2 Detection coverage dashboard

New frontend page: **ATT&CK Coverage**

- Heat map of techniques vs. detection depth: Alert-only / AI-enriched / Auto-response-ready.
- Quarterly gap analysis export (CSV/STIX report).
- Integration with **Atomic Red Team** or **MITRE Caldera** for validation runs (documented procedure, not bundled exploits).

### 7.3 Correlation engine upgrades

Extend existing Redis-backed correlation:

- **Cross-modality kill chains** — e.g., code deploy + metric spike + new outbound flow within 30 minutes.
- **Entity graph** — Link users, hosts, IPs, domains across findings (store in OpenSearch or graph DB).
- **TI-boosted scoring** — Increase `risk_score` when findings match active campaign indicators.
- **Suppression rules** — Maintenance windows, expected change tickets, analyst false-positive feedback (persisted per tenant).

---

## 8. Platform observability and monitoring

Defenders cannot trust detections from a platform they cannot monitor. Today OTEL is partial and there is no bundled metrics stack.

### 8.1 Observability stack (recommended bundle)

Add optional Compose overlay `docker-compose.observability.yml`:

| Component | Purpose |
|---|---|
| **Prometheus** | Scrape `/metrics` from all services |
| **Grafana** | SOC + platform dashboards |
| **Loki + Promtail** | Centralized service logs |
| **Jaeger or Tempo** | Trace storage (replace OTEL `debug` exporter) |
| **Alertmanager** | Route platform alerts to on-call |

**Key platform SLOs to instrument:**

| Metric | Target |
|---|---|
| Ingestion gateway availability | 99.9% |
| Kafka consumer lag (per topic) | < 60s p95 |
| Inference latency | < 2s p95 per message |
| Incident API p95 | < 250ms (per spec) |
| DLQ rate | Alert if > 0.1% of ingest |
| TI feed freshness | Alert if stale > 2× poll interval |
| Model gateway error rate | < 0.5% |

### 8.2 Extend OpenTelemetry

- Instrument **all services** (today: incident-api, correlation-engine, model-gateway only).
- Standardize trace context propagation over Kafka headers.
- Add **business spans**: `ingest.validate`, `correlate.publish`, `ti.enrich`, `response.execute`.
- Export to OTLP endpoint (Jaeger/Tempo/Grafana Cloud).

Package: extend `packages/black_onyx_otel/` with metrics helpers (Prometheus counters/histograms).

### 8.3 Health and ops API expansion

Extend `incident-api` `/ops` endpoints:

- Per-service build version, config fingerprint, last successful TI poll.
- Per-tenant ingest EPS, finding rate, incident rate.
- **Synthetic probes** — Periodic canary event through full pipeline; alert if end-to-end latency exceeds SLO.

---

## 9. Professional defender UX and workflows

### 9.1 Incident investigation workspace

Upgrade frontend incident detail view:

- **Unified timeline** — Logs, flows, metrics, code, host-state, TI hits on one axis.
- **Entity panel** — Pivot by IP, user, host, domain, hash.
- **Evidence export** — STIX incident bundle, PDF summary for compliance.
- **Investigation notes** — Markdown comments with audit trail (partially exists via incident comments).
- **One-click live query** — Trigger osquery distributed query against asset (via agent-config-service).

### 9.2 Triage queues and SLAs

- Priority queues by severity × asset criticality × TI match.
- SLA timers (time-to-acknowledge, time-to-contain) with escalation to notification-service.
- Shift handoff view (open incidents, in-progress investigations).

### 9.3 Feedback loop for model quality

Analyst feedback (`true_positive`, `false_positive`, `expected_change`) should:

- Feed **threshold calibration** per tenant/service.
- Suppress repeat false positives (fingerprint-based).
- Optionally export labeled datasets for model retraining (`training-orchestrator` integration).

---

## 10. Security and compliance hardening for production

Building on recent OIDC/RBAC/service-key work:

| Item | Action |
|---|---|
| **Production defaults** | Fail closed: `OIDC_DISABLED=false`, require API keys, no default `dev-ingest-key` |
| **Asset registry auth** | Parity with incident-api (OIDC + RBAC) |
| **mTLS service mesh** | Optional Istio/Linkerd for inter-service traffic in K8s |
| **Secrets management** | Vault / K8s External Secrets instead of plain env vars |
| **Audit logging** | Immutable audit for admin actions, playbook approvals, TI imports |
| **Data retention** | Documented policies per modality; OpenSearch ILM + Kafka retention |
| **PII handling** | Extend log masking; configurable redaction per tenant jurisdiction |
| **Signed artifacts** | cosign for container images and air-gap TI/model bundles |

---

## 11. Integration with existing SIEM / SOAR ecosystems

Many enterprises will keep Splunk, Elastic, Sentinel, or QRadar as the **system of record**. AutoAnalyzer should integrate as an **intelligent detection and correlation engine**, not require rip-and-replace.

| Direction | Integration |
|---|---|
| **Inbound** | Pull alerts/events from SIEM via API or syslog for supplemental correlation |
| **Outbound** | Push incidents/findings as CEF/JSON syslog, STIX bundles, or webhook |
| **SOAR** | Export playbooks to YAML; trigger external SOAR (Cortex XSOAR, Tines, Splunk SOAR) via webhook with standardized incident payload |
| **Ticketing** | Bi-directional Jira/ServiceNow sync for incident lifecycle |

Add `services/integration-hub/` with connector plugins following a registry pattern (similar to AiSOC's connector catalog).

---

## 12. Phased roadmap

### Phase 1 — Defender-ready foundation (8–10 weeks)

**Goal:** Deploy across heterogeneous servers with TI enrichment and platform observability.

| # | Deliverable | Priority |
|---|---|---|
| 1.1 | Collector packages (osquery + Vector) for Linux/Windows/macOS | P0 |
| 1.2 | `host-state` schema + processor + deterministic rules | P0 |
| 1.3 | `threat-intel-service` with CISA KEV + TAXII 2.1 + manual STIX upload | P0 |
| 1.4 | TI enrichment in correlation-engine and incident UI | P0 |
| 1.5 | `docker-compose.observability.yml` (Prometheus/Grafana/Loki/Jaeger) | P0 |
| 1.6 | OTEL instrumentation on all services | P1 |
| 1.7 | MITRE ATT&CK mapping (rule-based) for existing detectors | P1 |
| 1.8 | Production security defaults + asset-registry OIDC | P1 |
| 1.9 | Helm subchart docs or optional bundled infra | P1 |

### Phase 2 — Network, firewall, and application depth (8–10 weeks)

**Goal:** Full network defender visibility and application-aware detections.

| # | Deliverable | Priority |
|---|---|---|
| 2.1 | Suricata/Zeek/DNS/firewall syslog ingest | P0 |
| 2.2 | `firewall-processor` + rule-change detection | P0 |
| 2.3 | OTEL application signal normalization | P1 |
| 2.4 | WAF/proxy/auth event ingest | P1 |
| 2.5 | Entity graph in correlation-engine | P1 |
| 2.6 | ATT&CK coverage dashboard | P2 |
| 2.7 | SIEM outbound connector (syslog/STIX webhook) | P1 |

### Phase 3 — Controlled response and enterprise scale (10–12 weeks)

**Goal:** SOAR-lite response with approval gates; multi-site and air-gap.

| # | Deliverable | Priority |
|---|---|---|
| 3.1 | `response-orchestrator` + playbook YAML schema | P0 |
| 3.2 | pfSense/OPNsense + AD/Okta action adapters | P0 |
| 3.3 | EDR isolate adapter (Defender/CrowdStrike API) | P1 |
| 3.4 | Human approval UI + audit trail | P0 |
| 3.5 | Multi-site `site_id` + federated incident search | P1 |
| 3.6 | Air-gap TI/model bundle import | P1 |
| 3.7 | MSSP tenant rollup dashboards | P2 |
| 3.8 | Validated Compose/Helm environment profiles | P2 |

### Phase 4 — Advanced detection and validation (ongoing)

| # | Deliverable | Priority |
|---|---|---|
| 4.1 | `host-state` anomaly model | P2 |
| 4.2 | LLM investigation assistant (local/air-gap) | P2 |
| 4.3 | Caldera/Atomic Red Team validation harness | P2 |
| 4.4 | Integration hub (Splunk, Elastic, Sentinel connectors) | P2 |
| 4.5 | host-state + network cross-model kill chain rules | P1 |

---

## 13. Suggested repository layout (target)

```
AutoAnalyzer/
  collectors/                    # NEW — osquery packs, Vector profiles, installers
  contracts/
    host-state/                  # NEW
    firewall/                    # NEW
    threat-intel/                # NEW — STIX indicator mirror schema
  services/
    threat-intel-service/        # NEW
    response-orchestrator/       # NEW
    host-state-processor/        # NEW
    firewall-processor/          # NEW
    integration-hub/             # NEW (Phase 4)
    agent-config-service/        # NEW (optional)
  infrastructure/
    docker-compose/
      docker-compose.observability.yml   # NEW
      docker-compose.agents.yml          # NEW — reference agent sidecar stack
    helm/anomaly-platform/
      charts/                            # Optional bundled infra
    terraform/                           # Real modules (replace stub)
  docs/
    deployment/
      network-sensors.md
      cross-platform-agents.md
      air-gap.md
      siem-integration.md
    defender/
      mitre-coverage.md
      playbook-authoring.md
  playbooks/                     # NEW — versioned response playbooks
    packs/v1/
  planned_upgrades.md            # This document
```

---

## 14. Success criteria (professional deployment)

| Metric | Target |
|---|---|
| Supported host OS for collection | Linux, Windows, macOS |
| TI feed types | ≥ 3 (KEV + TAXII + manual STIX) |
| Mean time to enrich incident with TI | < 30 seconds |
| Platform observability | 100% services with metrics + traces |
| Containment action audit coverage | 100% with approval record |
| ATT&CK technique mapping (deterministic detections) | ≥ 80% of rules |
| Air-gap operational mode | Documented and tested |
| SIEM outbound integration | ≥ 1 vendor connector |

---

## 15. What not to build (stay focused)

To avoid scope collapse, continue treating these as **integrate, don't rebuild**:

- Full SIEM log storage at petabyte scale → partner with OpenSearch/Elastic/Splunk; AutoAnalyzer owns **detection + correlation**.
- Commercial EDR agent → integrate via API; ship osquery for gap coverage only.
- Vulnerability scanner → ingest results from Tenable/Qualys/Nessus.
- Full SOAR with 200 integrations → SOAR-lite with top 5 actions + webhook to external SOAR.
- Autonomous blocking on ML anomaly score alone → always require TI match or multi-model correlation + approval.

---

## 16. Immediate next steps (recommended sprint)

1. **Create `contracts/host-state/` and `contracts/threat-intel/`** — Unblocks processors and TI service in parallel.
2. **Scaffold `services/threat-intel-service/`** — Start with CISA KEV JSON + STIX file upload; add TAXII poller next.
3. **Add `collectors/osquery/` reference pack** — Document install for Linux/Windows/macOS pushing to existing `ingestion-gateway`.
4. **Add `docker-compose.observability.yml`** — Prometheus + Grafana with dashboards for Kafka lag, DLQ rate, inference latency.
5. **Add MITRE technique IDs to existing deterministic detectors** in `flow-processor/app/detectors.py` and code-processor heuristics.
6. **Draft first playbook** — `playbooks/packs/v1/block-ip-pfsense.yaml` with `approval: required` and dry-run default.

---

*This is a living roadmap. Update as components ship and as defender feedback from pilot deployments informs priorities.*
