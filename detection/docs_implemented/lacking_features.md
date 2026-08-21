# Lacking Features: What Cyber Pros Expect (Open Source / Free)

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).
>
> **Note:** Many listed gaps (TI, SOAR, OpenSearch hunt, ATT&CK, host-state) are now partially or fully shipped. Treat this file as a historical gap analysis, not a current inventory.


**Document version:** 1.0  
**Date:** July 27, 2026  
**Purpose:** Catalog capabilities cybersecurity professionals typically want in a SOC / detection platform that AutoAnalyzer does **not** yet provide — restricted to options that can be built or integrated with **open-source / free** software (no paid SaaS required).

**Scope note:** “Free” here means open-source or free-to-self-host community editions. Commercial feeds/APIs (VirusTotal paid tiers, etc.) may be optional enrichers but are not required for the feature to exist.

**Related:** `planned_upgrades.md`, `networking_upgrades.md`, `suggested_assistants_sources.md`, `cli_tools_info.md`, `suggested_models.md`.

---

## Executive summary

AutoAnalyzer is a strong **multi-modal anomaly → correlation → incident** spine. Practitioner OSS SOC stacks (Wazuh, Security Onion, TheHive + Cortex + MISP + Shuffle, OpenCTI, Velociraptor, SigmaHQ, etc.) show that analysts also expect:

1. **Endpoint agents** and host controls (FIM, SCA, vuln inventory, live response)  
2. **Threat intelligence** (STIX/TAXII, IOC matching, sharing)  
3. **Detection-as-code** (Sigma / YARA / Suricata rules), not only ML  
4. **Case management / SOAR** beyond status + webhook  
5. **Threat hunting** workspaces and DFIR collection  
6. **ATT&CK coverage**, compliance views, and searchable history  
7. **NSM** (Zeek/Suricata/PCAP) and **platform observability**  

This file lists those gaps, points at free OSS to fill them, and suggests integrate-vs-build.

---

## Already strong (do not treat as gaps)

| Capability | Status |
|---|---|
| Log / network-flow / metrics / code anomaly scoring | Implemented |
| Correlation → incidents | Implemented |
| Ops UI (incidents, findings, assets, models) | Implemented |
| Tenant header + RBAC + optional OIDC | Implemented (dev defaults soft) |
| Webhook / email notifications | Implemented |
| Compose + Helm packaging | Partial / usable |

---

## Priority legend

| Priority | Meaning |
|---|---|
| **P0** | Analysts ask for this in week-one SOC use |
| **P1** | Expected for serious / production defender use |
| **P2** | Differentiator / scale / compliance polish |

---

## 1. Endpoint visibility & host security — **P0**

**Why pros want it:** Most investigations start on a host (process, file, persistence), not only in flow windows. Wazuh’s free agent model covers FIM, config assessment, malware-oriented rules, vuln inventory, and active response ([Wazuh use cases](https://documentation.wazuh.com/current/getting-started/use-cases/index.html)).

| Lacking feature | Free OSS to leverage | Integrate vs build |
|---|---|---|
| Cross-OS endpoint agent | [osquery](https://www.osquery.io/), [Wazuh agent](https://wazuh.com/), Vector/Fluent Bit | Prefer **integrate** agents → gateway |
| File integrity monitoring (FIM) | Wazuh FIM, OSSEC heritage, AIDE | Integrate or ingest FIM events |
| Security configuration assessment (CIS-like) | Wazuh SCA | Integrate |
| Host vulnerability inventory (CVE ↔ package) | Wazuh vuln detection (NVD-oriented), [Trivy](https://github.com/aquasecurity/trivy), [Grype](https://github.com/anchore/grype) | Integrate scanners → findings |
| Process / Sysmon / audit telemetry | Sysmon + osquery; Linux audit | New `host-state` modality |
| Active response on host | Wazuh Active Response | SOAR adapter, not reinvent |

**AutoAnalyzer gap:** No agents, no FIM/SCA/vuln UI, no host-state pipeline.

---

## 2. Threat intelligence platform (TIP) — **P0**

**Why pros want it:** Free community stacks always include MISP and/or OpenCTI for IOC sharing, STIX relationships, and sightings ([MISP vs OpenCTI](https://www.cosive.com/misp-vs-opencti)).

| Lacking feature | Free OSS | Notes |
|---|---|---|
| STIX/TAXII ingest | [MISP](https://www.misp-project.org/), [OpenCTI](https://github.com/OpenCTI-Platform/opencti), taxii2 clients | CISA KEV JSON is free too |
| IOC store + expiry | MISP / OpenCTI / custom Postgres | Match IP/domain/hash/JA3 |
| Enrichment on alert | Cortex analyzers (OSS), AbuseIPDB free tier (API limits) | Shuffle/TheHive pattern |
| Indicator ↔ case linking | OpenCTI case management / TheHive observables | Sightings workflow |
| Community sharing | MISP sync | Optional for ISACs |

**AutoAnalyzer gap:** No TI service, enrichment, or IOC match in correlation.

---

## 3. Detection-as-code (rules, not only ML) — **P0**

**Why pros want it:** ML alone is hard to audit; Sigma is the open portable detection language ([Sigma explained](https://panther.com/blog/your-guide-to-the-sigma-rules-open-standard-for-threat-detection)); Suricata/YARA cover network and file malware.

| Lacking feature | Free OSS | Notes |
|---|---|---|
| Sigma rule engine | [SigmaHQ](https://github.com/SigmaHQ/sigma), pySigma / backends | Compile to Lucene/SQL/OpenSearch |
| Curated rule packs | SigmaHQ rules, Emerging Threats Open (Suricata) | Community updates |
| YARA scanning | [VirusTotal/yara](https://github.com/VirusTotal/yara), Loki (Neo23x0) | File/memory on demand |
| Suricata IDS signatures | [Suricata](https://suricata.io/) + ET Open | Network NSM |
| Rule UI / versioning / git sync | Detection-as-code repos + CI | Pros expect PR review of rules |
| Unit tests for detections | [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), custom | Verify rules fire |

**AutoAnalyzer gap:** Heuristics + ML only; Semgrep scaffold thin; no Sigma/YARA product surface.

---

## 4. Case management & IR workflow — **P0**

**Why pros want it:** Classic OSS SOC labs pair SIEM alerts with [TheHive](https://thehive-project.org/) for cases, tasks, observables, and TTLs — not just “incident status.”

| Lacking feature | Free OSS | Notes |
|---|---|---|
| Formal cases (tasks, TTPs, observables) | TheHive 5 (community), OpenCTI cases | Beyond acknowledge/resolve |
| Multi-analyst assignment queues | TheHive / custom | Shift handoff |
| SLA timers / escalation | TheHive + Shuffle | MTTA/MTTR |
| Observable management (hash/IP/email) | TheHive + MISP | Enrich → pivot |
| Evidence locker / attachments | MinIO + case API | Chain of custody metadata |
| Export for legal (PDF/STIX) | Custom + OpenCTI | Compliance asks |

**AutoAnalyzer gap:** Incident CRUD/comments exist; not full case/IR product.

---

## 5. SOAR / automation — **P0–P1**

**Why pros want it:** Practitioner guides automate Wazuh → Shuffle → TheHive → email/VT ([open-source SOC automation](https://rokibulroni.com/solutions/open-source-soc-stack-thehive-cortex-shuffle/)).

| Lacking feature | Free OSS | Notes |
|---|---|---|
| Playbook engine | [Shuffle](https://shuffler.io/), [n8n](https://n8n.io/) (fair-code), [Tracecat](https://github.com/TracecatHQ/tracecat), Cortex | Prefer integrate first |
| Enrichment analyzers | Cortex analyzers | Hash/IP/domain lookup |
| Approval-gated containment | Custom + firewall APIs | Matches planned SOAR-lite |
| Ticket sync | Free Jira/GitLab/GitHub APIs | Bi-directional |
| Runbook library | YAML playbooks (community packs) | MITRE-mapped steps |

**AutoAnalyzer gap:** Notifications only; no playbooks/approvals/containment.

---

## 6. Threat hunting & DFIR — **P1**

**Why pros want it:** Wazuh lists threat hunting as a use case; [Velociraptor](https://docs.velociraptor.app/) (free/OSS) is the standard for fleet VQL artifact collection and live response ([CISA listing](https://www.cisa.gov/resources-tools/services/velociraptor)).

| Lacking feature | Free OSS | Notes |
|---|---|---|
| Hunt workspace (saved queries, notebooks) | OpenSearch Dashboards, Jupyter, custom UI | Hypothesis → evidence |
| Scheduled hunts | Cron + Sigma/osquery packs | Continuous hunting |
| Live remote collection | Velociraptor, osquery distributed | IR without full disk image |
| Memory / disk triage artifacts | Velociraptor artifacts | On-demand |
| Timeline builder (plaso-style) | [plaso](https://github.com/log2timeline/plaso) offline | Heavy; optional |
| Pivot from IOC → hosts | TI + asset registry + agents | Core hunt loop |

**AutoAnalyzer gap:** Search is thin; OpenSearch not wired; no DFIR agent.

---

## 7. MITRE ATT&CK & detection coverage — **P1**

**Why pros want it:** Coverage heatmaps and technique tagging are table stakes for SOC reporting and gap analysis.

| Lacking feature | Free OSS | Notes |
|---|---|---|
| Technique tags on findings/incidents | [MITRE ATT&CK](https://attack.mitre.org/) STIX data (free) | Map Sigma/Suricata/detectors |
| Coverage heatmap UI | Custom + ATT&CK Navigator export | Layer JSON is free |
| Adversary emulation tests | Atomic Red Team, [Caldera](https://caldera.mitre.org/) | Validate detections |
| CWE ↔ ATT&CK for code | CWE data (in Antares CLI) + ATT&CK | Bridge code modality |

**AutoAnalyzer gap:** No ATT&CK on platform findings (CWE only inside Antares CLI).

---

## 8. Network security monitoring (beyond flow ML) — **P1**

Covered in depth in `networking_upgrades.md`. Pros expect Zeek + Suricata in free NSM stacks (Security Onion, Malcolm).

| Lacking feature | Free OSS |
|---|---|
| Zeek protocol logs | Zeek |
| Suricata IDS/IPS alerts | Suricata + ET Open |
| DNS / DHCP / HTTP metadata | Zeek |
| Selective PCAP / full-packet index | tcpdump, [Arkime](https://arkime.com/) |
| App-layer classification | [nDPI](https://github.com/ntop/nDPI) |

---

## 9. Identity, UEBA-lite, and access telemetry — **P1**

**Why pros want it:** Many incidents are identity-driven (valid accounts, MFA fatigue). Free sources: FreeIPA/Keycloak audit, Windows Security logs, Suricata, osquery `logged_in_users`.

| Lacking feature | Free approach |
|---|---|
| Auth event modality (success/fail/MFA) | Ingest IdP / AD / Keycloak / Windows 4624/4625 |
| Impossible travel / burst fail heuristics | Rules + simple baselines |
| Privileged group change alerts | osquery + AD logs |
| Session / token anomaly | App logs → log-model + rules |

**AutoAnalyzer gap:** No first-class identity pipeline (only generic logs if shipped).

---

## 10. Vulnerability & exposure management — **P1**

| Lacking feature | Free OSS |
|---|---|
| Host/package CVE inventory | Wazuh vuln, Trivy, Grype, OpenVAS/[Greenbone](https://www.greenbone.net/) |
| Container / K8s image scan in CI | Trivy, Grype |
| External attack surface (ports/services) | [Nuclei](https://github.com/projectdiscovery/nuclei) (templates free), nmap |
| KEV prioritization | CISA KEV free feed → boost incident risk |
| Link vuln → asset → incident | Asset registry + CVE IDs on findings |

**AutoAnalyzer gap:** Asset registry exists; no vuln scanner integration or KEV boost.

---

## 11. Search, retention, and evidence — **P1**

| Lacking feature | Free OSS |
|---|---|
| Full-text / field hunt over telemetry | Wire **OpenSearch** (already in Compose) |
| Long retention tiers | OpenSearch ISM + MinIO cold store |
| Immutable evidence export | STIX incident bundle, signed zip |
| Saved searches / dashboards | OpenSearch Dashboards / Grafana |
| Cross-tenant MSSP search | Custom RBAC + federation (later) |

**AutoAnalyzer gap:** OpenSearch present but not the analyst search plane.

---

## 12. Compliance, audit, and reporting — **P2**

Wazuh markets regulatory compliance mapping as a free use case.

| Lacking feature | Free approach |
|---|---|
| Control mappings (PCI, HIPAA, CIS) | Wazuh SCA + custom report templates |
| Audit log of analyst actions | Expand incident audit; export |
| Executive / MTTD-MTTR reports | Grafana + Postgres metrics |
| Retention policy UI | Policy-as-code + cron (partial today) |

---

## 13. Platform observability for the SOC itself — **P1**

Pros distrust a black-box detector. Free LGTM stack: Prometheus, Grafana, Loki, Tempo, Alertmanager (`suggested_assistants_sources.md`).

| Lacking feature | Free OSS |
|---|---|
| Metrics/logs/traces for all services | Prometheus + Loki + Tempo |
| SLO dashboards | Grafana |
| Assistant investigation CLI | Grafana Assistant CLI / grafana-mcp |
| Sensor health (Zeek/Suricata drops) | Exporters + Alertmanager |

---

## 14. Collaboration & knowledge — **P2**

| Lacking feature | Free OSS |
|---|---|
| Shared IR playbooks / wiki | Wiki.js, Outline (OSS), Markdown in-repo |
| ChatOps (enrich from Slack/Mattermost) | Mattermost + Shuffle bots |
| Post-incident review templates | Markdown + incident link |
| Detection engineering notes | Git + PR on Sigma rules |

---

## 15. Deception & purple team (optional) — **P2**

| Lacking feature | Free OSS |
|---|---|
| Honeypots / canary tokens | [OpenCanary](https://github.com/thinkst/opencanary), Thinkst canaries (limited free) |
| Adversary emulation scheduling | Atomic Red Team, Caldera |
| Detection validation dashboard | Custom + ATT&CK Navigator |

---

## 16. Security of the platform — **P1**

| Lacking feature | Free OSS |
|---|---|
| Secrets management | [HashiCorp Vault](https://www.vaultproject.io/) OSS, OpenBAO, SOPS |
| Signed artifacts / SBOMs | cosign, Syft |
| Hardened defaults (OIDC on) | Config/docs — already partially designed |
| Break-glass / audit for service keys | Custom |

---

## Feature gap matrix (compact)

| Domain | Status | Top free fills |
|---|---|---|
| Endpoint agent / FIM / SCA / vulns | Missing | Wazuh, osquery, Trivy |
| Threat intel | Missing | MISP, OpenCTI, CISA KEV |
| Sigma / YARA / Suricata rules | Missing | SigmaHQ, YARA, Suricata |
| Case management | Partial | TheHive, OpenCTI cases |
| SOAR playbooks | Missing | Shuffle, n8n, Tracecat, Cortex |
| Hunting / DFIR | Missing | Velociraptor, OpenSearch hunts |
| ATT&CK coverage | Missing | ATT&CK STIX + Navigator |
| NSM / PCAP | Partial (flows only) | Zeek, Suricata, Arkime |
| Identity telemetry | Missing | Keycloak/AD/Sysmon ingest |
| Vuln / ASM | Missing | Greenbone, Nuclei, KEV |
| Analyst search | Partial | Wire OpenSearch |
| Compliance reporting | Missing | Wazuh SCA + reports |
| Platform LGTM | Missing | Prometheus/Grafana/Loki/Tempo |
| Secrets / signing | Missing | Vault, cosign |

---

## Recommended “free SOC adjacency” architecture

Do **not** rebuild every OSS product inside AutoAnalyzer. Integrate:

```text
[osquery / Wazuh agents]──┐
[Zeek / Suricata]─────────┼──► ingestion-gateway ──► AutoAnalyzer (ML + correlate)
[Sigma/YARA jobs]─────────┤                              │
[Trivy / Grype / Nuclei]──┘                              ▼
                                              incident-api + UI
                                                     │
                    ┌────────────────────────────────┼────────────────────────┐
                    ▼                                ▼                        ▼
              MISP / OpenCTI                   TheHive / Shuffle         Grafana LGTM
                 (TI)                         (cases / SOAR)            (ops / hunt metrics)
                    │                                │
                    └──────── Velociraptor (DFIR on demand) ─────────────┘
```

AutoAnalyzer remains the **anomaly + multi-modal correlation brain**; OSS fills agents, TI, cases, SOAR, hunting, and NSM that pros already know.

---

## Suggested adoption order (free-first)

1. **Wire OpenSearch** for hunt/search + save searches  
2. **osquery/Vector collectors** + host-state findings  
3. **MISP or OpenCTI** + IOC enrich in correlation  
4. **Sigma pipeline** (even a small curated pack) beside ML  
5. **Zeek + Suricata** sensors → network findings  
6. **TheHive or Shuffle** for cases/playbooks (or minimal in-app SOAR-lite)  
7. **Velociraptor** for IR live response  
8. **Prometheus/Grafana/Loki** for platform trust  
9. **Trivy/Grype + CISA KEV** for vuln-aware scoring  
10. **ATT&CK tags + coverage heatmap**

---

## What not to chase (still free but wrong fit)

| Temptation | Why skip / defer |
|---|---|
| Replacing AutoAnalyzer with full Elastic SIEM | Loses specialist ML modality design; integrate instead |
| Building another TheHive from scratch | High cost; API-integrate |
| Continuous full PCAP by default | Cost/privacy; selective only (`networking_upgrades.md`) |
| Paid-only intel as a hard dependency | Keep free feeds first (KEV, MISP communities, OT Open) |

---

## Key references

- Wazuh free platform / use cases (FIM, SCA, vulns, hunting, IR, compliance): [documentation.wazuh.com](https://documentation.wazuh.com/current/getting-started/use-cases/index.html), [wazuh.com](https://wazuh.com/)  
- OSS SOC patterns: Wazuh + TheHive + Cortex + MISP + Shuffle (community labs and guides)  
- Sigma open detection standard: SigmaHQ  
- MISP / OpenCTI TIP comparison and case features  
- Velociraptor DFIR: docs + CISA resources listing  
- Suricata / Zeek / Arkime / nDPI for free NSM  
- Trivy, Grype, Nuclei, Greenbone for free vuln/ASM  
- Prometheus / Grafana / Loki / Tempo for free observability  

---

## Bottom line

Cyber professionals will judge AutoAnalyzer not only on anomaly quality but on whether they can **agent hosts, match IOCs, run Sigma/YARA, hunt in a real search index, open a case, automate enrich/contain, map ATT&CK, and pull DFIR artifacts** — all of which have mature **free OSS** answers. The highest leverage path is **integrate** those tools into the existing ingest → correlate → incident spine rather than reimplementing Wazuh/TheHive/MISP inside this repo.
