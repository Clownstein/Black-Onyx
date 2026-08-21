# Security Profile Implementation — Multi-Select Scan & Test Preconfigurations

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).


**Companion to:** [`security_standards.md`](security_standards.md)  
**Audience:** Platform, frontend, detection engineering  
**Status:** Design history (implemented — see canonical docs)  
**Date:** July 2026

---

## 1. Goal

Let operators (and tenants) **select one or more** security standards and/or industry packs in the AutoAnalyzer UI. The selection becomes a **Security Profile Configuration** that:

1. Enables the right **detectors, scanners, and telemetry expectations**
2. Tags findings/incidents with **framework control IDs**
3. Drives **coverage heatmaps** and gap reports against the selected checklists
4. Remains additive — selecting multiple packs **unions** checks; conflicts resolve by **strictest wins**

This extends existing platform surfaces (logs, network, metrics, code, host-state, firewall, Semgrep, ATT&CK coverage UI) rather than inventing a parallel product.

---

## 2. Current platform hooks (baseline)

| Capability | Today | Profile use |
| --- | --- | --- |
| Log / network / metrics / code anomaly models | Implemented | Weight/threshold packs; feature flags per profile |
| `code-processor` + Semgrep (`scanners/semgrep`) | Implemented | Enable rule packs mapped to OWASP/CIS/PCI app checks |
| Correlation engine + incidents | Implemented | Require multi-modality evidence for high-severity profile rules |
| ATT&CK coverage UI (`AttackCoverage.tsx`) | Partial | Filter/rank techniques by selected MITRE-oriented profiles |
| Host-state / firewall / TI | Roadmap / partial | Unlock host and perimeter checks for CIS, ZT, NERC, CMMC |
| Asset registry | Present | Scope which assets a profile applies to |

Profiles do **not** claim legal compliance certification. They produce **evidence-oriented findings** and **checklist coverage status** (`pass` / `fail` / `unknown` / `not_applicable`).

---

## 3. Concepts

### 3.1 Pack types

| Pack kind | Examples | Purpose |
| --- | --- | --- |
| **Framework pack** | `nist-csf-2`, `iso-27001`, `cis-v8-ig1`, `soc2-security`, `pci-dss-4`, `cobit-gov`, `nist-800-53-mod`, `zero-trust`, `mitre-attack-core`, `csa-ccm` | Map Part 1 of `security_standards.md` |
| **Industry pack** | `hipaa`, `glba-ffiec`, `pci-merchant`, `fedramp-mod`, `cmmc-l2`, `nerc-cip`, `ferpa`, `nydfs-500`, `otar-export`, `saas-trust` | Map Part 2 industry overlays |
| **Surface pack** (internal) | `surface-network`, `surface-host`, `surface-webapp`, `surface-identity`, `surface-cloud` | Reusable check groups referenced by frameworks |

### 3.2 Check

Atomic verifiable item from the standards checklists:

```text
check_id: cis.v8.8.audit-log-centralized
title: Audit logs centralized for servers, IdP, firewalls
surfaces: [network, host, identity, cloud]
automation: auto | manual | hybrid
severity_default: high
mitre_techniques: [T1070, T1562.008]   # optional
evidence_types: [log_presence, detector_hit, scanner_rule, config_assert, attestation]
```

### 3.3 Profile configuration (tenant-scoped)

```text
profile_config_id
tenant_id
name                    # e.g. "Prod SaaS — SOC2 + CIS IG1"
selected_packs: []      # multi-select framework + industry pack IDs
asset_scope: []         # asset_ids, tags, or site_id filters
enabled_surfaces: []    # network | host | webapp | identity | cloud | code
schedule: continuous | daily | weekly | on_demand
strictness: ig1 | ig2 | ig3 | baseline | custom
merge_policy: union_strictest   # only supported policy for v1
```

### 3.4 Multi-select merge rules

When the user selects **multiple** packs:

| Situation | Behavior |
| --- | --- |
| Same check in two packs | Keep one instance; highest severity / strictest threshold wins |
| Overlapping detectors | Enable once; attach **all** framework tags to the finding |
| Conflicting thresholds (e.g., MFA optional vs required) | **Required wins** |
| Manual-only checks | Appear in checklist UI as attestation tasks; do not block automated scan start |
| Industry + framework | Industry checks **add** requirements; never remove framework checks |
| Disabled surface (e.g., no host agents) | Checks for that surface → `unknown` with reason `telemetry_missing` |

Example: selecting `cis-v8-ig1` + `pci-dss-4` + `saas-trust` enables the union of CIS IG1 safeguards, PCI CDE-oriented checks, and SaaS multi-tenant/IDOR-oriented code rules.

---

## 4. Control catalog (data model)

Store versioned YAML/JSON in-repo (authored like Semgrep packs), loadable by a small **profile service** or by `incident-api`.

Suggested layout:

```text
profiles/
  packs/
    frameworks/
      nist_csf_2.yaml
      cis_v8_ig1.yaml
      cis_v8_ig2.yaml
      iso_27001.yaml
      soc2_security.yaml
      pci_dss_4.yaml
      cobit.yaml
      nist_800_53_moderate.yaml
      zero_trust.yaml
      mitre_attack_core.yaml
      csa_ccm.yaml
    industries/
      hipaa.yaml
      glba.yaml
      ...
  surfaces/
    network.yaml
    host.yaml
    webapp.yaml
    identity.yaml
    cloud.yaml
  bindings/
    detector_map.yaml      # check_id → detector_ids / semgrep rules / sigma
    scanner_map.yaml       # check_id → scanners/semgrep/rules/*.yml
```

### 4.1 Pack file sketch

```yaml
pack_id: cis-v8-ig1
kind: framework
version: "8.1"
title: CIS Controls v8.1 Implementation Group 1
extends_surfaces: [network, host, webapp, identity]
checks:
  - check_id: cis.v8.1.asset-inventory
    title: Enterprise assets inventoried
    surfaces: [network, host, cloud]
    automation: hybrid
    bindings:
      detectors: [asset_registry_gap, unauthorized_device]
      evidence: [asset_registry_coverage]
  - check_id: cis.v8.8.audit-log-management
    title: Audit log management
    surfaces: [host, network, identity]
    automation: auto
    bindings:
      detectors: [log_source_silent, auth_burst_unlogged]
      required_log_sources: [idp, firewall, os_auth]
```

### 4.2 Finding enrichment

Every automated hit should carry:

```json
{
  "profile_pack_ids": ["cis-v8-ig1", "pci-dss-4"],
  "check_ids": ["cis.v8.8.audit-log-management", "pci.10.logging"],
  "mitre_techniques": ["T1070"],
  "surfaces": ["host"],
  "automation": "auto"
}
```

Align with existing finding envelope fields; add optional `compliance` object rather than renaming modality payloads. Keep Kafka topic families unchanged (`findings.*`).

---

## 5. How checks map to AutoAnalyzer features

### 5.1 Network surface

| Check themes (from standards) | Platform mechanism |
| --- | --- |
| Segmentation / unexpected east-west | `flow-processor` + `network-model`; firewall processor deny/allow anomalies |
| Port scans / service discovery (T1046) | Existing `port_scan_heuristic`, `failed_connection_burst` |
| Beaconing / C2-like (T1071) | `beaconing_heuristic`, `new_external_peer` |
| Egress to rare destinations / exfil | Network model + TI IOC match (roadmap) |
| Management plane exposure | Config asserts from firewall/asset inventory + flow to `*:22/3389` from internet |
| PCI CDE flatness | Tagged asset zones (`cde` vs `non-cde`) + cross-zone flow findings |

### 5.2 Server / host surface

| Check themes | Platform mechanism |
| --- | --- |
| Unauthorized software / rare binary | `host-state-processor` process events; rare path detectors |
| Persistence (T1053, T1547) | Scheduled task / autorun rules (see ATT&CK catalog) |
| Brute force (T1110) | Sigma-style failed logon burst on auth logs |
| EDR / agent health | Heartbeat gap alerts (telemetry missing → checklist `unknown`) |
| Patch / vuln freshness | Vuln ingest (`vuln_ingest`) correlated to asset criticality |
| CIS secure config drift | Future: osquery/config baseline diffs → findings |

### 5.3 Web app / API / code surface

| Check themes | Platform mechanism |
| --- | --- |
| Injection, secrets, insecure crypto | `code-processor` Semgrep packs under `scanners/semgrep/rules/profiles/` |
| OWASP ASVS authn/z / session | Semgrep + optional DAST job results ingested as `code` or new `appsec` findings |
| Dependency CVEs (SCA) | CI webhook → ingestion-gateway → code features |
| Security headers / TLS | Scheduled external probe worker (new lightweight checker) writing synthetic findings |
| Multi-tenant IDOR (SaaS pack) | Targeted Semgrep + integration test harness results |
| PCI payment page scripts | Special pack: alert on unchecked third-party script changes (needs page inventory feed) |

**Semgrep layout proposal:**

```text
scanners/semgrep/rules/
  profiles/
    owasp-asvs/
    pci-dss/
    cis-appsec/
    hipaa-phi-handling/    # heuristic: PHI log leakage patterns
  common/
```

`SEMGREP_CONFIG` (or a new `SEMGREP_PROFILE_CONFIGS`) resolves to the **union** of rule dirs for selected packs.

### 5.4 Identity surface

| Check themes | Platform mechanism |
| --- | --- |
| MFA gaps | IdP audit log parsing → finding when privileged login without MFA claim |
| Dormant / shared accounts | Host-state + IdP join; policy checks |
| Impossible travel / token anomalies | Log model features + TI |
| Joiner/mover/leaver timeliness | Compare HR/IdP events (connector) vs admin still active |

### 5.5 Detect / respond / governance (manual + hybrid)

| Check themes | Platform mechanism |
| --- | --- |
| IR plan exists | Attestation checklist in UI (store evidence links) |
| Tabletop within 12 months | Attestation with date field |
| Backup restore tested | Attestation + optional metrics on backup job success |
| COBIT KPIs | Dashboard widgets: MTTD, MTTR, patch latency, % checks passing |
| ATT&CK coverage | Extend `AttackCoverage` to filter by profile-enabled techniques |

---

## 6. UI / UX — selecting multiple as a configuration

### 6.1 New console page: **Security Profiles**

Suggested nav entry beside Attack Coverage / Findings.

**Create / Edit Profile**

1. **Name + scope** — tenant, asset tags, environment (`prod` / `lab`)
2. **Framework packs** — multi-select chips (NIST CSF, CIS IG1/IG2, ISO, SOC2, PCI, …)
3. **Industry packs** — multi-select chips (HIPAA, CMMC L2, NERC, …)
4. **Surfaces** — toggles: Network, Host, Web/Code, Identity, Cloud
5. **Strictness** — IG1 / IG2 / IG3 or FedRAMP Low/Mod/High where relevant
6. **Preview** — live count: `N auto checks`, `M manual attestations`, `D detectors enabled`, overlapping packs highlighted
7. **Save** → activates continuous evaluation for scoped assets

**Run now** — on-demand evaluation pass (scanners + config probes + checklist refresh).

### 6.2 Checklist view

For an active profile, show the merged checklist from `security_standards.md` items bound to packs:

| Status | Meaning |
| --- | --- |
| `pass` | Automated evidence OK within SLA |
| `fail` | Open finding linked to `check_id` |
| `unknown` | Missing telemetry / agent / integration |
| `not_applicable` | Out of scope (e.g., no CDE for PCI) |
| `attested` | Manual evidence uploaded / signed off |

Clicking a fail opens linked findings/incidents (reuse EvidenceTabs).

### 6.3 Multi-select UX rules

- Show **compatibility hints** (e.g., “PCI implies network segmentation checks”)
- Warn when industry pack selected without recommended framework backbone
- Cap preview: do not overwhelm — group by surface, collapse passed IG1 noise if IG2 selected
- Export: CSV/JSON checklist + Navigator layer for MITRE pack

---

## 7. Runtime architecture

```text
                    ┌─────────────────────────────┐
                    │  Frontend Security Profiles │
                    │  (multi-select packs)       │
                    └─────────────┬───────────────┘
                                  │ REST
                    ┌─────────────▼───────────────┐
                    │ incident-api / profile-api   │
                    │  CRUD configs, merge packs  │
                    │  coverage summary           │
                    └─────────────┬───────────────┘
                                  │
           ┌──────────────────────┼──────────────────────┐
           ▼                      ▼                      ▼
   ┌───────────────┐    ┌─────────────────┐    ┌─────────────────┐
   │ Detector gate │    │ Scanner config  │    │ Checklist eval  │
   │ (enable rules │    │ (Semgrep union  │    │ (pass/fail/     │
   │  by pack)     │    │  rule dirs)     │    │  unknown)       │
   └───────┬───────┘    └────────┬────────┘    └────────┬────────┘
           │                     │                      │
           ▼                     ▼                      ▼
   processors/models      code-processor          Postgres
   findings.*             scanner_findings        profile_check_state
           │                     │                      │
           └──────────► correlation-engine ◄────────────┘
                                  │
                                  ▼
                           incidents + UI
```

### 7.1 Detector gating

Today detectors are always-on. Profiles add a **gate**:

- Global / tenant default profile can keep current behavior
- Optional mode: `profile_enforced=true` → only pack-bound detectors raise tenant-visible findings (platform health detectors excluded)

V1 recommendation: **do not disable** core anomaly models; **add** pack-specific rules and tags. Use profiles primarily for checklist scoring + extra scanners.

### 7.2 Evaluation loop

1. Load active `profile_config` for tenant  
2. Merge packs → `ResolvedProfile` (checks + bindings)  
3. For each `auto` check: query recent findings / telemetry presence / probe results  
4. Write `profile_check_state` rows  
5. Emit synthetic finding if state transitions `pass → fail`  
6. Update coverage API used by Security Profiles + Attack Coverage pages  

Schedule via existing worker patterns (training-orchestrator style cron, or a small `profile-evaluator` service). Prefer **one new evaluator** over scattering schedule logic.

---

## 8. API sketch (incident-api extension)

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/security-packs` | List available framework/industry packs + metadata |
| `GET` | `/v1/security-packs/{id}` | Pack detail + check list |
| `GET` | `/v1/security-profiles` | List tenant profiles |
| `POST` | `/v1/security-profiles` | Create (`selected_packs[]`, scope, surfaces) |
| `PATCH` | `/v1/security-profiles/{id}` | Update multi-select / scope |
| `POST` | `/v1/security-profiles/{id}/evaluate` | On-demand run |
| `GET` | `/v1/security-profiles/{id}/coverage` | Checklist status summary |
| `GET` | `/v1/security-profiles/{id}/export` | JSON/CSV / ATT&CK Navigator layer |

Auth: existing OIDC + RBAC (`viewer` read, `analyst` evaluate, `admin` mutate). Tenant header `X-Tenant-Id` required.

---

## 9. Preconfiguration presets (ship defaults)

Offer one-click templates that pre-select packs (still editable multi-select):

| Preset | Selected packs | Surfaces |
| --- | --- | --- |
| **Baseline SMB** | `nist-csf-2`, `cis-v8-ig1` | network, host, identity |
| **SaaS product** | `soc2-security`, `iso-27001`, `cis-v8-ig1`, `saas-trust`, `mitre-attack-core` | webapp, cloud, identity, network |
| **Payment merchant** | `pci-dss-4`, `cis-v8-ig2`, `owasp-web` (surface) | network, webapp, host |
| **Healthcare** | `hipaa`, `nist-csf-2`, `cis-v8-ig1` | host, identity, network, webapp |
| **DoD contractor L2** | `cmmc-l2`, `nist-800-53-mod`, `zero-trust` | host, identity, network, cloud |
| **Electric utility** | `nerc-cip`, `zero-trust`, `cis-v8-ig2` | network, host (OT tags) |
| **Threat-informed SOC** | `mitre-attack-core`, `nist-csf-2`, `cis-v8-ig2` | all |

Presets are only JSON defaults pointing at packs — no duplicate check logic.

---

## 10. Phased delivery

### Phase A — Catalog + UI multi-select (no gating)

- Author pack YAML for all 10 frameworks + 10 industries (checks from `security_standards.md`)
- CRUD profiles in API + Security Profiles page
- Coverage board: manual attestation + map existing detectors where bindings exist
- Export checklist

### Phase B — Scanner & detector bindings

- Semgrep profile rule dirs; wire `code-processor` to union configs from active profile
- Tag findings with `check_ids` / `pack_ids`
- Expand ATT&CK page filter by profile
- External TLS/header probe worker for web surface auto checks

### Phase C — Continuous evaluation + strict mode

- `profile-evaluator` service on schedule
- Telemetry-gap `unknown` reasons
- Optional `profile_enforced` detector gating
- Industry-specific zone tags (CDE, CUI, ePHI, BES)

### Phase D — Assessor workflow

- Evidence locker links per check
- POA&M-style exception register
- Auditor read-only role + signed PDF export

---

## 11. Explicit non-goals (v1)

- Guaranteeing legal certification (SOC 2 report, PCI ROC, CMMC cert)
- Replacing GRC tools for policy document management
- Destructive remediation / auto-blocking (remains human-gated per platform principles)
- Collecting multi-service pytest in one process when adding profile unit tests — keep pack tests under one service package

---

## 12. Testing strategy

| Layer | What |
| --- | --- |
| Pack schema | Contract tests: every pack validates against JSON Schema; every `check_id` unique |
| Merge logic | Unit tests: union, strictest-wins, industry additive |
| Bindings | Every detector ID in `detector_map.yaml` exists in catalog / code |
| API | Tenant isolation tests with `PYTHONPATH=services/incident-api` |
| Frontend | Playwright: multi-select packs → preview counts → save → coverage renders |
| Semgrep | Profile rule packs produce stable `scanner_findings` shape |

---

## 13. Configuration example (operator-facing)

**UI selection:** `CIS IG1` + `SOC 2 Security` + `SaaS Trust` + surfaces Network/Web/Identity  

**Resolved effect:**

1. Enable CIS asset/log/vuln detectors + SOC2 access/change monitoring tags  
2. Enable Semgrep `profiles/cis-appsec` ∪ `profiles/owasp-asvs` ∪ `profiles/saas-tenant`  
3. Checklist shows ~120 merged checks (illustrative), ~70 auto, ~50 manual  
4. Findings for open redirects / missing MFA claims carry `check_ids` for both CIS and SOC2  
5. Coverage widget: 62% pass, 11% fail, 18% unknown (no host agent), 9% attested  

---

## 14. Relationship to other roadmap docs

| Doc | Relationship |
| --- | --- |
| [`security_standards.md`](security_standards.md) | Source of checklist text and pack content |
| [`planned_upgrades.md`](planned_upgrades.md) | Host agents, TI, ATT&CK, SOAR — unlock more `auto` checks |
| [`docs/defender/mitre-coverage.md`](docs/defender/mitre-coverage.md) | Technique tagging conventions for MITRE pack |
| [`scanners/AGENTS.md`](scanners/AGENTS.md) | Semgrep pack wiring rules — profile rules must keep finding shape |

---

## 15. Success criteria

1. Operator can **multi-select** ≥2 packs and save a named profile in one flow  
2. Merged checklist reflects **union + strictest** semantics with no duplicate rows  
3. At least one **auto** check per surface (network, host, web, identity) produces tagged findings in a lab tenant  
4. Missing telemetry yields **`unknown`**, not silent **`pass`**  
5. Export matches selected packs for offline assessor review  

---

*Design only. Implementation should follow existing AutoAnalyzer patterns (uv workspace, per-service pytest, envelope fields, tenant headers) and should not invent new top-level `app` packages or broker addresses.*
