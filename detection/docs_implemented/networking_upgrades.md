# Networking Upgrades: Deeper Analysis Toward Packet Visibility

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).


**Document version:** 1.0  
**Date:** July 27, 2026  
**Audience:** Platform, security engineering, SOC / network defenders  
**Purpose:** Research-backed options to deepen AutoAnalyzer’s network stack from flow metadata toward packet-aware analysis — including OS-specific capture, models, graphs, monitoring, linking, alerting, containment, and verification — without abandoning privacy and MVP non-goals.

**Related:** `planned_upgrades.md` §3, `suggested_models.md` (FlowTransformer / UniNet), `suggested_assistants_sources.md` (Grafana linking), `ANOMALY_DETECTION_PLATFORM.md` §2.2 / §8.

---

## Executive summary

Today AutoAnalyzer does **flow-window anomaly detection** (NetFlow/Zeek-like metadata → `flow-processor` → `FlowTransformer` ONNX). It does **not** ingest PCAPs, run DPI, or train neural models on payloads. Spec §2.2 explicitly excludes *“full packet-payload inspection by a neural model”* and defaults packet payload collection out of scope.

Industry practice for professional NSM (network security monitoring) is a **layered funnel**, not “Wireshark everything forever”:

```text
Wire / host traffic
    ↓
Sensors (Zeek + Suricata + optional nDPI / eBPF)
    ↓
Rich metadata + IDS alerts (+ selective PCAP excerpts)
    ↓
AutoAnalyzer ingest → features → models / rules → correlation
    ↓
Graphs, Grafana, alerts, gated containment, forensic verify
```

**Recommendation:** Extend to **packet-derived intelligence** (protocol logs, TLS fingerprints, Suricata EVE, selective PCAP-on-alert) while keeping the hot-path ML on **structured sequences**, not raw bytes. Full-payload neural DPI remains a deliberate non-goal; use Suricata/nDPI for L7 classification and signature/anomaly alerts instead.

---

## 1. Current baseline vs target depth

| Layer | Today | Target (phased) |
|---|---|---|
| Ingest | `POST /api/v1/ingest/network-flows` → `network.raw` | + Zeek logs, Suricata EVE, DNS, firewall syslog, VPC flows; optional PCAP excerpt API |
| Features | 300s windows, counters, peer hashes | + JA3/JA4, SNI, DNS qname patterns, app-id (nDPI), HTTP/SSH metadata from Zeek |
| Detectors | Port scan, failed burst, new external peer | + Beaconing, rare JA3/SNI, DNS tunneling heuristics, Suricata SID mapping |
| Model | Compact `FlowTransformer` ONNX | Same family + optional UniNet-style multi-granularity; **not** payload LLM |
| Evidence UI | Network evidence page | Session graphs, timeline, PCAP snippet download when retained |
| Contain | Out of MVP | Gated SOAR: block IP, isolate host (see `planned_upgrades.md` §6) |

**Key paths today:**

- `services/flow-processor/` — normalize, windows, detectors  
- `models/network-model/` — FlowTransformer  
- `contracts/network/network_flow.schema.json` — flow metadata (optional `tls`/`dns` objects exist but are under-wired)

---

## 2. Depth spectrum (how “packet analysis” should work)

Avoid a binary “flows vs PCAPs.” Use escalating fidelity:

| Tier | What is analyzed | Storage cost | Model fit | Privacy |
|---|---|---|---|---|
| **T0 Flow only** (current) | 5-tuples, bytes, packets, state | Low | FlowTransformer | High (hash IPs) |
| **T1 Protocol metadata** | Zeek `conn`/`dns`/`http`/`ssl`/`ssh` fields | Medium | Sequence + heuristics | High if payloads stripped |
| **T2 IDS / DPI labels** | Suricata EVE alerts; nDPI app-id / risk flags | Medium | Finding ingest + correlation boost | Medium (alerts may include URIs) |
| **T3 Selective PCAP** | N packets / N seconds around an alert | High, short TTL | Forensics / human / replay to Zeek | Controlled retention |
| **T4 Full continuous PCAP** | Ring buffer or full capture | Very high | Rarely justified | Highest risk |

**Research pattern:** Mature SOCs run **Zeek + Suricata together** on a SPAN/TAP (or host interface): Suricata for signatures/IPS-style alerts, Zeek for rich protocol logs and scripted detection. They are complementary, not alternatives. DPI libraries such as [nDPI](https://www.ntop.org/products/deep-packet-inspection/ndpi/) classify application protocols from headers/payloads without requiring you to train a neural payload model.

**AutoAnalyzer ML stance:** Keep learning on **sequences of structured events** (flows, Zeek rows, alert bursts). Use packet engines as **feature factories** and **alert sources**. That respects the platform non-goal while still going “down to packets” at the sensor edge.

---

## 3. Operating system deployment models

### 3.1 Enterprise segment (preferred for east-west / north-south)

| Element | Approach |
|---|---|
| Placement | Network TAP or switch SPAN/mirror to a dedicated Linux sensor appliance |
| Engines | Zeek + Suricata (`af-packet` / `PF_RING` / DPDK as needed) |
| Optional | nDPI / ntopng for app-id; Arkime/Moloch for PCAP index |
| Ship to platform | Vector/Fluent Bit → `ingestion-gateway` (JSON) or Kafka mirror |
| OS of sensor | **Linux** (Ubuntu/RHEL) — primary supported sensor OS |

Cloud VPS note: without SPAN, sensors typically see **host traffic only** (useful for exposed services, less for full campus visibility).

### 3.2 Linux hosts (servers / sensors)

| Mechanism | Role |
|---|---|
| **AF_PACKET / TPACKET v3** | Suricata high-speed capture |
| **libpcap / tcpdump** | Ad-hoc / replay; Zeek can use pcap |
| **eBPF** (Cilium Tetragon, Pixie, custom) | Process↔socket correlation, metadata without full payload retention |
| **Zeek / Suricata packages** | Production NSM stack |
| Capabilities | Needs `CAP_NET_RAW` / `CAP_NET_ADMIN` or root; careful drop rights after bind |

**eBPF angle:** Good for “who opened this connection” linking to `host-state` / osquery without storing payloads — aligns with privacy goals.

### 3.3 Windows hosts / servers

| Mechanism | Role |
|---|---|
| **Npcap** | libpcap-compatible capture (Wireshark, Zeek-on-Windows experiments, custom agents); Admin/UAC often required; OEM license for redistribution |
| **Windows Filtering Platform (WFP)** | Loopback + filtering; used by Npcap for loopback |
| **ETW / Sysmon network events** | Connection create metadata without full PCAP (EID 3) — excellent **host-state** complement |
| **WinDivert** | User-mode divert/capture (specialized; careful with containment) |
| Reality check | Full Zeek+Suricata NSM is still **Linux-sensor-centric**; on Windows prefer **Sysmon + Npcap only when forensic PCAP needed**, or ship flows from Windows agents as metadata |

Npcap commercial redistribution requires OEM licensing for productized agents ([npcap.com](https://npcap.com/)).

### 3.4 macOS endpoints

| Mechanism | Role |
|---|---|
| **libpcap / tcpdump** (with privileges) | Ad-hoc capture |
| **Network Extension / content filter** | Managed MDM deployments; complex entitlement story |
| **EndpointSecurity + network events** | Process-centric (via osquery packs) more than full NSM |
| Reality check | Treat macOS as **endpoint visibility** (osquery sockets/process), not campus TAP replacement |

### 3.5 Recommended deployment matrix

| Environment | Capture strategy | What AutoAnalyzer receives |
|---|---|---|
| Datacenter VLAN | Linux Zeek+Suricata on SPAN | `network.flow` + `zeek.*` + `suricata.alert` |
| Cloud VPC | VPC Flow Logs + optional host Suricata | Flow records + host alerts |
| Windows estate | Sysmon network + optional Npcap on IR jump hosts | Host-state sockets + rare PCAP excerpts |
| macOS estate | osquery `process_open_sockets` + DNS logs | Host-state + DNS features |
| Analyst laptop | Wireshark / Arkime against retained excerpts | Manual verify, not continuous ML |

---

## 4. What to implement in AutoAnalyzer

### 4.1 New ingest contracts & topics

| Topic / event | Source | Purpose |
|---|---|---|
| `network.raw` (extend) | Existing flows | Keep |
| `zeek.conn` / `zeek.dns` / `zeek.ssl` / `zeek.http` | Zeek JSON/TSV→JSON | Protocol features |
| `suricata.alert` / `suricata.flow` | EVE JSON | Signature findings + evidence |
| `dns.raw` | DNS server / Zeek dns | Tunneling / DGA features |
| `firewall.raw` | Syslog CEF | Allow/deny correlation |
| `pcap.excerpt` (optional) | Sensor on alert | Short blob or object-store pointer (MinIO) |

Extend `contracts/network/` with schemas for Zeek/Suricata events; keep IP hashing policy (`store_raw_ip: false`) unless a tenant opts into forensic mode.

### 4.2 Processors & detectors

| Component | Work |
|---|---|
| `flow-processor` | Wire optional `tls`/`dns` schema fields; beaconing, rare JA3/JA4/SNI, cross-host fan-out |
| New `zeek-processor` or adapters | Normalize Zeek logs → feature windows |
| New `ids-processor` | Suricata EVE → `Finding` with SID, severity, MITRE tags |
| nDPI sidecar (optional) | App-id / risk flags attached to flows before Kafka |

### 4.3 Models (compatible with current design)

| Approach | Role |
|---|---|
| **Keep / upgrade FlowTransformer** | Core streaming scorer on enriched flow tensors (add JA3 hash buckets, DNS entropy, app-id one-hots) |
| **UniNet-style hierarchical encoder** | Session + flow + packet-stats (counts/sizes/IAT) — still not raw payload |
| **Isolation / classical on DNS features** | Cheap tunneling/DGA detectors |
| **Do not** | Train BERT/LLM on payload bytes for hot path; do not require continuous PCAP for scoring |

Training data: public Zeek/Suricata datasets + synthetic scan/beacon scenarios (`tests/synthetic-anomalies/network/`); optional replay of PCAPs **through Zeek/Suricata offline** to generate labeled metadata (sensors produce features; models never see raw PCAP at serve time).

### 4.4 Selective PCAP pipeline (packet analysis without drowning)

```text
Suricata/Zeek alert (high severity)
    → sensor captures ±N seconds or M packets (tcpdump/dumpcap ring)
    → upload to MinIO (encrypted, TTL 7–30 days)
    → incident evidence_refs: { type: "pcap", uri, sha256, filter }
    → analyst opens in Wireshark / Arkime OR offline Zeek re-parse
```

API sketch: `POST /api/v1/ingest/pcap-excerpt` (service-keyed) with metadata only in Kafka; bytes in object store.

---

## 5. Graphs & visualization

| View | Data | Implementation ideas |
|---|---|---|
| **Peer graph** | Asset ↔ external IP / domain | Frontend Network page: force-directed graph from window aggregates |
| **Session timeline** | Flows + alerts + DNS | Unified incident timeline (already planned) |
| **Protocol treemap** | nDPI / Zeek service | Grafana or frontend breakdown |
| **Beacon scatter** | Interval regularity vs rare peers | Detector output panels |
| **PCAP session list** | Arkime / Wireshark | Link out; don’t rebuild Wireshark |
| **Grafana Explore** | Prom metrics from sensors (drops, EPS) | Per `suggested_assistants_sources.md` |

**External tools to link, not rebuild:** [Arkime](https://arkime.com/) (PCAP index/search), Wireshark, Grafana dashboards for sensor health.

---

## 6. Monitoring (sensors + platform)

### Sensor health (must alert)

- Suricata/Zeek process up
- Kernel capture drops (`af-packet` drops, Zeek lag)
- EPS / log ship lag to gateway
- Disk for PCAP ring / Zeek spool
- Clock sync (NTP) — wrong time breaks correlation

### Platform metrics

- `network.raw` / `network.features` consumer lag
- Detector fire rates; model score distributions
- PCAP excerpt upload failures; MinIO TTL purge success

Expose to Prometheus/Grafana so Grafana Assistant can investigate “why did network findings stop?”

---

## 7. Linking (cross-modality & identity)

| Link | How |
|---|---|
| Network ↔ host process | eBPF/Sysmon/osquery: PID ↔ 5-tuple; join on `asset_id` + time |
| Network ↔ logs | Shared `trace_id` / connection UID (Zeek `uid`) in log lines where apps support it |
| Network ↔ code/deploy | New outbound peers within N minutes of `deployment_id` |
| Network ↔ TI | Match dst IP/domain/JA3 against `threat-intel-service` |
| Network ↔ incident | Suricata SID + FlowTransformer score → correlation bucket |
| Network ↔ Grafana | Deeplink Explore for sensor metrics + OpenSearch evidence |

Canonical join keys: `tenant_id`, `asset_id`, `service_id`, `community_id` / Zeek `uid`, `flow_id`, `trace_id`.

---

## 8. Alerting

| Class | Source | Action |
|---|---|---|
| Signature | Suricata SID (ET Open / custom) | Finding → correlation; MITRE map |
| Behavioral | FlowTransformer + beacon/scan detectors | Finding with contributors |
| DNS / TLS rare | Heuristics + TI | Boost risk_score |
| Sensor down / drop spike | Prometheus rules | Platform Alertmanager (ops), not SOC flood |
| High-severity correlated | Correlation engine | Notification-service / OnCall |

Keep **sensor ops alerts** separate from **security findings** to avoid alert fatigue.

---

## 9. Containing (response)

Align with gated SOAR (`planned_upgrades.md` §6); network-specific actions:

| Action | Mechanism | Gate |
|---|---|---|
| `block_ip` / `block_domain` | Firewall / DNS RPZ / cloud SG | Approval + TI confidence / multi-model |
| `rate_limit_peer` | Temporary shaper / WAF | Lower risk auto-suggest |
| `isolate_host` | EDR / switch port / cloud quarantine | High severity + approval |
| `capture_now` | Trigger selective PCAP on sensor | Analyst or playbook |
| `sinkhole_dns` | Internal DNS | Careful blast radius |

Never auto-block solely on FlowTransformer score. Prefer Suricata critical SID **or** multi-modality correlation **plus** human approval in production.

---

## 10. Verifying (detection quality & forensics)

| Activity | Method |
|---|---|
| Unit / synthetic | Existing `tests/synthetic-anomalies/network/` (scan/beacon) |
| PCAP replay | Replay public PCAPs through Zeek/Suricata → expect findings |
| Purple team | Controlled scans/beacons on lab SPAN; measure recall |
| ATT&CK | Map detectors to T1046, T1071, T1048, T1571, etc. |
| Forensic verify | Analyst opens PCAP excerpt; confirms or marks FP → calibration feedback |
| Drift | Monitor JA3/SNI catalog growth; retrain flow model on new baselines |

Offline pipeline: `pcap → zeek/suricata → JSON → flow-processor/ids-processor → score` validates end-to-end without putting PCAP in the online model path.

---

## 11. Privacy, legal, and policy

| Rule | Rationale |
|---|---|
| Default: no continuous full-payload storage | Spec non-goal; GDPR/wiretap risk |
| Hash or tokenize IPs in features (current policy) | Retention minimization |
| Selective PCAP: purpose limitation + TTL + access audit | Need-to-know forensics |
| TLS decryption | Out of scope unless enterprise SSL inspection already exists — do not build a MITM in AutoAnalyzer |
| Tenant forensic mode flag | Opt-in plaintext IP / longer PCAP TTL |

---

## 12. Resource sketch (sensors)

| Deployment | Rough sizing (research / field practice) |
|---|---|
| Host Suricata+Zeek (self traffic) | ~4 vCPU, 4–8 GB RAM, 80+ GB disk if local logs |
| Segment SPAN sensor (1–10 Gbps) | Scales with traffic; often dedicated NICs, 16+ cores, careful drop monitoring |
| Continuous full PCAP at line rate | Dominates disk/IO — avoid unless regulated capture mandate |
| Selective excerpt only | Modest MinIO growth |

Platform app tier network path stays CPU ONNX; cost spike is **sensors + log volume**, not the FlowTransformer.

---

## 13. Phased roadmap

### Phase N1 — Enrich flows (no PCAP) — 4–6 weeks

1. Ingest Zeek `conn`/`dns`/`ssl` and Suricata EVE into gateway.  
2. Wire `tls`/`dns` fields through `flow-processor`; add beacon + rare JA3/SNI detectors.  
3. Map Suricata alerts to findings with MITRE IDs.  
4. Document `docs/deployment/network-sensors.md` (Linux SPAN + host mode).

### Phase N2 — Graphs & monitoring — 3–4 weeks

1. Peer/session graph in Network UI.  
2. Sensor health metrics → Prometheus/Grafana.  
3. Incident deeplinks to evidence + Grafana.

### Phase N3 — Selective packet forensics — 4–6 weeks

1. Alert-triggered PCAP excerpt → MinIO + `evidence_refs`.  
2. Analyst download / Arkime link.  
3. Offline PCAP→Zeek replay job for verification.

### Phase N4 — Containment & OS agents — 6–8 weeks

1. SOAR actions: block_ip, capture_now (approval-gated).  
2. Windows: Sysmon network → host-state join; Npcap only on IR workstations/sensors.  
3. macOS/Linux: osquery socket packs linked to flows.  
4. Optional nDPI app-id enrichment.

### Phase N5 — Model upgrades (ongoing)

1. Retrain FlowTransformer on enriched tensors.  
2. Evaluate UniNet-style packet-stat hierarchy.  
3. Keep payload neural nets out of hot path.

---

## 14. Decision matrix

| Need | Prefer | Avoid |
|---|---|---|
| Deeper analysis | Zeek metadata + Suricata + enriched FlowTransformer | Raw-payload BERT on every packet |
| Packet visibility | Selective PCAP-on-alert + Arkime/Wireshark | Continuous full PCAP by default |
| Linux | Zeek+Suricata on SPAN/host `af-packet` | Ad-hoc tcpdump as production sensor |
| Windows | Sysmon/ETW metadata; Npcap for IR | Requiring Zeek on every endpoint |
| macOS | osquery sockets + DNS | Full NSM agent expectation |
| Graphs | Peer/session UI + Grafana | Rebuilding Wireshark |
| Alerting | Suricata + behavioral findings + sensor SLO alerts | One undifferentiated firehose |
| Contain | Gated firewall/EDR playbooks | Auto-block on ML score alone |
| Verify | PCAP replay through Zeek + analyst confirm | Trusting File/Flow F1 without purple tests |

---

## 15. Key references

- Zeek: network analysis framework / protocol logs — [docs.zeek.org](https://docs.zeek.org/)  
- Suricata + Zeek co-deployment (SPAN vs host) — field guides e.g. Suricata `af-packet` + Zeek side-by-side patterns  
- nDPI: open DPI / app protocol classification — [ntop.org/nDPI](https://www.ntop.org/products/deep-packet-inspection/ndpi/)  
- Npcap (Windows capture) — [npcap.com](https://npcap.com/)  
- Traffic analysis toolchains (tcpdump / Suricata / nDPI) — open-source DPI writeups  
- AutoAnalyzer constraints — `ANOMALY_DETECTION_PLATFORM.md` §2.2, §8; `planned_upgrades.md` §3  
- Model direction — `suggested_models.md` (FlowTransformer / UniNet)

---

## Bottom line

Go deeper on networking by treating **packets as a sensor concern** and **structured metadata + alerts as the platform concern**. Deploy **Zeek + Suricata** on Linux SPAN/host sensors, enrich the existing FlowTransformer path, add **graphs / Grafana / selective PCAP**, and only then wire **gated containment** and **OS-specific host join** (Sysmon/osquery/eBPF). That delivers packet-informed analysis and forensics without violating the “no neural full-payload inspection” non-goal or exploding storage and privacy risk.
