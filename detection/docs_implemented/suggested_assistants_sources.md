# Suggested Assistants & Data Sources

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).


**Document version:** 1.0  
**Date:** July 27, 2026  
**Purpose:** Ideas for AI assistants, MCP/CLI tooling, and observability data sources AutoAnalyzer still lacks for proper analysis, monitoring, linking, and alerting — with emphasis on [Grafana Assistant](https://github.com/grafana/ai-marketplace/tree/0d0526a92f5e5546bdd9e84390100766cc61298f/plugins/grafana-assistant) and the broader Grafana/LGTM ecosystem.

**Related docs:** `planned_upgrades.md` §8 (platform observability), `cli_tools_info.md` (Antares CLI), `suggested_models.md` (detection models).

---

## Executive summary

AutoAnalyzer today is strong at **anomaly detection → correlation → incidents**, but weak at **operational observability of itself and of the monitored estate** in a form AI assistants can query. Grafana’s assistant stack assumes a live Grafana instance backed by metrics, logs, traces, alerts, and (optionally) IRM/OnCall. We largely lack those backends and the assistant/MCP layer in front of them.

**Recommended direction:**

1. Stand up an **LGTM-style observability plane** (Loki, Grafana, Tempo/Mimir or Prometheus, Alertmanager).
2. Wire AutoAnalyzer services + Kafka/Postgres/OpenSearch exporters into it.
3. Add **Grafana Assistant CLI** and/or **grafana-mcp** so humans and coding agents can investigate with PromQL/LogQL/TraceQL and deeplinks.
4. Link AutoAnalyzer **incidents** to Grafana Explore / Alertmanager / OnCall so analysis and alerting share one investigation path.

Without (1), assistants have little to query. Without (3–4), dashboards stay siloed from defender workflows.

---

## 1. Grafana Assistant CLI (primary research target)

### What it is

Cursor/Claude plugin material in [grafana/ai-marketplace …/plugins/grafana-assistant](https://github.com/grafana/ai-marketplace/tree/0d0526a92f5e5546bdd9e84390100766cc61298f/plugins/grafana-assistant) documents skills and rules for the **`grafana-assistant` CLI**, which talks to **Grafana Assistant via the A2A API**.

| Piece | Role |
|---|---|
| `skills/grafana-assistant-cli/SKILL.md` | How agents should call the CLI (`prompt`, `chat`, tunnel, context) |
| `rules/grafana-assistant.mdc` | Best practices for Grafana MCP tools (summaries, JSONPath, deeplinks) |
| Binary | [grafana/assistant-cli](https://github.com/grafana/assistant-cli) (+ Docker image) |

### Capabilities useful for AutoAnalyzer

From the skill docs, the CLI agent is **read-only** against Grafana and can:

- Query **metrics** (PromQL), **logs** (LogQL), **traces** (TraceQL), profiles, SQL datasources
- Discover datasources, metric names, labels, log streams
- Search dashboards / panel definitions
- Query **alert history**, **on-call schedules**, **incidents**
- Query **Asserts** entity health / RCA patterns (where licensed)
- Search Grafana docs
- Follow investigation workflows: metrics → logs → traces for probable cause

**Not in CLI** (web/Slack only): dashboard create/update, alert rule/silence management.

### Agent-facing usage patterns

```bash
# Non-interactive (primary for Cursor/agents)
grafana-assistant prompt "Kafka consumer lag for inference-worker last 1h" --json
grafana-assistant prompt "Break that down by topic" -c <contextId> --json

# Interactive
grafana-assistant chat

# Local tool tunnel (filesystem/terminal with allowlists)
grafana-assistant tunnel connect --terminal
```

Config supports multiple Grafana instances, service-account tokens, project paths for tunnel, and filesystem/terminal allow/deny lists. Auth: PKCE browser flow or `GRAFANA_URL` + `GRAFANA_SA_TOKEN`.

**Implication for us:** Install the CLI in engineering/SOC workstations *after* Grafana has real datasources. Until then, prompts will fail or return empty.

### Assistant tunnel (local linking)

Tunnel lets Grafana Assistant read local project files / run allowlisted commands during an investigation (e.g. open a Compose log, `kubectl` describe). Default security: read-only FS, blocks secrets (`*.key`, `.env`, `~/.ssh`, …), 1MB file limit, dangerous shell blocked.

**Idea:** Register AutoAnalyzer repo + `infrastructure/docker-compose` as a tunnel **project** so assistant investigations can correlate platform metrics with local config/runbooks.

---

## 2. Grafana MCP (complementary to Assistant CLI)

The marketplace README points to a separate **grafana-mcp** plugin wrapping the official [Grafana MCP server](https://github.com/grafana/mcp-grafana) ([docs](https://grafana.com/docs/grafana/latest/developer-resources/mcp/)).

| Category | Example tools (40+) | AutoAnalyzer use |
|---|---|---|
| Dashboards | search, summary, property, patch | Build/maintain platform + SOC dashboards from agents |
| Datasources | list, get | Discover Prom/Loki/Tempo UIDs |
| Prometheus | query, metadata, labels | Consumer lag, inference latency, DLQ rate |
| Loki | LogQL, labels, patterns | Service error spikes, ingest failures |
| Alerting | rules, contact points | Platform SLO alerts (write only when asked) |
| Incidents | search, create, activity | Bridge Grafana Incident ↔ AutoAnalyzer incidents |
| OnCall | schedules, shifts, alert groups | Page the right person from correlated high-severity |
| Navigation | **generate_deeplink** | One-click Explore from incident UI |
| Annotations | create/list | Mark deploy / model canary on graphs |

**Rules of thumb** (from grafana-assistant rules): prefer `get_dashboard_summary` / JSONPath / `patch_dashboard`; always bound Prom/Loki time ranges; avoid writes unless the user asks; always return **deeplinks**.

**CLI vs MCP:**

| | Grafana Assistant CLI | grafana-mcp |
|---|---|---|
| Interface | A2A chat/`prompt` | Direct MCP tools in Cursor |
| Writes | Read-only | Can write (Editor token) |
| Best for | Multi-step investigations in natural language | Precise tool calls (query Prom, patch panel) |
| Context cost | Conversation | 40+ tools in context — enable when needed |

**Suggestion:** Use **both** — MCP for dashboard/alert engineering; Assistant CLI for “why is this incident firing?” investigations.

---

## 3. Data sources we are lacking (foundation)

Assistants are useless without backends. Current AutoAnalyzer stack (Compose) has Postgres, Redpanda, OpenSearch, Redis, MinIO, partial OTEL → `debug`. It does **not** ship the queryable LGTM plane Grafana Assistant expects.

### 3.1 Must-have for assistant-driven analysis

| Data source | Role | Gap today | Suggested action |
|---|---|---|---|
| **Prometheus** (or Grafana Mimir) | Metrics, PromQL, alert rules | No scrape of service `/metrics`; gateway has some Prometheus metrics only | Add `docker-compose.observability.yml`; scrape all services + Kafka lag exporters |
| **Grafana** | UI + Assistant/MCP host | Not in Compose | Bundle OSS Grafana; provision datasources + starter dashboards |
| **Loki** (+ Promtail/Alloy) | LogQL over platform & app logs | No central log store for assistants | Ship container logs to Loki; label by `service`, `tenant_id` where safe |
| **Tempo** (or Jaeger) | TraceQL / distributed traces | OTEL collector exports to `debug` only | Point OTLP → Tempo; propagate trace IDs over Kafka headers |
| **Alertmanager** | Route/silence/group alerts | Notifications are webhook/email only | Alertmanager → notification-service / Slack / PagerDuty |

This matches the industry “PLG / LGTM” pattern (Prometheus/Loki/Tempo + Grafana) described in 2026 observability roundups and Grafana’s own stack.

### 3.2 Strongly recommended for linking & alerting

| Source / product | Why it matters for defenders |
|---|---|
| **Grafana Alloy / OTEL Collector** | Single agent path for metrics+logs+traces into LGTM (extend existing `docker-compose.otel.yml`) |
| **Kafka / Redpanda exporters** | Consumer lag, under-replicated partitions → SLO alerts assistants can query |
| **Postgres exporter** | Incident-api / asset-registry DB health |
| **Redis exporter** | Correlation bucket store health |
| **OpenSearch datasource** | Evidence/search already in OpenSearch — expose to Grafana for linked panels |
| **node-exporter / cAdvisor** | Host & container CPU/mem for platform nodes |
| **Blackbox / synthetic probes** | End-to-end ingest→incident canary (ties to planned synthetic probes) |

### 3.3 Optional / later (richer Assistant capabilities)

| Source | Capability unlocked |
|---|---|
| **Pyroscope / continuous profiling** | CLI skill mentions profiles; debug hot model/processor paths |
| **Grafana OnCall / IRM** | MCP OnCall tools; schedule-aware paging |
| **Grafana Incident / Sift** | Cross-link AutoAnalyzer incidents; AI-assisted RCA patterns |
| **Asserts** (Grafana Cloud) | Entity graph + RCA — overlaps planned correlation entity graph |
| **Grafana Cloud MCP / LLM plugins** | Hosted assistant if not self-managing A2A |
| **External SIEM** (Splunk/Elastic Security) | Existing SOC system of record; Grafana as platform-ops lens, AutoAnalyzer as detection spine |

---

## 4. Linking model: AutoAnalyzer ↔ Grafana

Goal: one investigation story from anomaly finding → metrics/logs/traces → human action.

```text
Telemetry (services, Kafka, hosts)
        ↓
Prometheus / Loki / Tempo  ←── OTEL + exporters
        ↓
Grafana (+ Alertmanager)
   ↙         ↘
grafana-mcp   grafana-assistant CLI
   ↘         ↙
 Cursor / SOC analyst
        ↕
AutoAnalyzer incident-api (deeplinks, annotations, severity)
```

### Concrete linking ideas

1. **Incident → Explore deeplink**  
   Store Grafana Explore URLs (or MCP `generate_deeplink`) on incidents: time range around `first_seen`/`last_seen`, filters for `asset_id` / `service_id` / `tenant_id`.

2. **Deploy / model canary annotations**  
   On deployment ingest or model-gateway canary switch, create Grafana annotations so metric anomalies align with change events (MCP annotations API).

3. **Alertmanager → AutoAnalyzer**  
   Critical platform alerts (DLQ spike, lag, model 5xx) create or update AutoAnalyzer incidents via webhook; reverse: high-severity AutoAnalyzer incidents create Grafana annotations or OnCall pages.

4. **Shared identity keys**  
   Standardize labels: `tenant_id`, `service_id`, `asset_id`, `model_name`, `deployment_id`, `trace_id` across Kafka envelopes, OTEL resources, Prom labels, and Loki streams — otherwise assistants cannot join signals.

5. **Runbook projects in Assistant tunnel**  
   Point tunnel projects at `docs/operations/runbooks/` so investigations can pull rollback steps while querying live metrics.

---

## 5. Alerting gaps & ideas

| Gap | Idea |
|---|---|
| No Prom-based SLO alerts | Alertmanager rules for ingest availability, lag, DLQ rate, inference p95, model gateway errors (targets in `planned_upgrades.md` §8.1) |
| Notifications ≠ alert lifecycle | Keep `notification-service` for SOC incident webhooks; use Alertmanager for **platform** ops paging |
| No silences / grouping | Alertmanager silences during maintenance windows (feed correlation suppression later) |
| Assistants can’t see alert history | Requires Grafana alerting + history; then Assistant CLI / MCP can query |
| No on-call awareness | Grafana OnCall or PagerDuty schedule as MCP datasource |

**Suggested starter alert set (platform):**

- `ingestion_gateway_up == 0`
- `kafka_consumergroup_lag > threshold` (per modality)
- `dlq_messages_rate > 0.1% of ingest`
- `inference_latency_p95 > 2s`
- `model_gateway_error_ratio > 0.5%`
- `correlation_publish_failures`
- OpenSearch / Postgres / Redis down

---

## 6. Other assistants & agent tooling (beyond Grafana)

| Assistant / tool | Fit | Notes |
|---|---|---|
| **Antares CLI** (`cli_tools_info.md`) | Code CWE file localization | Orthogonal; SARIF → incident evidence |
| **Cursor + grafana-mcp** | Dashboard/alert engineering | Enable only when talking to live Grafana |
| **Cursor + grafana-assistant plugin** | Ops investigation skill/rules | Depends on CLI binary + Grafana |
| **OpenTelemetry + Alloy** | Unified telemetry pipeline | Prefer over ad-hoc per-service exporters |
| **Prometheus Alertmanager chatbot patterns** | Ops chatops | Optional Slack bots; lower priority than Assistant |
| **Elastic / OpenSearch assistants** | Search evidence corpora | We already store evidence in OpenSearch — could add MCP later |
| **SIEM copilots** (existing Splunk/Sentinel) | Enterprise SOC | Integrate outbound; don’t rebuild |

---

## 7. What AutoAnalyzer already has (don’t rebuild)

| Asset | Keep / extend |
|---|---|
| Incident API + frontend | Add Grafana deeplinks & timeline |
| Correlation engine | Feed labels into Prom/Loki; don’t replace with Asserts overnight |
| Notification service | Peer to Alertmanager, not a substitute for Prom rules |
| Partial OTEL package | Expand to all services → Tempo |
| OpenSearch | Grafana datasource for evidence panels |
| Ops probes in incident-api | Export as Prometheus metrics + synthetic blackbox |

---

## 8. Phased adoption ideas

### Phase A — Data plane first (unblocks assistants)

1. `docker-compose.observability.yml`: Prometheus, Grafana, Loki, Tempo, Alertmanager, Alloy/Promtail.
2. Scrape all AutoAnalyzer services + Redpanda/Postgres/Redis exporters.
3. Provision Grafana datasources + 3–5 dashboards (ingest, inference, correlation, data health).
4. Fix OTEL exporter from `debug` → Tempo.

### Phase B — Assistant access

1. Install [grafana-assistant CLI](https://github.com/grafana/assistant-cli); configure local Grafana instance.
2. Install Cursor plugins: [grafana-assistant](https://github.com/grafana/ai-marketplace/tree/0d0526a92f5e5546bdd9e84390100766cc61298f/plugins/grafana-assistant) + **grafana-mcp** (separate).
3. Document `GRAFANA_URL` / service-account token for agents; Viewer for read, Editor only for dashboard work.
4. Add tunnel project for AutoAnalyzer repo + runbooks.

### Phase C — Product linking

1. Incident detail: “Open in Grafana” deeplink (time-bounded Explore).
2. Deployment/model events → Grafana annotations.
3. Alertmanager webhook → create platform incidents in incident-api.
4. Optional: Grafana OnCall for severity ≥ high.

### Phase D — Hardening

1. Multi-instance Assistant config (prod vs staging).
2. RBAC: assistants never get write tokens in production by default.
3. Tenant label hygiene and PII rules for Loki (no raw secrets in log lines).
4. Record example `grafana-assistant prompt` playbooks for common incidents (lag, DLQ, model 5xx, correlation storm).

---

## 9. Example investigation prompts (once wired)

```text
grafana-assistant prompt "For the last 30 minutes, show inference-worker consumer lag by topic and any related error logs" --json

grafana-assistant prompt "Correlate spike in findings.logs publish rate with model-gateway latency and recent deployments" --json

grafana-assistant prompt "Which alert rules fired for anomaly-platform namespace today and who is on call?" --json
```

MCP-side equivalents: PromQL/LogQL tools + `generate_deeplink` for the same windows, pasted into AutoAnalyzer incident comments.

---

## 10. Decision matrix

| Need | Prefer | Avoid |
|---|---|---|
| Natural-language ops investigation | Grafana Assistant CLI | Asking Antares (wrong domain) |
| Edit dashboards/alerts from Cursor | grafana-mcp (Editor token) | Giving Assistant CLI write expectations |
| Store metrics/logs/traces | Prometheus + Loki + Tempo | Only OpenSearch for everything |
| Page humans on platform SLOs | Alertmanager (+ OnCall) | Only notification-service webhooks |
| Page humans on security incidents | AutoAnalyzer → notification-service / SOAR | Mixing with every infra flap |
| Code vuln file hunt | Antares CLI | Grafana Assistant |
| Streaming anomaly scores | Existing modality models | Either assistant |

---

## 11. Key references

- Grafana Assistant plugin (skills/rules): [grafana/ai-marketplace …/grafana-assistant](https://github.com/grafana/ai-marketplace/tree/0d0526a92f5e5546bdd9e84390100766cc61298f/plugins/grafana-assistant)
- Grafana Assistant CLI binary: [grafana/assistant-cli](https://github.com/grafana/assistant-cli)
- Grafana MCP server: [grafana/mcp-grafana](https://github.com/grafana/mcp-grafana) · [docs](https://grafana.com/docs/grafana/latest/developer-resources/mcp/)
- Prometheus / Alertmanager: [prometheus.io](https://prometheus.io/)
- LGTM / Grafana+Prometheus stack context: industry 2026 observability summaries (Grafana Labs PLG/LGTM pattern)
- AutoAnalyzer observability roadmap: `planned_upgrades.md` §8

---

## Bottom line

**Grafana Assistant CLI is the right assistant for monitoring and cross-signal investigation** — but only after AutoAnalyzer grows real **Prometheus, Loki, Tempo, Grafana, and Alertmanager** data sources and consistent **tenant/service/asset/trace labels**. Pair it with **grafana-mcp** for dashboard/alert engineering and deeplinks; keep **Antares CLI** for code CWE localization; keep AutoAnalyzer’s own incident spine for security correlation. The missing piece is not more chatbots — it is **queryable telemetry + linking into incidents**.
