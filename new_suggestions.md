# Black Onyx — Blue-Team Analytics & Improvement Suggestions

Research date: 2026-08-02  
Audience: cybersecurity blue teamers (SOC analysts, detection engineers, CTI analysts, IR leads)  
Status: research / backlog notes — many analytics and triage items have since shipped; see [docs/FEATURES.md](docs/FEATURES.md) for current product behavior

**Update (2026-08-07):** the P0 foundation items in §8 have shipped and should not be re-proposed:
1. Disposition + acknowledge timestamps on alerts — done (`web/src/detection/pages/IncidentDetail.tsx`, `IncidentDisposition` in `web/src/detection/api/contracts.ts`).
2. `/api/v1/analytics/overview` + `/timeseries` — done (`src/black_onyx/api/routes_analytics.py`, `src/black_onyx/threat/analytics.py`).
3. Dashboard ops KPIs + sparklines — done (`web/src/components/ops_kpis.tsx`).
4. Open detections read access to analysts — done (`/detections` gates on the `operational` role, not admin, in `web/src/main.tsx`).
5. Chart library + shared `AnalyticsChart` primitives — done (`recharts` in `web/package.json`, `web/src/components/charts.tsx`).

A unified `/triage` route and `/analytics` workspace (§6.1, §4) have also shipped (`web/src/main.tsx`, `web/src/workflows_analytics.tsx`). Treat §8 P1/P2/P3 items as the current backlog frontier, not P0.

---

## 1. What Black Onyx is today

Black Onyx is an **invite-only threat-intelligence workspace (TIP-first)**, not a SIEM replacement. It combines:

| Layer | What exists |
| --- | --- |
| **Investigation** | Semantic + image search (Qdrant), RAG chat (multi-provider LLM), collections, bookmarks, annotations |
| **Threat intel** | IOC extract/enrich/score, STIX export, feeds (RSS/Atom/TAXII), MISP sync, outbound TAXII 2.1, decay/freshness |
| **CVE intelligence** | NVD + FIRST EPSS + CISA KEV enrichment |
| **ATT&CK** | Technique search, text extraction, tactic heatmap, relationship graphs |
| **Operations** | Cases, watchlists + alerts, inbound webhooks, SOAR-lite playbooks (enrich / case / webhook / Sigma gen / approval) |
| **Detection ingest** | Pull connectors: Microsoft Defender, CrowdStrike Falcon, generic REST → normalized into Qdrant |
| **UX shell** | Classic sidebar workflows + immersive R3F gallery hub with live tile metrics and pin-able external consoles |
| **Security** | Invite-only roles (`admin` / `analyst` / `viewer`), Argon2id, CSRF, optional TOTP MFA |

**Strengths for blue teamers already:** evidence-centric investigation, CTI sharing, enrichment depth, ATT&CK visualization, light automation, and connector-based SIEM/EDR pull.

**Core gap for blue teamers:** the product has rich **operational data** (alerts, cases, detections, IOCs, decay, playbooks) but almost no **time-series analytics, triage queue UX, or SOC KPIs**. The dashboard is health tiles + recent tables — not a detection/response analytics surface.

Explicit product boundaries (from `planned_ideas.md`) that suggestions should respect:

- Do **not** run Sigma/YARA locally
- Do **not** become a full CNAPP / asset CMDB
- Do **not** chase dark-web marketplace features

Improvements should deepen **detection visibility, triage, CTI impact, and ATT&CK coverage analytics** on top of what is already stored.

---

## 2. Research inputs (what blue teams actually measure)

Synthesized from industry guidance (SOC KPIs, IR metrics, CTI value metrics, ATT&CK coverage, alert triage):

| Source | Takeaways relevant to Black Onyx |
| --- | --- |
| [Prophet Security — SOC metrics](https://www.prophetsecurity.ai/blog/soc-metrics-that-matter-mttr-mtti-false-negatives-and-more) | Track detection coverage (ATT&CK-aligned), MTTD, MTTA/MTTI, MTTR; measure analyst cognitive load (alert volume, reopen rate); prioritize ~65% technique coverage over chasing 100% |
| [ArmorPoint — SOC KPIs](https://www.armorpoint.com/blog/soc-metrics-that-matter) | Core nine: MTTD, MTTR, MTTA&A, FPR, FNR, incident volume, escalation rate, closure rate, containment rate; trends over time matter more than single snapshots |
| [UnderDefense — SOC metrics](https://underdefense.com/blog/soc-metrics/) | MTTD formula = alerted_at − activity_started_at; good MTTD often 30m–4h; tool class affects latency (EDR vs correlated SIEM) |
| [Splunk — IR metrics](https://www.splunk.com/en_us/blog/learn/incident-response-metrics.html) | Track volume, severity mix, financial/business impact; metrics for impact + performance + maturity |
| [CyberDefenders — SOC metrics guide](https://cyberdefenders.org/blog/soc-metrics-for-analyzing-soc-performance/) | Four buckets: operational, detection/response, analyst performance, business alignment; alert-to-incident ratio and alerts-by-source are first-class |
| [Filigran — CTI metrics](https://filigran.io/blog/how-metrics-prove-the-value-of-threat-intelligence/) | Prove intel value with outcome metrics (used in detections, reduced noise, faster response) — not vanity feed counts |
| [Anomali — TI metrics](https://www.anomali.com/blog/threat-intelligence-metrics) | Four CTI categories: effectiveness, efficiency, landscape coverage, business impact; true/false positive rates on intel-driven alerts |
| [BitSight — ATT&CK heatmaps](https://www.bitsight.com/learn/cti/mitre-attack-heatmap) | Heatmaps must be risk-prioritized (sector/threat prevalence/CVE linkage), not just “technique seen in docs” |
| [Exaforce — Alert triage](https://www.exaforce.com/learning-center/alert-triage) | Triage = validate → enrich → severity → disposition; FP overload is the top D&R challenge; enrichment + disposition history are the scale levers |
| [Exabeam — IOC Statistics dashboard](https://docs.exabeam.com/en/dashboard/all/dashboard-guide/pre-built-dashboards/event-store-dashboards/ioc-statistics.html) | Pre-built IOC stats dashboards are expected in SOC platforms: match volume, type mix, trend over time |

---

## 3. Gap analysis: data we already have vs. analytics we lack

### Already available as raw signal (can power charts without new sensors)

| Existing store | Blue-team signal |
| --- | --- |
| Watchlist `alerts` | Hits over time, IOC type mix, ack latency (MTTA proxy) |
| Cases + timeline | Open/closed volume, priority mix, time-in-status (MTTR proxy), assignee load |
| Connector `seen_detections` / indexed detections | Pull volume by source, severity/title trends, connector health |
| Decay / IOC tracking | Fresh vs stale, sighting velocity, multi-source corroboration |
| Enrichment cache | Provider hit rates, verdict distribution, cache age |
| ATT&CK fields on points + heatmap API | Technique frequency from ingested/pulled evidence |
| Playbook runs / steps | Automation success, wait-approval dwell time |
| Feeds + MISP sync logs | Intel freshness, sync lag, IOC yield per source |
| Audit events | Admin/ops activity (compliance-adjacent) |
| Gallery tile metrics | Lightweight live counters (good for hub, insufficient for SOC analytics) |

### Missing for blue-team detection analytics

| Gap | Why it hurts |
| --- | --- |
| No charting library / no `/analytics/*` APIs | Cannot show trends, distributions, or SLA burn-down |
| No unified alert triage queue | Watchlist alerts and SIEM detections live in separate UIs; detections are admin-only |
| No disposition taxonomy | Cannot compute true/false positive rates or alert-to-incident ratio |
| No incident timing model | Cases lack `detected_at` / `contained_at` / SLA clocks → no real MTTD/MTTR |
| ATT&CK heatmap is document-driven | Not org detection coverage or connector-mapped coverage |
| No CTI impact metrics | Hard to show “intel reduced noise / created cases / matched detections” |
| No severity histograms or source breakdown charts | Analysts cannot see where noise concentrates |
| Playbooks have run history but no analytics | Cannot prove automation ROI |
| Viewer/analyst cannot see detection metrics | Detection page is admin-gated |

---

## 4. Recommended analytics product: “Operations Analytics”

Add a first-class **Analytics** workspace (route e.g. `/analytics`) and promote a subset of charts onto `/dashboard`. Keep classic power workflows intact; analytics is a read-mostly layer over existing SQLite + Qdrant metadata.

Suggested chart stack (fits React 19 + Vite): **Recharts** or **Visx** (SVG, accessible, no heavy WebGL conflict with the gallery). Prefer server-aggregated time buckets over shipping raw event dumps to the browser.

### 4.1 Dashboard upgrade (high impact, low risk)

Replace/extend the current KPI strip with dual rows:

**Health (keep):** collections, indexed points, active jobs, Qdrant version, connector poll health.

**Ops (add):**

1. Open alerts (unacked) + 7-day sparkline  
2. Open cases by priority (stacked bar)  
3. Detections pulled (24h / 7d) by connector (stacked area)  
4. Fresh vs stale IOC ratio (donut)  
5. MTTA (mean time to acknowledge watchlist alerts) last 7/30d  
6. Playbook runs succeeded/failed (7d)

Every tile deep-links into the owning workflow.

### 4.2 Charts & graphs blue teamers need

#### A. Detection & alert volume (operational)

| Chart | Type | Data source | Question answered |
| --- | --- | --- | --- |
| Alerts over time | Line / area | `alerts.triggered_at` | Are we getting noisier? |
| Alerts by source | Stacked bar | watchlist vs connector vs webhook | Where does volume come from? |
| Detections by connector | Stacked area | connector recent + indexed points tagged with connector | Is Defender vs Falcon dominating? |
| Alert volume by IOC type | Horizontal bar | `ioc_type` | IP/domain/hash/CVE mix |
| Severity distribution | Histogram / donut | case priority + detection severity fields | Are we drowning in lows? |
| Hour-of-day / day-of-week heatmap | Calendar heatmap | alert + detection timestamps | Shift staffing & hunting windows |

#### B. Response effectiveness (detection/response KPIs)

Requires light schema additions (see §5).

| Metric / chart | Type | Definition (practical for Black Onyx) |
| --- | --- | --- |
| **MTTA** | KPI + trend | `acknowledged_at − triggered_at` on watchlist alerts |
| **MTTI** (investigate) | KPI + trend | `case.created_at − alert.triggered_at` when alert promotes to case |
| **MTTR** | KPI + trend | `case.closed_at − case.created_at` (or `contained_at` when added) |
| **MTTD** (best-effort) | KPI + trend | For connector detections: `indexed_at − event_time` when source provides activity start; else label as “ingest latency” |
| Alert-to-case ratio | Gauge | cases created / alerts in window |
| Closure rate | KPI | % cases closed within SLA window |
| Escalation / reopen rate | KPI | status transitions + reopen events |

Industry context: high-performing teams often target MTTD in roughly **30 minutes–4 hours**; MTTR and MTTA expose process bottlenecks more than tooling alone.

#### C. Quality / noise (analyst cognitive load)

| Chart | Type | Needs |
| --- | --- | --- |
| Disposition mix | Stacked bar over time | Disposition enum on alerts/detections: `true_positive`, `false_positive`, `benign_positive`, `duplicate`, `informational`, `escalated` |
| False positive rate | KPI + line | `FP / (TP+FP)` over rolling windows |
| Top noisy IOCs / rules / connectors | Table + bar | Group by indicator or connector title |
| Enrichment verdict distribution | Donut | malicious / suspicious / clean / unknown from scorer |
| Duplicate / dedup savings | KPI | watchlist dedup hits + connector `seen_detections` skips |

Research consistently ranks **false positives / alert fatigue** as the top scale killer; disposition capture is the unlock for FPR and CTI true-positive rate.

#### D. Threat intelligence impact (CTI value)

Align with Filigran/Anomali guidance — measure outcomes, not feed vanity.

| Chart | Type | Question |
| --- | --- | --- |
| Watchlist hit rate by list | Bar | Which intel lists actually fire? |
| IOC yield per feed / MISP sync | Bar | Which sources produce usable indicators? |
| Enrichment coverage | Stacked bar | % IOCs enriched / failed / cached |
| Intel → case conversions | Funnel | IOC sighted → alert → case → closed TP |
| Decay freshness trend | Dual-axis line | fresh/stale counts over time |
| CVE risk board | Table + scatter | CVSS (NVD) vs EPSS vs KEV flag — prioritize patching/hunting |
| STIX/TAXII publish volume | Line | Outbound sharing health |
| “Intel age at match” | Histogram | How old was the IOC when it hit? (freshness of CTI) |

#### E. ATT&CK & detection coverage (threat-informed defense)

Current heatmap counts techniques in selected text/docs. Blue teamers need **coverage vs sightings**:

| Chart | Type | Suggestion |
| --- | --- | --- |
| Org ATT&CK sightings heatmap | Matrix | Aggregate `mitre_techniques` from Qdrant points + connector detections over a date range |
| Coverage vs sightings overlay | Matrix (2-layer) | Layer A: techniques observed in evidence; Layer B: techniques you claim to detect (manual tag or Sigma metadata) — highlight gaps |
| Top tactics trend | Stacked area | Tactic volume over time |
| Technique leaderboard | Bar | Top 20 techniques last 7/30d with deep-link to graph/search |
| Risk-weighted priority | Matrix tint | Weight cells by EPSS/KEV-linked CVEs and watchlist hit frequency (Bitsight-style prioritization, locally computed) |
| ATT&CK Navigator export | Action | Export layer JSON for offline Navigator / sharing |

Do not chase 100% ATT&CK coverage; use the heatmap to **direct detection engineering and hunting** toward high-prevalence / high-impact cells.

#### F. Case / IR / automation analytics

| Chart | Type |
| --- | --- |
| Cases by status funnel | Funnel |
| Time-in-status waterfall | Horizontal stacked bar |
| Assignee workload | Bar |
| Priority aging (SLA burn-down) | Bar / list |
| Playbook success rate & median duration | KPI + line |
| Approval wait time | Histogram |
| Webhook ingest volume & failure rate | Line |

#### G. Gallery / immersive surface

Keep the hub lean, but let tile previews show **real sparklines** (alerts 7d, detections 24h, fresh IOC %) instead of static counters only. Analytics detail stays on `/analytics` and classic pages.

---

## 5. Data & API changes needed (minimal, additive)

These are the smallest schema/API additions that unlock most charts without becoming a SIEM.

### 5.1 Disposition & timing fields

- **Alerts:** `acknowledged_at`, `disposition`, `disposition_by`, `disposition_note`, `promoted_case_id`  
- **Cases:** `detected_at` (optional), `contained_at`, `closed_at` (if not already first-class), `sla_due_at`, `severity` normalized  
- **Connector detections (payload or side table):** preserve source `event_time`, `severity`, `technique_ids`, `host`/`user` when present; store `disposition` after analyst review  
- **Playbook runs:** already have history — expose aggregate endpoints

### 5.2 Analytics API group

Suggested read APIs under `/api/v1/analytics/...` (role: all authenticated; mutate dispositions remain analyst+):

| Endpoint | Returns |
| --- | --- |
| `GET /analytics/overview?range=7d` | KPI bundle for dashboard |
| `GET /analytics/timeseries?metric=alerts&group_by=source` | Bucketed series |
| `GET /analytics/distributions?metric=ioc_type` | Category counts |
| `GET /analytics/kpis?metrics=mtta,mttr,fpr` | Computed KPIs + prior-period delta |
| `GET /analytics/attack/coverage?range=30d` | Technique → count (+ optional coverage tags) |
| `GET /analytics/cti/impact?range=30d` | Funnel + feed yield |
| `GET /analytics/connectors/health` | Last poll, error rate, volume |

Server-side aggregation (SQL `GROUP BY` time buckets + optional Qdrant facet counts) keeps the UI fast.

### 5.3 Role adjustments

- Expose **read-only detections analytics** to `analyst` and `viewer` (connector **config** stays admin).  
- Keep secret material and connector credentials admin-only.

---

## 6. Workflow improvements beyond charts

Charts alone do not make a blue-team tool usable under load. Pair analytics with these UX/process upgrades:

### 6.1 Unified triage queue (highest product leverage)

One **Triage** view merging:

- Watchlist alerts  
- Connector detections (normalized)  
- Webhook events awaiting review  

Columns: severity, source, IOC/entity, ATT&CK techniques, enrichment verdict, age, assignee.  
Actions: acknowledge, set disposition, enrich, create/link case, trigger playbook, open in graph/search.

This matches the validate → enrich → severity → disposition loop described in modern triage guidance.

### 6.2 Alert → case promotion with timing

One-click “Promote to case” that stamps `promoted_case_id` and starts MTTR clocks. Without this link, KPIs stay vanity.

### 6.3 Analyst-facing detections (not admin-only)

Admins configure connectors; analysts live in the queue. Current admin-only detections page blocks the primary blue-team user.

### 6.4 Hunting assist from analytics

From any chart bar/cell: “Search evidence for this technique/IOC/source” pre-fills `/search` or `/graph`. Turns analytics into investigation, not wallpaper.

### 6.5 CTI feedback loop

When an alert disposition is `false_positive`, offer:

- Suppress / raise threshold on that watchlist item  
- Mark IOC confidence down  
- Optional note back to MISP (manual publish)  

This is how FPR becomes a tuning flywheel.

### 6.6 Scheduled analytics reports

Extend existing Markdown/HTML/PDF reports with an **Ops digest** template: KPIs, top techniques, top noisy sources, open SLA breaches — email/webhook optional later.

### 6.7 Keep SOAR-lite honest

Playbooks already generate Sigma but never execute it. Analytics should show **generated rule count / approval latency**, and deep-link exports to the analyst’s SIEM — not pretend local detection execution.

---

## 7. Suggested metric definitions (Black Onyx-native)

Use these exact definitions so UI, API, and docs stay consistent:

| KPI | Formula | Window |
| --- | --- | --- |
| Alert volume | count(alerts) | 24h / 7d / 30d |
| Detection ingest volume | count(connector detections indexed) | same |
| MTTA | avg(`acknowledged_at − triggered_at`) for acked alerts | 7d / 30d |
| MTTI | avg(`case.created_at − alert.triggered_at`) for promoted alerts | 7d / 30d |
| MTTR | avg(`closed_at − created_at`) for closed cases | 7d / 30d |
| Ingest latency (MTTD proxy) | avg(`indexed_at − event_time`) when `event_time` present | 7d / 30d |
| FPR | FP dispositions / (TP + FP) | 7d / 30d |
| Alert→case ratio | distinct promoted alerts / alerts | 7d / 30d |
| Fresh IOC ratio | fresh / (fresh + stale) from decay summary | point-in-time + trend |
| ATT&CK sighting coverage | distinct techniques seen / techniques in enterprise matrix (or scoped subset) | 30d |
| Automation success | successful playbook runs / total runs | 7d / 30d |
| Intel hit rate | watchlist alerts / active watchlist items (or per-list) | 30d |

Always show **sample size** next to averages (means on n=3 are dangerous).

---

## 8. Prioritized roadmap (suggestions only)

### P0 — Foundation (unlocks almost everything)

1. Disposition + acknowledge timestamps on alerts (and detections)  
2. `/api/v1/analytics/overview` + `/timeseries`  
3. Dashboard ops KPIs + sparklines  
4. Open detections read access to analysts  
5. Chart library + shared `AnalyticsChart` primitives matching existing design system

### P1 — Blue-team daily drivers

6. Unified Triage queue  
7. Alert → case promotion with timing fields  
8. FPR / disposition mix charts  
9. ATT&CK sightings heatmap (org-wide, date-ranged)  
10. CVE risk board (NVD × EPSS × KEV)

### P2 — CTI & automation value

11. CTI impact funnel + feed/MISP yield charts  
12. Playbook analytics  
13. Ops digest report template  
14. ATT&CK Navigator export + coverage-vs-sightings overlay  
15. Gallery tile sparklines fed by analytics overview

### P3 — Nice-to-have / later

16. Shift heatmaps (hour×weekday)  
17. Assignee performance (use carefully; prefer team-level metrics)  
18. SLA policies per case priority  
19. Push/webhook inbound for connectors (today is poll-only) — improves MTTD realism  
20. Saved analytic views / per-role home dashboards

---

## 9. What not to build (stay TIP-shaped)

| Tempting idea | Why skip or defer |
| --- | --- |
| Full log search (KQL/SPL) | SIEM job; Black Onyx already has semantic evidence search |
| Local Sigma/YARA execution | Explicitly out of scope |
| Full asset/identity CMDB | Out of scope CNAPP territory; optional enrich fields on detections are enough |
| Vanity “IOCs ingested this year” alone | Filigran/Anomali: prefer impact metrics |
| 100% ATT&CK coverage score as a goal | Misaligned incentive; prioritize risk-weighted gaps |
| Replacing vendor EDR consoles | Gallery external sites already cover “open the console”; focus on correlation + KPIs here |

---

## 10. Mapping suggestions → existing UI surfaces

| Surface | Improvement |
| --- | --- |
| `/dashboard` | Ops KPI row + mini charts; keep health metrics |
| **New** `/analytics` | Full chart workspace with range filters |
| `/detections` | Analyst-readable; disposition; charts strip; feed triage |
| `/watchlists` | Ack timing + disposition; noisy-item leaderboard |
| `/cases` | SLA clocks, time-in-status chart, promote-from-alert |
| `/attack` | Org sightings heatmap + Navigator export (keep current doc heatmap) |
| `/iocs` | Verdict distribution + CVE risk scatter |
| `/feeds` + MISP | Yield / lag charts |
| `/playbooks` | Success/latency analytics |
| `/decay` | Freshness trend chart |
| `/` gallery | Sparklines on Ops tiles; optional Analytics tile |
| Reports | Ops digest template |

---

## 11. Success criteria (how we’d know this helped blue teamers)

1. An analyst can answer in under a minute: “What fired overnight, from where, and what’s still unacked?”  
2. A lead can show 30-day MTTA/MTTR/FPR trends in a stakeholder review without exporting CSV by hand.  
3. CTI can point to watchlists/feeds that produce true positives vs noise.  
4. Detection engineering can open an ATT&CK cell and jump to evidence + hunting search.  
5. Automation shows measurable reduction in time-to-enrich / time-to-case.  
6. None of the above requires leaving Black Onyx for a spreadsheet — while still not pretending to be the SIEM of record.

---

## 12. Summary verdict

Black Onyx is already strong as a **TIP + investigation + light SOAR** workspace with growing **SIEM/EDR pull**. The largest blue-team gap is not “more connectors” — it is **turning existing alerts, cases, detections, IOCs, ATT&CK, and playbook telemetry into triage workflows and time-series analytics**.

Highest-leverage path:

1. Capture dispositions and timestamps  
2. Ship an analytics API + dashboard charts  
3. Unify triage  
4. Evolve ATT&CK from document heatmap → org sightings/coverage analytics  
5. Prove CTI and automation impact with funnels, not vanity counters

That sequence keeps the product inside its TIP charter while giving blue teamers the charts, graphs, metrics, and detection visibility they need to operate day to day.
