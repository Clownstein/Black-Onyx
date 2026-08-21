# Qdrant Implementation — Vector Search for Detection, Linking, TI & Anomaly Analysis

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).


**Audience:** Platform, detection engineering, correlation, threat intel  
**Status:** Design history (implemented — see canonical docs)  
**Date:** July 2026  
**Related:** [`planned_upgrades.md`](planned_upgrades.md), [`security_implementation.md`](security_implementation.md), [`docs/defender/mitre-coverage.md`](docs/defender/mitre-coverage.md)

---

## 1. Executive summary

[Qdrant](https://qdrant.tech/) is an open-source, Rust-based **vector database** optimized for similarity search over high-dimensional embeddings. Official use cases include [advanced search](https://qdrant.tech/use-cases/), [RAG](https://qdrant.tech/rag/), [recommendations](https://qdrant.tech/recommendations/), and [data analysis / anomaly detection](https://qdrant.tech/data-analysis-anomaly-detection/). Industry writing on “vector SIEM” argues that representing security events as vectors enables multi-attribute similarity, long-horizon pattern recall, and ML-friendly analytics that single-threshold rules struggle with ([Auguria — Why Your Next SIEM Will Analyze Vectors](https://auguria.io/insights/why-your-next-siem-will-analyze-vectors/)).

For **AutoAnalyzer**, Qdrant should **complement**—not replace—existing systems:

| Keep as-is | Add with Qdrant |
| --- | --- |
| Kafka modalities → models → `findings.*` | Embedding + nearest-neighbor enrichment |
| Redis / memory correlation buckets | Semantic **linking** of similar past findings/incidents |
| Postgres exact IOC match (`threat-intel-service`) | **Fuzzy / semantic** TI (similar malware reports, related campaigns, ATT&CK narrative match) |
| OpenSearch (hunt / full-text / ILM) | Dense+sparse retrieval for analyst RAG and “find me similar” |
| Deterministic detectors + logistic scoring | Distance-from-normal / diversity search as **additional** signals |

Exact matches (IP = IOC, hash = hash) stay in Postgres. Qdrant answers: *“What does this look like?”*, *“Have we seen behavior like this?”*, *“Which intel or MITRE technique narratives are nearest?”*

---

## 2. What Qdrant provides (research takeaways)

### 2.1 Core capabilities relevant to security

| Capability | Why it matters for AutoAnalyzer |
| --- | --- |
| **Dense vector ANN search** | Find semantically similar logs, findings, code diffs, flow windows, TI descriptions |
| **Payload filtering** (`must` / `should` / `must_not`) | Enforce `tenant_id`, TLP, modality, time window, asset tags without re-embedding ([filtering docs](https://qdrant.tech/documentation/search/filtering/)) |
| **Named / multi-vectors per point** | Store both a modality embedding and a text embedding on one point |
| **Hybrid queries + RRF/DBSF fusion** | Combine dense semantic + sparse keyword (e.g., IOC strings, CVE IDs) in one query ([hybrid queries](https://qdrant.tech/documentation/search/hybrid-queries/)) |
| **Recommend / diversity / discover APIs** | Cluster-like exploration; surface dissimilar outliers for anomaly workflows ([anomaly page](https://qdrant.tech/data-analysis-anomaly-detection/)) |
| **Collections + payload indexes** | Scale per-tenant or shared multi-tenant with indexed `tenant_id` |

### 2.2 Anomaly detection patterns with vectors

Common patterns documented in Qdrant tutorials and case studies:

1. **Distance-from-centroid / kNN density** — Embed “normal” windows; score new points by distance to nearest neighbors or cluster center. Far = anomalous.
2. **Dissimilarity / diversity search** — Ask for points *unlike* the normal set (Qdrant’s anomaly-oriented APIs).
3. **Isolation Forest + vectors** — Train classical AD on embedding space; store embeddings in Qdrant for retrieval of nearest training examples when explaining a score ([Isolation Forest + Qdrant tutorial](https://vectorsearch.tech/anomaly-detection-with-isolation-forest-and-qdrant/)).
4. **Metric learning** — Train encoders so same-class behaviors cluster; attackers / faults land off-manifold ([Qdrant coffee anomaly case study referenced on their AD page](https://qdrant.tech/data-analysis-anomaly-detection/)).

AutoAnalyzer already has **modality specialist models**. Qdrant does not replace them; it stores their embeddings (or parallel text embeddings) so correlation and analysts can **retrieve neighbors** and **link** events across time.

### 2.3 Vector SIEM / SOC narrative

Vector-centric SOC designs emphasize:

- Multi-attribute comparison beats brittle univariate thresholds.
- Historical retention of compact vectors is cheaper than full raw log hot storage for “similarity over months.”
- Embeddings are the native input format for LLMs used in investigation assistants (RAG over past incidents, runbooks, ATT&CK).

AutoAnalyzer should keep **OpenSearch for raw/hunt** and use **Qdrant for similarity + RAG indexes**.

---

## 3. Platform fit — where Qdrant plugs in

```text
  *.raw → processors → *.features → inference-worker → findings.*
                              │                              │
                              │ optional embed               │
                              ▼                              ▼
                     ┌─────────────────┐            ┌──────────────────┐
                     │ embedding-worker│───────────►│     Qdrant       │
                     │ (new or extend  │  upsert    │  collections     │
                     │  inference)     │            └────────┬─────────┘
                     └─────────────────┘                     │
                                                             │ search / recommend
              ┌──────────────────────────────────────────────┼────────────────┐
              ▼                                              ▼                ▼
   correlation-engine                              threat-intel-service   incident-api /
   (similar-incident link,                         (semantic IOC /        ops console
    neighbor evidence)                              report / ATT&CK RAG)   ("Similar")
```

### 3.1 Services touched (proposed)

| Component | Role with Qdrant |
| --- | --- |
| **New `embedding-worker`** (or stage in `inference-worker`) | Consume features/findings; call embedding model; upsert points |
| **`correlation-engine`** | Query similar open/recent findings; boost risk / merge candidates; attach neighbor IDs |
| **`threat-intel-service`** | Keep Postgres exact match; add `/api/v1/match/semantic` via Qdrant |
| **`incident-api` + frontend** | “Similar incidents”, hunt-by-example, RAG context for investigation notes |
| **Compose / Helm** | Optional `qdrant` service (port **6333** HTTP / **6334** gRPC typical) |

Env prefix proposal: `QDRANT_` (URL, API key, collection names). Feature flag: `VECTOR_SEARCH_ENABLED=false` by default so air-gapped / minimal stacks stay unchanged.

---

## 4. Use cases for AutoAnalyzer

### 4.1 Detection

| Use case | How |
| --- | --- |
| **Near-duplicate attack patterns** | Embed finding summaries / contributor feature bags; alert when a new finding is close to a known-bad prototype vector (campaign fingerprint) |
| **Low-and-slow behavioral novelty** | Maintain rolling “normal” vectors per asset/service; flag points with low neighbor density |
| **Cross-modality prototype matching** | One collection of labeled attack prototypes (red-team / historical incidents); match live findings regardless of modality |
| **Code risk neighbors** | Embed Semgrep + diff text; detect PRs similar to past high-risk changes even if rules differ |

**Important:** Treat vector scores as **contributors** on findings (`type: vector_similarity`), not sole block criteria—aligned with platform “no auto-remediation from raw anomaly alone.”

### 4.2 Analyzing

| Use case | How |
| --- | --- |
| **Explain-by-neighbors** | For any finding, return top-k similar past findings with outcomes (FP / TP / resolved) |
| **Cluster exploration** | Diversity/recommend queries to map alert fatigue groups |
| **Investigation RAG** | Hybrid search over runbooks, past incident write-ups, MITRE technique text → LLM context ([RAG](https://qdrant.tech/rag/)) |
| **Security profile checklist assist** | Embed checklist text from `security_standards.md` packs; suggest related open findings |

### 4.3 Linking (entity & incident correlation)

Today correlation buckets by `tenant|asset|service` in Redis ([correlation-engine](services/correlation-engine/AGENTS.md)). Qdrant adds **soft links**:

| Link type | Mechanism |
| --- | --- |
| **Similar findings across assets** | Same TTPs, different hosts — payload filter `tenant_id`, search without requiring same `asset_id` |
| **Campaign stitching** | Shared embedding neighborhood + shared TI campaign labels |
| **User / identity behavior** | Embed sequences of auth events; link impossible-travel-like neighbors |
| **Incident dedup assist** | Before creating a new incident, search similar open incidents; suggest merge / relate |

Payload should always carry graph-friendly IDs: `finding_id`, `incident_id`, `asset_id`, `observable_values[]`, `mitre_techniques[]`.

`planned_upgrades.md` mentions an **entity graph** (OpenSearch or graph DB). Qdrant can bootstrap “edges” as *similarity relationships* while a true graph store remains optional later.

### 4.4 Threat intelligence

Current TI path: Postgres upsert + **exact** `match_observables` → correlation enrichment ([threat-intel-service](services/threat-intel-service/AGENTS.md)).

Qdrant extends TI as follows:

| Capability | Exact (Postgres) | Semantic (Qdrant) |
| --- | --- | --- |
| IP / domain / hash / CVE equality | ✅ Primary | Optional corroboration |
| Partially obfuscated URLs / typosquat domains | Weak | ✅ Embedding + sparse token hybrid |
| Malware report / STIX description similarity | ❌ | ✅ Embed `description` / `labels` / raw STIX text |
| “Reports like this campaign” | ❌ | ✅ |
| ATT&CK technique narrative match from alert text | ❌ | ✅ Embed MITRE descriptions; retrieve technique IDs ([community pattern: ATT&CK in Qdrant for SIEM enrichment](https://www.youtube.com/watch?v=SbWrCe0R9LE)) |
| Air-gapped | Bundle Postgres indicators | Ship **signed Qdrant snapshots** of intel+ATT&CK collections |

**Hybrid TI match algorithm (proposed):**

1. Run exact match (unchanged).  
2. If miss or low confidence, embed observable context (URL path, email subject, file name, alert text).  
3. Hybrid query: dense + sparse over `ti_reports` / `ti_indicators_text` collections with filters: `tlp`, `valid_until`, `tenant_id` (or global), `confidence >= N`.  
4. Return `ThreatIntelMatchResult` with `match_type: exact | semantic`, distance, and cited indicator IDs.

Do **not** auto-promote semantic-only IP matches to the same confidence as exact hash hits—cap confidence and require analyst or multi-signal correlation.

### 4.5 Anomaly detection (alongside existing models)

| Modality | Vector approach |
| --- | --- |
| **Logs** | Embed Drain3 template sequences or log windows; kNN density vs per-service baseline collection |
| **Network** | Embed flow-window feature vectors already produced for `network-model` (reuse model hidden state or explicit feature vector) |
| **Metrics** | Embed resampled windows; detect shape anomalies similar to past incidents |
| **Code** | Embed diff + scanner finding text; novelty vs repo baseline |
| **Host-state** | Embed process trees / rare binary paths for neighbor search |

**Two-layer scoring (recommended):**

1. Existing modality model → `calibrated_score` (unchanged contract).  
2. Optional `vector_novelty` = `1 - max_cosine_similarity(neighbors in baseline)` added as a contributor.  
3. Correlation logistic score consumes both.

This preserves golden-path tests while allowing A/B of vector novelty.

---

## 5. Collection design

### 5.1 Suggested collections

| Collection | Point = | Vectors | Key payload fields |
| --- | --- | --- | --- |
| `findings_v1` | One finding | `dense` **768** (SecureBERT) + optional `sparse` | `tenant_id`, `finding_id`, `finding_type`, `asset_id`, `service_id`, `severity`, `mitre_techniques`, `occurred_at`, `incident_id` |
| `incidents_v1` | One incident | `dense` **768** (SecureBERT) + optional `sparse` | `tenant_id`, `incident_id`, `status`, `risk_score`, `asset_ids`, `labels` |
| `features_baseline_v1` | Feature window (sampled) | modality named vectors (numeric; `code` text = 768 SecureBERT) | `tenant_id`, `modality`, `asset_id`, `window_start`, `is_baseline=true` |
| `ti_text_v1` | Indicator or report chunk | `dense` **768** + `sparse` | `indicator_id`, `observable_type`, `source`, `tlp`, `confidence`, `valid_until`, `mitre_techniques`, `campaigns` |
| `attack_tech_v1` | ATT&CK technique/tactic text | `dense` **768** (SecureBERT) | `technique_id`, `tactic`, `name` |
| `runbooks_v1` | Chunk of runbook / IR doc | `dense` **768** + `sparse` | `doc_id`, `title`, `tags` (for RAG) |

### 5.2 Multi-tenancy

- **Mandatory** payload filter: `tenant_id` on every search (mirror SQL discipline).  
- Index `tenant_id` as a [payload index](https://qdrant.tech/documentation/search/filtering/) for speed.  
- Global intel (`tenant_id: null` or `tenant_id: "__global__"`) searchable with explicit filter OR.  
- Prefer **one shared collection + tenant filter** over per-tenant collections until scale demands isolation.

### 5.3 Point IDs

Use deterministic ULIDs already in envelopes (`finding_id`, `indicator_id`) as Qdrant point IDs where possible for idempotent upserts.

### 5.4 Retention

- Findings vectors: hot 30–90 days (align OpenSearch ILM philosophy).  
- Baseline vectors: rolling window per asset (e.g., 14 days), downsample.  
- TI / ATT&CK / runbooks: long-lived; refresh on feed sync.  
- TTL via payload `expires_at` + periodic scroll/delete job (Qdrant has collection-level optimization; implement sweeper in worker).

### 5.5 Collection data schemas

Dimensions below assume the default **cybersecurity text** embedder [cisco-ai/SecureBERT2.0-biencoder](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder) at **768** dims (Cosine). Feature-window vectors in `features_baseline_v1` stay modality-specific numeric sizes (not SecureBERT). Change `size` only with a new collection version (`*_v2`).

Shared conventions for every collection:

| Field | Rule |
| --- | --- |
| Point `id` | UUID/ULID string matching platform IDs when possible |
| Distance (dense) | `Cosine` (vectors L2-normalized before upsert) |
| Sparse | Qdrant `SparseVector` (`indices` + `values`); optional until hybrid ships |
| Timestamps | ISO-8601 UTC strings in payload; also store `occurred_at_ts` (unix seconds) for range filters |
| Embedding provenance | Always set `embed_model`, `embed_version` |

---

#### 5.5.1 `findings_v1`

**Purpose:** Similar-finding search, correlation neighbor evidence, hunt-by-example.

**Collection config**

```json
{
  "collection_name": "findings_v1",
  "vectors": {
    "dense": {
      "size": 768,
      "distance": "Cosine"
    }
  },
  "sparse_vectors": {
    "sparse": {}
  }
}
```

**Payload schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://autoanalyzer.local/qdrant/findings_v1.payload.json",
  "title": "FindingsV1Payload",
  "type": "object",
  "required": [
    "tenant_id",
    "finding_id",
    "finding_type",
    "asset_id",
    "calibrated_score",
    "occurred_at",
    "occurred_at_ts",
    "embed_model",
    "embed_version"
  ],
  "properties": {
    "tenant_id": { "type": "string", "minLength": 1 },
    "finding_id": { "type": "string", "minLength": 1 },
    "finding_type": {
      "type": "string",
      "description": "e.g. log.anomaly, network.flow_anomaly, code.risk, host_state.anomaly, firewall.deny_spike"
    },
    "modality": {
      "type": "string",
      "enum": ["log", "code", "network", "metrics", "host_state", "firewall", "malware", "other"]
    },
    "asset_id": { "type": "string" },
    "service_id": { "type": ["string", "null"] },
    "site_id": { "type": ["string", "null"] },
    "model_name": { "type": ["string", "null"] },
    "calibrated_score": { "type": "number", "minimum": 0, "maximum": 1 },
    "severity_hint": {
      "type": ["string", "null"],
      "enum": ["info", "low", "medium", "high", "critical", null]
    },
    "incident_id": { "type": ["string", "null"] },
    "mitre_tactics": { "type": "array", "items": { "type": "string" } },
    "mitre_techniques": { "type": "array", "items": { "type": "string" } },
    "contributor_types": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Flattened contributor.type values for sparse/filter use"
    },
    "observables": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["type", "value"],
        "properties": {
          "type": {
            "type": "string",
            "enum": ["ipv4", "ipv6", "domain", "url", "file_hash", "email", "ja3", "cve", "user", "host"]
          },
          "value": { "type": "string" }
        }
      }
    },
    "summary_text": {
      "type": "string",
      "description": "Redacted text that was embedded; keep short; no secrets/PHI/CHD"
    },
    "occurred_at": { "type": "string", "format": "date-time" },
    "occurred_at_ts": { "type": "integer", "minimum": 0 },
    "expires_at_ts": { "type": ["integer", "null"], "minimum": 0 },
    "embed_model": { "type": "string" },
    "embed_version": { "type": "string" },
    "schema_version": { "type": "string", "pattern": "^[0-9]+\\.[0-9]+$" }
  },
  "additionalProperties": false
}
```

**Payload indexes:** `tenant_id` (keyword), `finding_type` (keyword), `modality` (keyword), `asset_id` (keyword), `incident_id` (keyword), `occurred_at_ts` (integer), `mitre_techniques` (keyword), `calibrated_score` (float).

**Example point**

```json
{
  "id": "01JFINDING0000000000000000",
  "vector": {
    "dense": [0.01, 0.02],
    "sparse": { "indices": [12, 88, 401], "values": [0.9, 0.4, 0.2] }
  },
  "payload": {
    "tenant_id": "tenant-acme",
    "finding_id": "01JFINDING0000000000000000",
    "finding_type": "network.flow_anomaly",
    "modality": "network",
    "asset_id": "asset-checkout-01",
    "service_id": "checkout",
    "site_id": "site-ewr",
    "model_name": "network-model",
    "calibrated_score": 0.86,
    "severity_hint": "high",
    "incident_id": "01JINCIDENT000000000000000",
    "mitre_tactics": ["Command and Control"],
    "mitre_techniques": ["T1071"],
    "contributor_types": ["new_external_peer", "beaconing_heuristic"],
    "observables": [{ "type": "ipv4", "value": "203.0.113.50" }],
    "summary_text": "New external peer with periodic egress from checkout",
    "occurred_at": "2026-07-27T14:02:11.000Z",
    "occurred_at_ts": 1785156131,
    "expires_at_ts": 1787748131,
    "embed_model": "cisco-ai/SecureBERT2.0-biencoder",
    "embed_version": "1",
    "schema_version": "1.0"
  }
}
```

---

#### 5.5.2 `incidents_v1`

**Purpose:** Similar-incident search, merge/relate suggestions, RAG seed for investigations.

**Collection config**

```json
{
  "collection_name": "incidents_v1",
  "vectors": {
    "dense": {
      "size": 768,
      "distance": "Cosine"
    }
  },
  "sparse_vectors": {
    "sparse": {}
  }
}
```

**Payload schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://autoanalyzer.local/qdrant/incidents_v1.payload.json",
  "title": "IncidentsV1Payload",
  "type": "object",
  "required": [
    "tenant_id",
    "incident_id",
    "status",
    "severity",
    "risk_score",
    "created_at",
    "created_at_ts",
    "embed_model",
    "embed_version"
  ],
  "properties": {
    "tenant_id": { "type": "string" },
    "incident_id": { "type": "string" },
    "status": {
      "type": "string",
      "enum": ["open", "acknowledged", "investigating", "resolved", "suppressed"]
    },
    "severity": {
      "type": "string",
      "enum": ["info", "low", "medium", "high", "critical"]
    },
    "risk_score": { "type": "number", "minimum": 0, "maximum": 1 },
    "title": { "type": "string" },
    "summary_text": { "type": "string" },
    "asset_ids": { "type": "array", "items": { "type": "string" } },
    "service_ids": { "type": "array", "items": { "type": "string" } },
    "finding_ids": { "type": "array", "items": { "type": "string" } },
    "modalities": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["log", "code", "network", "metrics", "host_state", "firewall", "malware"]
      }
    },
    "mitre_tactics": { "type": "array", "items": { "type": "string" } },
    "mitre_techniques": { "type": "array", "items": { "type": "string" } },
    "labels": { "type": "array", "items": { "type": "string" } },
    "disposition": {
      "type": ["string", "null"],
      "description": "Align with incident-api disposition enums when set"
    },
    "created_at": { "type": "string", "format": "date-time" },
    "created_at_ts": { "type": "integer" },
    "updated_at_ts": { "type": ["integer", "null"] },
    "expires_at_ts": { "type": ["integer", "null"] },
    "embed_model": { "type": "string" },
    "embed_version": { "type": "string" },
    "schema_version": { "type": "string" }
  },
  "additionalProperties": false
}
```

**Payload indexes:** `tenant_id`, `status`, `severity`, `created_at_ts`, `mitre_techniques`, `risk_score`.

**Example point**

```json
{
  "id": "01JINCIDENT000000000000000",
  "vector": {
    "dense": [0.11, -0.03],
    "sparse": { "indices": [3, 19], "values": [1.0, 0.5] }
  },
  "payload": {
    "tenant_id": "tenant-acme",
    "incident_id": "01JINCIDENT000000000000000",
    "status": "investigating",
    "severity": "high",
    "risk_score": 0.91,
    "title": "Checkout egress + auth anomalies",
    "summary_text": "Correlated network beaconing with failed logon burst on checkout hosts",
    "asset_ids": ["asset-checkout-01"],
    "service_ids": ["checkout"],
    "finding_ids": ["01JFINDING0000000000000000", "01JFINDING0000000000000001"],
    "modalities": ["network", "log"],
    "mitre_tactics": ["Command and Control", "Credential Access"],
    "mitre_techniques": ["T1071", "T1110"],
    "labels": ["production", "pci-adjacent"],
    "disposition": null,
    "created_at": "2026-07-27T14:05:00.000Z",
    "created_at_ts": 1785156300,
    "updated_at_ts": 1785156400,
    "expires_at_ts": null,
    "embed_model": "cisco-ai/SecureBERT2.0-biencoder",
    "embed_version": "1",
    "schema_version": "1.0"
  }
}
```

---

#### 5.5.3 `features_baseline_v1`

**Purpose:** Per-asset/service “normal” windows for novelty / distance-from-baseline anomaly signals.

**Collection config**

```json
{
  "collection_name": "features_baseline_v1",
  "vectors": {
    "log": { "size": 128, "distance": "Cosine" },
    "network": { "size": 64, "distance": "Cosine" },
    "metrics": { "size": 64, "distance": "Cosine" },
    "code": { "size": 768, "distance": "Cosine" },
    "host_state": { "size": 128, "distance": "Cosine" }
  }
}
```

Only **one** named vector is set per point (the active `modality`). Numeric sizes for `log` / `network` / `metrics` / `host_state` are illustrative—match live model/feature dims at implementation time. The `code` named vector uses **768** when embedding diff text with SecureBERT 2.0.

**Payload schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://autoanalyzer.local/qdrant/features_baseline_v1.payload.json",
  "title": "FeaturesBaselineV1Payload",
  "type": "object",
  "required": [
    "tenant_id",
    "modality",
    "asset_id",
    "window_start",
    "window_start_ts",
    "window_end",
    "window_end_ts",
    "is_baseline",
    "embed_model",
    "embed_version"
  ],
  "properties": {
    "tenant_id": { "type": "string" },
    "modality": {
      "type": "string",
      "enum": ["log", "network", "metrics", "code", "host_state"]
    },
    "asset_id": { "type": "string" },
    "service_id": { "type": ["string", "null"] },
    "site_id": { "type": ["string", "null"] },
    "feature_event_id": {
      "type": ["string", "null"],
      "description": "Upstream features envelope event_id if available"
    },
    "window_start": { "type": "string", "format": "date-time" },
    "window_start_ts": { "type": "integer" },
    "window_end": { "type": "string", "format": "date-time" },
    "window_end_ts": { "type": "integer" },
    "is_baseline": {
      "type": "boolean",
      "const": true,
      "description": "Always true for this collection; live suspects are queried, not stored here by default"
    },
    "sample_rate": {
      "type": "number",
      "minimum": 0,
      "maximum": 1,
      "description": "Downsample factor used when selecting this window"
    },
    "feature_fingerprint": {
      "type": ["string", "null"],
      "description": "Hash of feature keys for drift debugging"
    },
    "expires_at_ts": { "type": ["integer", "null"] },
    "embed_model": { "type": "string" },
    "embed_version": { "type": "string" },
    "schema_version": { "type": "string" }
  },
  "additionalProperties": false
}
```

**Payload indexes:** `tenant_id`, `modality`, `asset_id`, `service_id`, `window_start_ts`, `is_baseline`.

**Example point**

```json
{
  "id": "01JBASELINE000000000000000",
  "vector": {
    "network": [0.05, 0.12]
  },
  "payload": {
    "tenant_id": "tenant-acme",
    "modality": "network",
    "asset_id": "asset-checkout-01",
    "service_id": "checkout",
    "site_id": "site-ewr",
    "feature_event_id": "01JFEATURE0000000000000000",
    "window_start": "2026-07-27T13:45:00.000Z",
    "window_start_ts": 1785155100,
    "window_end": "2026-07-27T14:00:00.000Z",
    "window_end_ts": 1785156000,
    "is_baseline": true,
    "sample_rate": 0.1,
    "feature_fingerprint": "sha256:abc…",
    "expires_at_ts": 1786365600,
    "embed_model": "network-feature-l2",
    "embed_version": "1",
    "schema_version": "1.0"
  }
}
```

---

#### 5.5.4 `ti_text_v1`

**Purpose:** Semantic / hybrid threat-intel match beside Postgres exact IOC store. Align observable enums with `contracts/threat-intel/indicator.schema.json`.

**Collection config**

```json
{
  "collection_name": "ti_text_v1",
  "vectors": {
    "dense": {
      "size": 768,
      "distance": "Cosine"
    }
  },
  "sparse_vectors": {
    "sparse": {}
  }
}
```

**Payload schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://autoanalyzer.local/qdrant/ti_text_v1.payload.json",
  "title": "TiTextV1Payload",
  "type": "object",
  "required": [
    "indicator_id",
    "observable_type",
    "observable_value",
    "source",
    "confidence",
    "chunk_kind",
    "text",
    "embed_model",
    "embed_version"
  ],
  "properties": {
    "tenant_id": {
      "type": ["string", "null"],
      "description": "null or __global__ for shared feed intel"
    },
    "indicator_id": { "type": "string" },
    "chunk_id": {
      "type": "string",
      "description": "indicator_id or indicator_id:chunkN for long reports"
    },
    "chunk_kind": {
      "type": "string",
      "enum": ["observable", "description", "report", "stix_pattern", "kev_summary"]
    },
    "observable_type": {
      "type": "string",
      "enum": ["ipv4", "ipv6", "domain", "url", "file_hash", "email", "ja3", "cve", "text"]
    },
    "observable_value": { "type": "string" },
    "source": { "type": "string" },
    "confidence": { "type": "integer", "minimum": 0, "maximum": 100 },
    "tlp": {
      "type": ["string", "null"],
      "enum": ["white", "green", "amber", "red", "clear", null]
    },
    "valid_from": { "type": ["string", "null"], "format": "date-time" },
    "valid_until": { "type": ["string", "null"], "format": "date-time" },
    "valid_until_ts": { "type": ["integer", "null"] },
    "labels": { "type": "array", "items": { "type": "string" } },
    "campaigns": { "type": "array", "items": { "type": "string" } },
    "mitre_techniques": { "type": "array", "items": { "type": "string" } },
    "text": {
      "type": "string",
      "description": "Embedded chunk (description, STIX name+desc, KEV summary, etc.)"
    },
    "external_refs": {
      "type": "array",
      "items": { "type": "object" }
    },
    "embed_model": { "type": "string" },
    "embed_version": { "type": "string" },
    "schema_version": { "type": "string" }
  },
  "additionalProperties": false
}
```

**Payload indexes:** `tenant_id`, `observable_type`, `source`, `tlp`, `confidence`, `valid_until_ts`, `campaigns`, `mitre_techniques`, `chunk_kind`.

**Example point**

```json
{
  "id": "ind-01JTI000000000000000000:0",
  "vector": {
    "dense": [0.2, 0.01],
    "sparse": { "indices": [1001, 2048], "values": [0.8, 0.6] }
  },
  "payload": {
    "tenant_id": "__global__",
    "indicator_id": "ind-01JTI000000000000000000",
    "chunk_id": "ind-01JTI000000000000000000:0",
    "chunk_kind": "description",
    "observable_type": "domain",
    "observable_value": "malware-c2.example",
    "source": "taxii:acme-cti",
    "confidence": 80,
    "tlp": "amber",
    "valid_from": "2026-07-01T00:00:00.000Z",
    "valid_until": "2026-10-01T00:00:00.000Z",
    "valid_until_ts": 1790812800,
    "labels": ["c2", "botnet"],
    "campaigns": ["campaign-orange"],
    "mitre_techniques": ["T1071.001"],
    "text": "Domain used as HTTP C2 for botnet orange; seen with rare JA3",
    "external_refs": [{ "source_name": "acme-cti", "url": "https://cti.example/rep/1" }],
    "embed_model": "cisco-ai/SecureBERT2.0-biencoder",
    "embed_version": "1",
    "schema_version": "1.0"
  }
}
```

---

#### 5.5.5 `attack_tech_v1`

**Purpose:** Suggest MITRE ATT&CK techniques from finding/incident text (never overwrite high-confidence rule tags blindly).

**Collection config**

```json
{
  "collection_name": "attack_tech_v1",
  "vectors": {
    "dense": {
      "size": 768,
      "distance": "Cosine"
    }
  }
}
```

**Payload schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://autoanalyzer.local/qdrant/attack_tech_v1.payload.json",
  "title": "AttackTechV1Payload",
  "type": "object",
  "required": [
    "technique_id",
    "name",
    "domain",
    "text",
    "embed_model",
    "embed_version"
  ],
  "properties": {
    "technique_id": {
      "type": "string",
      "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$",
      "description": "e.g. T1110 or T1071.001"
    },
    "name": { "type": "string" },
    "tactics": {
      "type": "array",
      "items": { "type": "string" },
      "description": "ATT&CK tactic names or short IDs"
    },
    "domain": {
      "type": "string",
      "enum": ["enterprise", "ics", "mobile"]
    },
    "platforms": {
      "type": "array",
      "items": { "type": "string" }
    },
    "is_subtechnique": { "type": "boolean" },
    "parent_technique_id": { "type": ["string", "null"] },
    "text": {
      "type": "string",
      "description": "name + description (+ detection notes) used for embedding"
    },
    "url": { "type": ["string", "null"], "format": "uri" },
    "attack_version": { "type": "string" },
    "embed_model": { "type": "string" },
    "embed_version": { "type": "string" },
    "schema_version": { "type": "string" }
  },
  "additionalProperties": false
}
```

**Payload indexes:** `technique_id`, `domain`, `tactics`, `is_subtechnique`.

**Example point**

```json
{
  "id": "T1071.001",
  "vector": {
    "dense": [0.08, 0.22]
  },
  "payload": {
    "technique_id": "T1071.001",
    "name": "Web Protocols",
    "tactics": ["Command and Control"],
    "domain": "enterprise",
    "platforms": ["Linux", "Windows", "macOS"],
    "is_subtechnique": true,
    "parent_technique_id": "T1071",
    "text": "T1071.001 Web Protocols — adversaries may communicate using application layer protocols associated with web traffic…",
    "url": "https://attack.mitre.org/techniques/T1071/001/",
    "attack_version": "16.1",
    "embed_model": "cisco-ai/SecureBERT2.0-biencoder",
    "embed_version": "1",
    "schema_version": "1.0"
  }
}
```

---

#### 5.5.6 `runbooks_v1`

**Purpose:** Defender RAG — retrieve IR steps, detector notes, and ops runbooks for investigation assistants.

**Collection config**

```json
{
  "collection_name": "runbooks_v1",
  "vectors": {
    "dense": {
      "size": 768,
      "distance": "Cosine"
    }
  },
  "sparse_vectors": {
    "sparse": {}
  }
}
```

**Payload schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://autoanalyzer.local/qdrant/runbooks_v1.payload.json",
  "title": "RunbooksV1Payload",
  "type": "object",
  "required": [
    "doc_id",
    "chunk_id",
    "title",
    "text",
    "embed_model",
    "embed_version"
  ],
  "properties": {
    "tenant_id": {
      "type": ["string", "null"],
      "description": "null/__global__ for platform docs; set for tenant-specific runbooks"
    },
    "doc_id": { "type": "string" },
    "chunk_id": { "type": "string" },
    "chunk_index": { "type": "integer", "minimum": 0 },
    "title": { "type": "string" },
    "section": { "type": ["string", "null"] },
    "source_path": {
      "type": ["string", "null"],
      "description": "Repo path e.g. docs/operations/runbooks/broker-outage.md"
    },
    "doc_type": {
      "type": "string",
      "enum": ["runbook", "detector_note", "security_standard", "playbook", "postmortem"]
    },
    "tags": { "type": "array", "items": { "type": "string" } },
    "mitre_techniques": { "type": "array", "items": { "type": "string" } },
    "modalities": {
      "type": "array",
      "items": { "type": "string" }
    },
    "text": { "type": "string" },
    "updated_at": { "type": ["string", "null"], "format": "date-time" },
    "updated_at_ts": { "type": ["integer", "null"] },
    "embed_model": { "type": "string" },
    "embed_version": { "type": "string" },
    "schema_version": { "type": "string" }
  },
  "additionalProperties": false
}
```

**Payload indexes:** `tenant_id`, `doc_type`, `tags`, `mitre_techniques`, `doc_id`.

**Example point**

```json
{
  "id": "runbook-broker-outage:2",
  "vector": {
    "dense": [0.04, 0.09],
    "sparse": { "indices": [50, 51], "values": [0.7, 0.3] }
  },
  "payload": {
    "tenant_id": "__global__",
    "doc_id": "runbook-broker-outage",
    "chunk_id": "runbook-broker-outage:2",
    "chunk_index": 2,
    "title": "Broker outage",
    "section": "Verification",
    "source_path": "docs/operations/runbooks/broker-outage.md",
    "doc_type": "runbook",
    "tags": ["kafka", "redpanda", "availability"],
    "mitre_techniques": [],
    "modalities": [],
    "text": "Verify Redpanda topic lag and producer errors; confirm clients use localhost:19092 from host…",
    "updated_at": "2026-07-20T00:00:00.000Z",
    "updated_at_ts": 1784505600,
    "embed_model": "cisco-ai/SecureBERT2.0-biencoder",
    "embed_version": "1",
    "schema_version": "1.0"
  }
}
```

---

#### 5.5.7 Shared create / index checklist

When provisioning collections in code or ops scripts:

1. Create collection with named vectors as above.  
2. Create payload indexes listed per collection **before** bulk load when possible.  
3. Upsert with `wait=true` in small batches during backfill.  
4. Reject upserts missing `tenant_id` (or explicit `__global__`) at the application layer.  
5. Store these JSON Schemas under something like `contracts/qdrant/*.payload.json` when implementation starts (keep in sync with this doc).  
6. Example vectors in this section are truncated (`[0.01, 0.02, …]`) — real upserts must send full `size`-length dense arrays.

---

## 6. Embedding strategy

### 6.1 Primary text model: SecureBERT 2.0 bi-encoder

| | |
| --- | --- |
| **Model** | [`cisco-ai/SecureBERT2.0-biencoder`](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder) |
| **Type** | Cybersecurity-domain sentence / document bi-encoder (Sentence Transformers) |
| **Output dim** | **768** |
| **Max sequence** | 1024 tokens |
| **License** | Apache-2.0 |
| **Base** | Fine-tuned from `cisco-ai/SecureBERT2.0-base` (ModernBERT); see [arXiv:2510.00240](https://arxiv.org/abs/2510.00240) |
| **Payload value** | `embed_model: "cisco-ai/SecureBERT2.0-biencoder"`, `embed_version: "1"` |

**Use for:** `findings_v1`, `incidents_v1`, `ti_text_v1`, `attack_tech_v1`, `runbooks_v1`, and any text-shaped `code` diff summaries stored as dense text vectors.

**Why this model:** Built for semantic search, IR, and RAG over threat intel, advisories, vulnerability notes, and SOC corpora—closer to AutoAnalyzer content than general embedders (e.g. `bge-small`). Bi-encoder encoding supports scalable ANN in Qdrant.

**Local / air-gap:** Load weights with `sentence-transformers` inside Compose (no Hugging Face Inference API required at runtime once cached). Example:

```python
from sentence_transformers import SentenceTransformer

model = SentenceTransformer("cisco-ai/SecureBERT2.0-biencoder")
embeddings = model.encode(texts, normalize_embeddings=True)  # Cosine-ready, shape (n, 768)
```

**Out of scope for this model (per model card):** Non-technical general-domain similarity; generative chat. Do not use it to embed raw numeric flow/metrics tensors.

| Content | Model direction | Notes |
| --- | --- | --- |
| Finding / incident / TI / ATT&CK / runbook text | **SecureBERT 2.0 bi-encoder (768-d)** | Default for all text collections |
| Numeric feature windows | L2-normalized raw feature vector **or** modality model encoder output | `features_baseline_v1` named vectors (`log`, `network`, `metrics`, `host_state`) |
| Code diffs (text) | SecureBERT 2.0 (same 768-d space) unless a code-specialist embedder is adopted later | Keep one text space for cross-collection linking |
| Sparse lexical | BM25/SPLADE-style sparse vectors in Qdrant | Critical for CVE IDs, hashes, exact tokens in hybrid search |
| Optional lightweight fallback | Small general embedder (e.g. bge-small 384-d) | Only if SecureBERT cannot run on constrained nodes; requires separate collection version |

**Rules:**

- Version embeddings: payload `embed_model` + `embed_version`; never mix 768-d SecureBERT points with 384-d general embedder points in the same collection.  
- On model upgrade → new collection `findings_v2` + dual-write / backfill.  
- Do not send secrets, raw PHI, or cardholder data into external embedding APIs; prefer local SecureBERT inference in Compose.  
- Always L2-normalize SecureBERT outputs before upsert when using Cosine distance.

---

## 7. Query patterns (implementation sketches)

### 7.1 Similar findings (linking / analysis)

```text
filter: must [ tenant_id=T, occurred_at >= now-7d ]
query: dense vector of current finding
limit: 10
with_payload: true
```

Attach results as incident evidence: `related_finding_ids`, `similarity_scores`.

### 7.2 Hybrid TI / hunt

```text
prefetch:
  - sparse query (tokens from alert)
  - dense query (alert embedding)
query: rrf fusion
filter: must [ tlp in {...}, valid_until > now ]
```

([RRF hybrid pattern](https://qdrant.tech/documentation/search/hybrid-queries/))

### 7.3 Novelty / anomaly vs baseline

```text
filter: must [ tenant_id=T, asset_id=A, modality=network, is_baseline=true ]
search current window vector → max similarity S
novelty = 1 - S
if novelty > threshold → contributor on finding
```

### 7.4 ATT&CK suggestion

Embed finding summary → search `attack_tech_v1` → propose `mitre_techniques` with confidence from distance (never auto-overwrite high-confidence rule tags).

---

## 8. API additions (proposed)

### 8.1 Shared internal client

Small library under `packages/` (e.g., extend `black-onyx-otel` sibling later) **or** thin helpers inside each service—avoid a new top-level `app` collision. Prefer `packages/black_onyx_vector/` only if/when explicitly added to the uv workspace.

### 8.2 HTTP surfaces

| Service | Endpoint | Purpose |
| --- | --- | --- |
| `incident-api` | `GET /api/v1/findings/{id}/similar` | Analyst UI |
| `incident-api` | `GET /api/v1/incidents/{id}/similar` | Merge/relate UX |
| `incident-api` | `POST /api/v1/hunt/vector` | Hunt-by-example text/ID |
| `threat-intel-service` | `POST /api/v1/match/semantic` | Semantic TI |
| `correlation-engine` | (internal client only) | Neighbor boost during bucket score |

Preserve `X-Tenant-Id` on all routes.

---

## 9. Infrastructure

### 9.1 Docker Compose (optional profile)

```yaml
# conceptual — add under infrastructure/docker-compose when approved
qdrant:
  image: qdrant/qdrant:latest
  ports:
    - "6333:6333"
    - "6334:6334"
  volumes:
    - qdrant_data:/qdrant/storage
```

- Dev: single node.  
- Prod Helm: StatefulSet + persistent volume; consider Qdrant Cloud only if policy allows.  
- Backups: Qdrant snapshots to MinIO (already in stack).  
- Air-gap: load snapshot images; no outbound embed APIs.

### 9.2 Security

- Network-isolate Qdrant; only platform services reach it.  
- API key if exposed beyond the mesh.  
- Payload minimization (hashes already preferred in contracts).  
- Tenant filter enforced in **application code**, not only convention.

### 9.3 Observability

- Metrics: upsert latency, search latency, collection size, error rate.  
- Trace spans: `vector.embed`, `vector.upsert`, `vector.search` (align with planned OTEL business spans).

---

## 10. Phased delivery

### Phase 0 — Spike (lab only)

- Run Qdrant in Compose profile `vector`.  
- Load [`cisco-ai/SecureBERT2.0-biencoder`](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder) locally; create `findings_v1` with dense size **768**.  
- Manually embed 1k synthetic findings; validate tenant filter + similar search.  
- No production traffic.

### Phase 1 — Similar findings / incidents (analyze + link)

- `embedding-worker` upserts on `findings.*` (async, best-effort).  
- `incident-api` similar endpoints + frontend panel.  
- Correlation optionally attaches neighbor IDs (no score change yet).

### Phase 2 — Semantic threat intel + ATT&CK

- Index TI descriptions + MITRE text.  
- `/match/semantic` with confidence caps.  
- Enrich findings with suggested techniques when rule tags absent.

### Phase 3 — Novelty signals into detection

- Baseline collections per modality.  
- `vector_novelty` contributor → correlation scoring behind feature flag.  
- Evaluate FP/TP on golden + synthetic suites.

### Phase 4 — RAG for defenders

- `runbooks_v1` + incident write-ups.  
- Investigation assistant context (human-gated; no auto-remediation).  
- Hybrid search for hunt UI.

---

## 11. What Qdrant should not do

| Anti-pattern | Prefer instead |
| --- | --- |
| Replace Kafka / feature pipelines | Keep modality processors authoritative |
| Replace exact IOC matching | Postgres `threat-intel-service` |
| Become the system of record for incidents | Postgres `incident-api` |
| Full-text SIEM replacement | OpenSearch hunt indices |
| Unfiltered cross-tenant search | Always filter `tenant_id` |
| Sole trigger for SOAR blocks | Multi-signal + human approval ([planned_upgrades](planned_upgrades.md)) |
| Embed regulated raw payloads off-box | Local models / redact / hash |

---

## 12. Testing strategy

| Layer | Tests |
| --- | --- |
| Unit | Embedding determinism fixtures; filter builder always includes tenant |
| Contract | Payload schema for vector contributor type if added to findings |
| Service | TI semantic match with fake Qdrant (testcontainer or mock client) |
| Integration | Soft-skip if Qdrant down (mirror broker skip pattern) |
| Eval | Precision@k for “similar incident” against labeled set; novelty FP rate |

Respect monorepo rule: per-package pytest only; do not invent multi-service collection.

---

## 13. Success criteria

1. Analyst can open a finding and see **top-k similar** historical findings within the same tenant in &lt;500ms p95 (lab scale).  
2. Semantic TI returns useful neighbors for **text-rich** intel without breaking exact-match latency/SLO.  
3. Vector novelty behind a flag improves or holds precision on a held-out anomaly set vs models alone.  
4. Disabling Qdrant (`VECTOR_SEARCH_ENABLED=false`) leaves the existing golden path green.  
5. Air-gapped snapshot restore brings ATT&CK + TI text collections online without internet.

---

## 14. Primary sources

- [cisco-ai/SecureBERT2.0-biencoder](https://huggingface.co/cisco-ai/SecureBERT2.0-biencoder) — default text embedding model (768-d)  
- [SecureBERT 2.0 paper (arXiv:2510.00240)](https://arxiv.org/abs/2510.00240)  
- [Qdrant — Data Analysis & Anomaly Detection](https://qdrant.tech/data-analysis-anomaly-detection/)  
- [Qdrant — Use Cases](https://qdrant.tech/use-cases/)  
- [Qdrant — Hybrid Queries (RRF / prefetch)](https://qdrant.tech/documentation/search/hybrid-queries/)  
- [Qdrant — Filtering](https://qdrant.tech/documentation/search/filtering/)  
- [Qdrant — RAG](https://qdrant.tech/rag/)  
- [Auguria — Why Your Next SIEM Will Analyze Vectors](https://auguria.io/insights/why-your-next-siem-will-analyze-vectors/)  
- [Anomaly Detection with Isolation Forest and Qdrant](https://vectorsearch.tech/anomaly-detection-with-isolation-forest-and-qdrant/)  
- Platform internals: `services/correlation-engine`, `services/threat-intel-service`, `planned_upgrades.md`

---

*Design research only. Adding Qdrant as a workspace dependency, Compose service, or new uv package should wait for an explicit implementation request and follow existing infra/Helm patterns.*
