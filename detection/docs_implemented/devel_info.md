# Development Findings: Anomaly Detection Platform

> **Status:** Design history. Substantial content is now **implemented** in the monorepo. Prefer `README.md`, `ANOMALY_DETECTION_PLATFORM.md`, and `docs/operations/` for current behavior. See [`docs_implemented/README.md`](README.md).


| Field | Value |
| --- | --- |
| Prepared | 2026-07-26 |
| Sources | `ANOMALY_DETECTION_PLATFORM.md`, `ProjectResearch.md`, public papers/docs |
| Purpose | Implementation guidance so engineering can build correctly against the platform spec |

---

## 1. Current project state

The workspace currently contains **only design documents**, not application code:

| File | Role |
| --- | --- |
| `ANOMALY_DETECTION_PLATFORM.md` | Full implementation baseline (schemas, four models, APIs, MLOps, delivery plan) |
| `ProjectResearch.md` | Earlier research memo recommending a hybrid specialist ensemble |

There is no repository layout, services, models, contracts, or infra yet. Treat the platform doc as the product/engineering contract and this file as research-backed notes for implementing it correctly.

**Key evolution from research → platform:**

| Topic | `ProjectResearch.md` | `ANOMALY_DETECTION_PLATFORM.md` |
| --- | --- | --- |
| Model count | 3 encoders (+ fusion); network and metrics often shared | **4 independent models** (logs, code, network, metrics) |
| Fusion | Lightweight ML fusion | Deterministic + logistic/GBT **Correlation Engine** (not a 5th neural model) |
| Delivery | Informal MVP phases | 16-week MVP, 24-week hardening, concrete acceptance criteria |
| Stack | Sketch | Full stack: Kafka/Redpanda, Postgres, OpenSearch, ONNX, MLflow, K8s |

Implement the **four-model** architecture from the platform spec. Keep the research memo as background rationale, not as the build plan.

---

## 2. Architecture decisions that must not be weakened

1. **One model per modality.** Logs, code, flows, and metrics need different tokenization, windows, drift handling, and evaluation. Share serving/orchestration; do not share one vocabulary.
2. **Async, fail-open.** Collection and inference stay off the production request path. Platform failure must not break monitored apps.
3. **Normal-first training.** Train primarily on normal data; sparse labels for calibration and hybrid heads only.
4. **No automatic online weight updates.** Feedback enters an approved retraining workflow.
5. **Explainability mandatory.** Every alert needs contributors/evidence refs, not a bare score.
6. **Advisory code risk by default.** Model-only scores must not block merges unless an explicit policy combines them with deterministic scanners.
7. **Immutable raw events.** Corrections create new normalized records; never rewrite source telemetry in place.

---

## 3. Model A — Log anomaly detection

### 3.1 What the literature actually does

**LogBERT** ([arXiv:2103.04475](https://arxiv.org/abs/2103.04475); code: [HelenGuohx/logbert](https://github.com/HelenGuohx/logbert)):

- Parse logs → **log keys** (templates) → sequences of keys.
- Transformer encoder with two self-supervised tasks:
  - **Masked Log Key Prediction (MLKP):** mask keys, predict from bidirectional context.
  - **Volume of Hypersphere Minimization (VHM):** pull sequence embeddings (via a special prefix token they call `DIST`) toward a center of normal sequences — same idea as **Deep SVDD** ([Ruff et al., ICML 2018](https://ml.cs.rptu.de/publications/2018/deep-svdd.pdf)).
- Detection: mask keys at inference; if the true key is outside the top-`g` predictions often enough (`r` anomalous positions), flag the sequence.
- Paper config (reference, not a hard limit): **2 layers**, input dim 50, hidden 256; train on ~5k normal sequences on HDFS/BGL/Thunderbird.

**LAnoBERT** ([arXiv:2111.09564](https://arxiv.org/abs/2111.09564); HF: [yukyung/LAnoBERT](https://huggingface.co/yukyung/LAnoBERT)):

- Emphasizes **parser-free** regex-light preprocessing and MLM loss per log key at test time.
- Checkpoints exist for BGL/HDFS/Thunderbird with small custom vocabs (200–10k).
- Useful as a comparison baseline; the platform still prefers **Drain3 templates** for stable IDs, privacy masking, and explainability.

### 3.2 How to implement Model A correctly for this platform

| Spec item | Correct implementation approach |
| --- | --- |
| Parser | Use **Drain3** (`logpai/Drain3`, PyPI `drain3`) for streaming template mining |
| Masking | Configure Drain3 `[MASKING]` regexes for IP, UUID, paths, emails, tokens **before** clustering; also apply platform-level typed parameter categories |
| Train vs infer | Training/online learning of templates: `add_log_message()`. Stable production matching: persist clusters and prefer `match()` so templates do not silently mutate under load |
| Sequence keys | Service+host, service+process, trace, session, workload, auth principal hash, custom |
| Windows | Max length 128, max duration 15m, min length 4, stride 32, inactivity close |
| Architecture | Compact encoder: hidden 256, 4 layers, 4 heads, FFN 512, max pos 128, ~5–15M params (spec). LogBERT paper used fewer layers; start small and scale if validation needs it |
| Objectives | Start with **masked event modeling + corruption discrimination**; add VHM/Deep-SVDD-style compactness only if validation improves |
| Scoring | Configurable weighted mix (masked loss, corruption prob, template novelty, embedding distance, parameter anomaly) — weights in config, not constants |
| Unknown templates | Map to `[UNK]` **plus** an explicit novelty feature; never treat unseen templates as ordinary |
| Evidence | Top unexpected positions, expected template candidates, novel templates, sequence time range, model/vocab versions |

### 3.3 Drain3 operational notes

- Defaults that matter: `sim_th=0.4`, `depth=4`, `max_children=100`, optional `max_clusters` (LRU eviction when set).
- **Strip structured fields first** (timestamp, host, severity, process) — Drain3 docs and LogPAI guidance stress mining the message body, not the whole syslog line.
- Persist Drain3 state (Kafka/Redis/file snapshot) so replicas share a vocabulary version; version the template map with the model (`feature_version`).
- The HelenGuohx LogBERT repo uses an older Drain copy; **do not fork that parser**. Use current Drain3 and feed template IDs into your own training code.

### 3.4 Evaluation datasets

Use **LogHub** ([github.com/logpai/loghub](https://github.com/logpai/loghub), Zenodo record 8196385) for implementation verification:

| Dataset | Labeled | Notes |
| --- | --- | --- |
| HDFS_v1 | Yes | Block-ID sequences; standard LogBERT/DeepLog benchmark |
| BGL | Yes | Alert tags in first column |
| Thunderbird | Yes | Large; useful stress test |

Cite LogHub / original dataset papers when publishing results. **Public F1 is not production acceptance** — final thresholds come from pilot tenants and seeded incidents.

---

## 4. Model B — Source-code anomaly / risk

### 4.1 Pretrained bases

| Model | Ref | Use for this platform |
| --- | --- | --- |
| **CodeBERT** | [arXiv:2002.08155](https://arxiv.org/abs/2002.08155); `microsoft/codebert-base` | Primary starting encoder (RoBERTa-base init, NL+PL, 6 languages from CodeSearchNet) |
| **GraphCodeBERT** | [arXiv:2009.08366](https://arxiv.org/abs/2009.08366); `microsoft/graphcodebert-base` | Optional later upgrade when you can extract **data-flow** edges; improves structure awareness beyond tokens |
| **CodeBERTa** | Hugging Face small CodeBERT-family | Candidate student for distillation toward the 20–50M param target |

CodeBERT languages in pretraining: Python, Java, JavaScript, PHP, Ruby, Go. The platform also requires **TypeScript and C#** in production — plan fine-tuning / tokenizer coverage and Tree-sitter grammars for those explicitly; do not assume CodeBERT “just works” for C#.

### 4.2 Correct pipeline

1. Verify Git webhook signatures; resolve tenant/repo; use **short-lived, read-scoped** credentials.
2. Fetch only needed commits; skip binaries/generated paths.
3. Parse with **Tree-sitter** (or language-native AST) to extract **changed functions/methods**, not whole-repo classification.
4. Run **Semgrep, CodeQL, secret scanner, dependency scanner** as structured features.
5. Build hybrid feature vector: neural score + scanner counts + path sensitivity + change size + author familiarity.
6. Final layer: **logistic regression or GBT** before any deeper fusion.
7. Delete temporary clones; audit every fetch.

### 4.3 Input representation (align with spec)

```text
[CLS] [LANG=...] [PATH_CATEGORY=...] [CHANGE_TYPE=...]
[BEFORE] ... [SEP] [AFTER] ... [SEP]
[SCANNER] semgrep:... [SEP]
```

- Max **512** subword tokens per segment; function-level chunks; overlap large diffs; never drop all new lines to keep old context.
- Aggregate chunk scores with max / weighted max + change-size context.

### 4.4 Policy

- PR annotation and check-run: allowed.
- Merge blocking: **off by default**; require explicit policy and preferably deterministic scanner + high-confidence combined rule.
- Never send source to external model APIs.

---

## 5. Model C — Network-flow anomaly

### 5.1 Research anchors

**FlowTransformer** ([arXiv:2304.14746](https://arxiv.org/abs/2304.14746); code: [liamdm/FlowTransformer](https://github.com/liamdm/FlowTransformer)):

- Modular pipeline: preprocessing → input encoding → sequential model → classification head.
- Evaluated GPT/BERT-style blocks on flow NIDS datasets.
- Important finding: **classification head choice dominates accuracy**; Global Average Pooling (common in NLP) performs poorly for NIDS; their recommendation leans toward **LastToken**-style heads.
- Treat as a **framework reference**, not a drop-in product. Our platform needs **self-supervised / normal-only** objectives plus deterministic companion detectors, not only supervised attack labels.

**Network Transformer (NeT)** ([arXiv:2202.12997](https://arxiv.org/abs/2202.12997)):

- Incorporates **communication graph** structure for interpretability (global / node / edge features).
- Supports the platform’s topology-violation and peer-novelty evidence story.
- Use as design inspiration for topology features and hierarchical explainability, not as the sole architecture.

### 5.2 Zeek mapping (canonical `network.flow`)

Prefer Zeek metadata over payloads. Primary logs:

| Zeek log | Role |
| --- | --- |
| `conn.log` | Core flow: `uid`, endpoints, `proto`, `service`, duration, bytes/pkts, `conn_state`, history |
| `dns.log` | Query categories, volume, suspicious domains (join on `uid`) |
| `ssl.log` / TLS | Version, cipher, SNI categories |
| `http.log` | Metadata only for MVP |

Critical Zeek fields for the platform schema:

- `uid` → `flow_id` (correlate conn ↔ DNS/TLS/HTTP).
- `id.orig_h` / `id.resp_h` → hash or asset resolve; store zone/role/ASN/country categories, not raw IPs in model inputs.
- `id.orig_p` / `id.resp_p`, `proto`, `service`.
- `duration`, `orig_bytes` / `resp_bytes`, `orig_pkts` / `resp_pkts`.
- `conn_state` (e.g. `SF`, `REJ`, `S0`) → connection_state embedding + failed-connection flag.
- Optional: `community_id` for cross-sensor joins.

Also accept NetFlow/IPFIX/cloud VPC flow logs by normalizing into the same schema.

### 5.3 Implementation defaults from the platform

```yaml
window_duration: 5m
max_events: 256
stride_events: 64
minimum_events: 4
late_event_tolerance: 2m
architecture: { hidden: 128, layers: 3, heads: 4, ffn: 384 }  # ~2–8M params
```

Event embedding = sum/concat of categorical embeddings + log-scaled numerical projection + novelty flags.

**Always keep non-neural detectors** (new peer, scan, beaconing, denylist, topology violation, deprecated TLS). Do not force the Transformer to rediscover simple rules.

### 5.4 Datasets

**CICIDS2017** (UNB CIC): benign + labeled attacks; CICFlowMeter CSVs (~80 flow features) and PCAPs. Research use with citation (Sharafaldin et al.); check [unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html) for current terms. Good for scan/DoS-style seeding; **not** a substitute for site-specific baselines.

---

## 6. Model D — Server / service metrics

### 6.1 Correct modeling approach

- Metrics are **multivariate numerical windows**, not text. Do not BERT-tokenize floats.
- Compact Transformer over vectors: hidden ~96, 3 layers, 4 heads, window length 60 @ 60s (~60 minutes), ~0.5–3M params.
- Heads: reconstruction, short-horizon forecast (1–5 steps), corruption/window classification, metric contribution.
- Always attach **missingness indicators**; reject windows above `max_missing_fraction` (default 0.10).
- Use **named metric profiles** so feature dimensions stay stable per entity type.

### 6.2 Baselines the Transformer must beat

Ship and compare against: static thresholds, rolling z-score, robust MAD, seasonal residual, Isolation Forest, simple autoencoder. Promote the Transformer only if incident-level F1 or lead time is materially better.

OpenTelemetry metrics + Prometheus scrapes are the preferred collection path; map into the `metric.sample` envelope with stable `metric_name`, unit, temporality, and dimensions.

---

## 7. Correlation engine

Not a large neural model. Implement as:

1. Group findings by correlation keys (tenant, asset, service, trace, deployment, commit, peer pair, workload, time window, shared category).
2. Build a transparent feature vector (max scores per modality, model_count, criticality, deployment age, novelty flags, maintenance).
3. Score with **calibrated logistic regression or GBT**.
4. Overlay deterministic severity rules from Appendix A.6.
5. Deduplicate via fingerprint (tenant + service/asset + category + dominant contributor + destination category + deployment + time bucket).

Incident lifecycle and dispositions must be audited. Feedback calibrates thresholds later; it must **not** immediately retrain production weights.

---

## 8. Data plane and schemas

### 8.1 Event IDs

Envelope examples use Crockford Base32 IDs like `01J3T5C0RB6GCYKAT1BFRX7A3Q` — treat as **ULIDs** (time-sortable, unique). Generate ULIDs (or UUIDv7) at ingestion if collectors omit them; never trust client-only uniqueness without tenant scoping.

### 8.2 Common envelope (non-negotiable fields)

`schema_version`, `event_id`, `event_type`, `tenant_id`, `occurred_at`, `ingested_at`, `source`, `asset`, optional `trace`, `labels`. Reject unsupported major versions; preserve vendor extensions separately.

### 8.3 Topics (minimum)

```text
logs.raw / code.raw / network.raw / metrics.raw / deployment.events
logs.features / code.features / network.features / metrics.features
findings.logs / findings.code / findings.network / findings.metrics
*.dlq
```

Delivery: **at-least-once**; consumers idempotent on `tenant_id:event_id:processor_version`.

### 8.4 OpenTelemetry

- Use Collector pipelines for logs, metrics, traces (OTLP gRPC/HTTP; default HTTP port 4318).
- Enforce consistent **resource attributes** (`service.name`, `deployment.environment`, host/k8s attrs) across signals — correlation depends on this.
- Hash/delete sensitive attributes in Collector processors before long-term storage when policy requires.
- Trace IDs in the envelope are optional but valuable sequence keys for Model A.

---

## 9. Serving, MLOps, and quantization

### 9.1 Inference

- Export to **ONNX**; serve with **ONNX Runtime** on CPU.
- Shared `AnomalyModel` protocol: `validate_input` / `predict` / `health`; HTTP `POST /v1/predict` with feature and model versioning.
- One immutable deployment per model version; Model Gateway routes by tenant, stage, canary policy.
- Batch with capped wait time to honor detection latency SLOs.

### 9.2 Quantization

- Prefer Hugging Face **Optimum ONNX Runtime** (`ORTQuantizer`, `AutoQuantizationConfig`) or ONNX Runtime quantization APIs.
- Dynamic INT8 is the usual first step for Transformers on CPU; static INT8 needs calibration data and accuracy gates.
- Record quantized vs FP32 score deviation in evaluation; block promotion if outside tolerance.

### 9.3 MLflow registry — important current API reality

The platform lists stages: Development → Candidate → Shadow → Canary → Production → Archived.

**MLflow deprecated classic stages** (`Staging` / `Production` / `Archived`) as of **2.9.0** in favor of:

- **Aliases** (e.g. `@champion`, `@challenger`, `@shadow`, `@canary`)
- Environment-specific registered models + `copy_model_version()`

**Implementation recommendation:** keep the platform’s *logical* stages, but map them to MLflow **aliases + tags** (and/or separate registered model names per environment). Do not build new code on `transition_model_version_stage()`.

Artifact package contents from the spec (`model.onnx`, model card, config, feature schema, calibration, thresholds, metrics, dataset manifest, signature, checksums) remain correct.

### 9.4 Security for artifacts

- Prefer ONNX / safetensors; **never load arbitrary pickle** in production.
- Sign and verify artifacts; restrict registry writes; sandbox training jobs.

---

## 10. Stack choices (first production baseline)

| Layer | Spec recommendation | Implementation note |
| --- | --- | --- |
| Languages | Python 3.12 (ML/data); Go or Python for high-throughput ingest | FastAPI + Pydantic for APIs; Ruff + mypy/Pyright |
| Broker | Kafka or Redpanda | Redpanda simplifies local Compose |
| DB / search | PostgreSQL + OpenSearch | Alembic migrations; evidence/search in OpenSearch |
| Metrics store | Prometheus-compatible or TimescaleDB | Keep profiled windows also in feature store/object store as needed |
| Object store | S3 / MinIO | Models + datasets |
| Cache | Redis | Short-lived state, Drain3 optional persistence, rate limits |
| Orchestration | Temporal, Argo, or K8s Jobs | Training + code scan jobs |
| Auth | OIDC users; OAuth client credentials / signed keys for collectors | Tenant from identity, not client headers alone |
| Frontend | React + TypeScript | Playwright e2e |
| IaC | Terraform + Helm | Namespace split per §17.2 |

---

## 11. Delivery order (aligned with §19)

| Phase | Weeks | Build first | Exit signal |
| --- | --- | --- | --- |
| 0 Foundation | 1–2 | Monorepo, Compose, envelope, broker, Postgres, auth skeleton, asset registry, OTel metrics | Test event gateway → consumer; tenant isolation tests |
| 1 Logs + incidents | 3–6 | Drain3, sequences, log Transformer, findings, correlation skeleton, incident API/UI, dispositions | Seeded log anomalies → explainable incidents &lt; 5 min |
| 2 Network + metrics | 7–10 | Zeek/flow + metrics profiles/windows + two Transformers + unified timeline | Multi-model incidents; scan/beacon/spike/drift suite |
| 3 Code + deploy | 11–13 | Git webhooks, Tree-sitter diffs, Semgrep, distilled CodeBERT, deploy correlation | Risky commit ↔ runtime findings linked; clones deleted |
| 4 MLOps + pilot | 14–16 | Training orchestrator, MLflow aliases, ONNX/INT8, shadow/canary, drift, rollback | All four models promote/rollback; MVP metrics or documented exceptions |
| Harden | 17–24 | HA, notifications, retention automation, DR, pen-test fixes | Production readiness review |

**Build logs first** — strongest BERT fit, mature parsers/datasets, clearest explainability path.

---

## 12. Testing and acceptance (what “correct” means)

### 12.1 Synthetic anomaly suites (must exist in CI)

Cover the suites in platform §16.4 for logs, code, network, and metrics (insert/delete/reorder, shell+injection patterns, scan/beacon, spike/drift/broken correlation, etc.).

### 12.2 Metric philosophy

Report **incident-level** precision/recall/F1, false alerts per entity per day, detection delay, evidence completeness, calibration error, and inference cost — not only event-level F1.

### 12.3 End-to-end golden scenario (§20.1)

Code auth change → moderate code risk → deployment link → log privilege anomaly → metrics error/pool anomaly → network new external peer → **one** high/critical correlated incident with unified timeline → analyst disposition stored without immediate retrain.

---

## 13. Gaps and risks to plan for

| Risk | Mitigation |
| --- | --- |
| Template churn / Drain3 vocabulary explosion | `max_clusters`, masking quality, per-service template namespaces, monitor unknown-template rate |
| CodeBERT language coverage vs C#/TS | Explicit Tree-sitter + fine-tune/eval per language; hybrid scanners carry early precision |
| FlowTransformer is supervised-NIDS oriented | Reuse encoding ideas; train with platform’s masked/corruption/contrastive objectives on **normal** site data |
| Metric profile drift (new metrics appear) | Version profiles; reject unknown metric sets or pad with missingness — do not silently reshape ONNX inputs |
| MLflow stage API deprecation | Aliases from day one |
| Privacy (IPs, code, PII in logs) | Hash/mask before model vocab and long-term store; RBAC for raw evidence |
| Alert fatigue | Correlation + maintenance suppression + per-service thresholds tied to analyst capacity |
| Poisoned baselines | Exclude confirmed incidents; review large new baseline windows; do not auto-trust FP labels as clean truth |
| Benchmark overfitting | LogHub/CICIDS for unit/integration only; pilot data for promotion |

---

## 14. Recommended reference links

| Topic | URL |
| --- | --- |
| LogBERT paper | https://arxiv.org/abs/2103.04475 |
| LogBERT code | https://github.com/HelenGuohx/logbert |
| LAnoBERT | https://arxiv.org/abs/2111.09564 |
| Drain3 | https://github.com/logpai/Drain3 |
| LogHub | https://github.com/logpai/loghub |
| CodeBERT | https://arxiv.org/abs/2002.08155 / https://huggingface.co/microsoft/codebert-base |
| GraphCodeBERT | https://arxiv.org/abs/2009.08366 |
| FlowTransformer | https://arxiv.org/abs/2304.14746 / https://github.com/liamdm/FlowTransformer |
| Network Transformer (NeT) | https://arxiv.org/abs/2202.12997 |
| Deep SVDD | https://github.com/lukasruff/Deep-SVDD-PyTorch |
| Zeek docs | https://docs.zeek.org/ |
| OpenTelemetry | https://opentelemetry.io/docs/ |
| ONNX Runtime quantization | https://onnxruntime.ai/docs/performance/model-optimizations/quantization.html |
| HF Optimum ORT quantization | https://huggingface.co/docs/optimum-onnx/en/onnxruntime/usage_guides/quantization |
| MLflow Model Registry | https://mlflow.org/docs/latest/ml/model-registry/ |
| CICIDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html |

---

## 15. Concrete first engineering backlog (after Phase 0 skeleton)

1. Define JSON Schema / Pydantic contracts under `contracts/` for envelope + four raw types + findings + incidents.
2. Stand up Compose: Redpanda, Postgres, OpenSearch, MinIO, Redis, MLflow.
3. Implement ingestion gateway with auth, size limits, late/future skew, DLQ.
4. Implement log processor: structured parse → Drain3 → sequence buffers → feature records.
5. Train tiny log Transformer on LogHub HDFS (sanity) then on synthetic normal+corrupt sequences matching platform objectives.
6. Export ONNX; serve `/v1/predict`; emit findings; correlate into incidents; ship minimal incident UI.

Do not start with a universal multimodal BERT, raw PCAP neural models, or automatic merge-blocking from CodeBERT scores.
