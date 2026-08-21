ANOMALY DETECTION PLATFORM  
Development Specification

Four-model monitoring for logs, source code, network traffic, and server metrics — plus security profiles, optional vector search, federated hunt, and response orchestration

| Document version | 1.1 |
| --- | --- |
| Status | Implementation baseline (includes Security Profiles + Qdrant) |
| Audience | Backend, ML, platform, security, and frontend engineers |
| Prepared | July 26, 2026 |
| Updated | July 27, 2026 |
| Target delivery | MVP in 16 weeks; production hardening in 24 weeks |

Purpose: provide enough product, architecture, data, model, API, security, testing, and operational detail for an engineering team to build the application.

Design notes that informed Phase 6 live under `docs_implemented/` (historical; prefer this file and `README.md` for current behavior).

# Contents

1. Executive summary
2. Product scope and success criteria
3. System context and architecture
4. Technology baseline
5. Data ingestion and canonical schemas
6. Model A: log anomaly detection
7. Model B: source-code anomaly and risk detection
8. Model C: network-flow anomaly detection
9. Model D: server-metrics anomaly detection
10. Correlation and incident scoring
11. Application services and APIs
12. User interface
13. Model training and MLOps
14. Security, privacy, and compliance
15. Reliability, scalability, and observability
16. Testing strategy
17. Deployment architecture
18. Repository structure
19. Delivery plan
20. Acceptance criteria
21. Appendix A: Configuration examples
22. Appendix B: Reference event payloads
23. Appendix C: Research references

Sections **10.11–10.12**, **11.10–11.13**, and **12.10–12.11** document Security Profiles and Qdrant vector search shipped after the original MVP baseline.
# 1. Executive summary

Build a security and operations monitoring application that continuously ingests telemetry and code changes, applies four compact specialist models, correlates their findings, and presents explainable incidents to operators.

The system must detect deviations from learned normal behavior without relying exclusively on labeled attack data.

| Model | Primary input | Model family | Primary output |
| --- | --- | --- | --- |
| A. Log anomaly | System and application log templates | Small BERT-style encoder | Sequence anomaly score and unexpected events |
| B. Code anomaly/risk | Git diffs, changed functions, static-analysis findings | Distilled CodeBERT-style encoder | Change risk score and risk categories |
| C. Network anomaly | Zeek, NetFlow, or IPFIX flow sequences | Small BERT-style flow Transformer | Flow-window anomaly score and unusual peers or services |
| D. Metrics anomaly | Multivariate server and service time series | Compact anomaly Transformer | Point or window anomaly score and contributing metrics |

A fifth component, the Correlation Engine, is deliberately not another large neural model. It combines model scores, deployment context, asset criticality, topology, and deterministic rules into an incident-level risk score.

This preserves explainability and permits independent model upgrades.

> **Key design decision:** Use one model per modality. Logs, source code, flow records, and numerical time series have different tokenization, sequencing, drift, and evaluation requirements. Sharing the serving platform is useful. Sharing one universal vocabulary is not.

# 2. Product scope and success criteria

## 2.1 Goals

- Detect anomalous behavior in logs, code changes, network traffic, and infrastructure or service metrics.
- Operate with primarily normal training data and sparse analyst labels.
- Provide evidence for every alert, including contributing events, metrics, flows, code lines, and contextual changes.
- Run inference on commodity CPU infrastructure using compact models and ONNX Runtime.
- Support both single-server installations and horizontally scalable clustered deployments.
- Provide feedback workflows for false-positive suppression, threshold calibration, and controlled retraining.
- Keep collection and model execution isolated from production request paths.

## 2.2 Non-goals for MVP

- Automatic remediation or blocking of network traffic.
- Full packet-payload inspection by a neural model.
- Replacement of SIEM, EDR, static analysis, dependency scanning, or secret scanning.
- Perfect attribution of attacks or root cause from anomaly scores alone.
- Unsupervised online model-weight updates in production.
- Autonomous code rejection based solely on the CodeBERT risk score.

## 2.3 Success metrics

| Metric | MVP target | Production target |
| --- | --- | --- |
| Actionable alert precision | At least 50% in pilot | At least 70% after calibration |
| Known-incident recall | At least 80% | At least 90% |
| Median detection latency | Under 5 minutes | Under 2 minutes |
| Inference service availability | 99.5% | 99.9% |
| P95 API latency excluding searches | Under 500 ms | Under 250 ms |
| False alerts per monitored service per day | No more than 3 | No more than 1 |
| Evidence completeness | At least 90% of alerts have top contributors | At least 98% |
| Model rollback time | Under 30 minutes | Under 10 minutes |
| Data loss during collector interruption | Under 15 minutes | Under 5 minutes |

## 2.4 Primary users

### Security analyst

Needs to:

- Review high-risk incidents.
- Understand which model or models contributed.
- Inspect logs, flows, metrics, and code changes in one timeline.
- Record true-positive, false-positive, expected-change, maintenance, or unknown feedback.
- Search for related activity across assets.

### Site reliability engineer

Needs to:

- Identify emerging service degradation.
- Correlate metric anomalies with deployments and log events.
- Distinguish operational anomalies from likely security events.
- Suppress expected maintenance behavior.

### Machine-learning engineer

Needs to:

- Train and evaluate each model independently.
- Compare model versions.
- Publish models to a registry.
- Monitor drift, calibration, inference latency, and data quality.
- Roll back models safely.

### Platform administrator

Needs to:

- Configure collectors and data retention.
- Manage tenants, users, roles, service accounts, and secrets.
- Configure asset criticality and topology.
- Monitor pipeline health and storage usage.

# 3. System context and architecture

## 3.1 Logical architecture

```text
Collectors and sensors
  OpenTelemetry Collector
  Fluent Bit or Vector
  Git provider webhook
  Zeek or flow exporter
  Prometheus-compatible scraper
             |
             v
Ingestion gateway
  Authentication
  Validation
  Rate limiting
  Schema versioning
             |
             v
Message broker
  logs.raw
  code.raw
  network.raw
  metrics.raw
  deployment.events
             |
             v
Normalization and feature services
  Log template parser
  Code diff extractor
  Flow normalizer
  Metrics window builder
             |
             v
Feature topics and feature store
  logs.features
  code.features
  network.features
  metrics.features
             |
             v
Model-serving services
  Log model
  Code model
  Network model
  Metrics model
             |
             v
Finding topics
  findings.logs
  findings.code
  findings.network
  findings.metrics
             |
             v
Correlation engine
  Rules
  Score calibration
  Topology correlation
  Deployment correlation
             |
             v
Incident service and API
             |
             +-------------------+
             |                   |
             v                   v
       Web application      External integrations
                            SIEM, Slack, email,
                            PagerDuty, webhooks
```

## 3.2 Architectural principles

1. **Asynchronous by default.** Telemetry collection and model inference must not sit in a production request path.
2. **At-least-once delivery.** Consumers must be idempotent.
3. **Immutable raw events.** Corrected interpretations create new normalized records rather than rewriting source telemetry.
4. **Independent model deployment.** Updating the metrics model must not require redeploying the log model.
5. **Version every contract.** Events, features, model artifacts, thresholds, and correlation policies must carry versions.
6. **Explainability is mandatory.** A score without supporting evidence is insufficient.
7. **Tenant isolation.** All persisted data and model requests must be scoped by tenant.
8. **Fail open for monitoring.** Failure of the anomaly platform must not interrupt monitored applications.
9. **No automatic online learning.** Production feedback enters an approved retraining workflow.
10. **Minimal sensitive content.** Normalize or hash high-cardinality and sensitive values before storage where practical.

## 3.3 Service boundaries

| Service | Responsibility |
| --- | --- |
| Ingestion Gateway | Receive, authenticate, validate, and enqueue incoming data |
| Asset Registry | Store assets, services, owners, environments, criticality, and topology |
| Log Processor | Parse structured fields, mask variables, derive templates, and create sequences |
| Code Processor | Receive repository events, resolve commits, extract diffs and changed functions, and run scanners |
| Flow Processor | Normalize Zeek, NetFlow, or IPFIX records and construct host or service windows |
| Metrics Processor | Validate samples, resample series, impute limited gaps, and build multivariate windows |
| Feature Store | Persist reusable model inputs and metadata |
| Model Gateway | Route versioned inference requests and enforce deadlines |
| Four Model Services | Execute modality-specific inference |
| Correlation Engine | Combine findings into incidents |
| Incident Service | Persist incidents, state transitions, comments, and feedback |
| Training Orchestrator | Build datasets, run training jobs, evaluate candidates, and publish approved artifacts |
| Model Registry | Store artifacts, metadata, evaluation results, and deployment stages |
| Query API | Serve UI and integration queries |
| Notification Service | Deliver routed alerts and integration webhooks |

# 4. Technology baseline

The implementation may substitute equivalent technologies, but the first production baseline should avoid unnecessary novelty. There is already plenty of novelty in training four models to decide whether computers are behaving strangely.

## 4.1 Recommended stack

| Layer | Recommended technology |
| --- | --- |
| Backend language | Python 3.12 for ML and data services; Go or Python for high-throughput ingestion |
| API framework | FastAPI |
| Frontend | React with TypeScript |
| Message broker | Kafka or Redpanda |
| Operational database | PostgreSQL |
| Search and evidence store | OpenSearch |
| Vector similarity store (optional) | Qdrant (Compose profile `vector`; off by default) |
| Metrics storage | Prometheus-compatible store or TimescaleDB |
| Object storage | S3-compatible storage such as MinIO |
| Cache and short-lived state | Redis |
| Workflow orchestration | Temporal, Argo Workflows, or Kubernetes Jobs |
| Model training | PyTorch and Hugging Face Transformers |
| Inference | ONNX Runtime |
| Text embeddings | SecureBERT 2.0 bi-encoder (768-d); restore fails when the real model is unavailable |
| Experiment tracking | MLflow |
| Model registry | MLflow registry or equivalent |
| Log parser | Drain3 |
| Network sensor | Zeek plus optional NetFlow or IPFIX |
| Static analysis | Semgrep (incl. profile rule packs), CodeQL, dependency scanner, and secret scanner |
| Telemetry | OpenTelemetry |
| Deployment | Docker and Kubernetes |
| Infrastructure as code | Helm; Docker Compose for single-host deployments |
| Authentication | OpenID Connect and OAuth 2.0 |
| Secrets | Vault or cloud secret manager |

## 4.2 Development standards

- Python must use type annotations.
- Enforce formatting and linting with Ruff.
- Use mypy or Pyright for static type checks.
- Use Pydantic models for API and event validation.
- Generate OpenAPI documentation from the API implementation.
- Use Alembic for PostgreSQL schema migrations.
- Use pytest for Python tests.
- Use Playwright for end-to-end web tests.
- Use pre-commit hooks.
- Build containers with pinned dependencies and software bills of materials.
- Sign production images and model artifacts.
- Use semantic versioning for services and models.

# 5. Data ingestion and canonical schemas

## 5.1 Common event envelope

Every raw, normalized, feature, finding, and incident event must include a common envelope.

```json
{
  "schema_version": "1.0",
  "event_id": "01J3T5C0RB6GCYKAT1BFRX7A3Q",
  "event_type": "log.normalized",
  "tenant_id": "tenant-acme",
  "occurred_at": "2026-07-26T20:41:02.123Z",
  "ingested_at": "2026-07-26T20:41:03.004Z",
  "source": {
    "collector_id": "otel-prod-west-01",
    "source_type": "opentelemetry"
  },
  "asset": {
    "asset_id": "host-payments-03",
    "service_id": "payments-api",
    "environment": "production",
    "region": "us-west-2"
  },
  "trace": {
    "trace_id": "optional",
    "span_id": "optional"
  },
  "labels": {
    "team": "payments",
    "cluster": "prod-west"
  }
}
```

### Envelope requirements

- `event_id` must be globally unique and sortable where possible.
- `occurred_at` represents source time.
- `ingested_at` represents platform receipt time.
- Events more than a configured maximum age may be accepted but marked late.
- Unknown fields may be preserved in a vendor-extension object.
- Consumers must reject unsupported major schema versions.
- Minor schema additions should remain backward compatible.

## 5.2 Asset registry

The asset registry provides stable identities and context to all four models.

```json
{
  "asset_id": "host-payments-03",
  "asset_type": "virtual_machine",
  "name": "payments-api-03",
  "service_id": "payments-api",
  "environment": "production",
  "criticality": 0.9,
  "owner_team": "payments",
  "network_zone": "application",
  "expected_peers": [
    "payments-db",
    "identity-api"
  ],
  "tags": {
    "cloud": "aws",
    "account": "production"
  },
  "active": true
}
```

### Supported asset types

- Physical host
- Virtual machine
- Kubernetes cluster
- Kubernetes node
- Kubernetes namespace
- Kubernetes workload
- Container
- Serverless function
- Database
- Message broker
- Network appliance
- Repository
- Service
- External dependency

## 5.3 Log event schema

```json
{
  "event_type": "log.raw",
  "severity": "ERROR",
  "facility": "auth",
  "logger": "session.manager",
  "message": "Failed login for user alice from 10.0.4.21",
  "structured": {
    "user": "alice",
    "source_ip": "10.0.4.21"
  },
  "resource": {
    "process_name": "payments-api",
    "container_id": "abc123"
  }
}
```

After normalization:

```json
{
  "event_type": "log.normalized",
  "template_id": "tpl-auth-failed-login-v2",
  "template": "Failed login for user <*> from <IP>",
  "parameters": [
    {
      "name": "user",
      "type": "identifier",
      "value_hash": "sha256:..."
    },
    {
      "name": "source_ip",
      "type": "ip",
      "category": "internal"
    }
  ],
  "sequence_key": "payments-api:host-payments-03:auth",
  "severity": "ERROR"
}
```

## 5.4 Code-change schema

```json
{
  "event_type": "code.change",
  "repository_id": "repo-payments",
  "provider": "github",
  "repository_url_hash": "sha256:...",
  "default_branch": "main",
  "base_commit": "91bfc7a",
  "head_commit": "25d874c",
  "pull_request_number": 481,
  "author_id_hash": "sha256:...",
  "files": [
    {
      "path": "src/auth/session.py",
      "language": "python",
      "status": "modified",
      "additions": 8,
      "deletions": 3,
      "diff": "@@ ...",
      "changed_functions": [
        {
          "name": "create_session",
          "start_line": 88,
          "end_line": 126,
          "before": "...",
          "after": "..."
        }
      ]
    }
  ],
  "scanner_findings": []
}
```

## 5.5 Network-flow schema

```json
{
  "event_type": "network.flow",
  "sensor_id": "zeek-edge-west",
  "flow_id": "C8Z...",
  "source": {
    "asset_id": "host-payments-03",
    "ip_hash": "sha256:...",
    "zone": "application",
    "port": 52113
  },
  "destination": {
    "asset_id": "payments-db",
    "ip_hash": "sha256:...",
    "zone": "database",
    "port": 5432,
    "country": null,
    "asn": null
  },
  "protocol": "tcp",
  "service": "postgres",
  "duration_ms": 92,
  "bytes_out": 1482,
  "bytes_in": 9374,
  "packets_out": 14,
  "packets_in": 20,
  "connection_state": "SF",
  "tls": null,
  "dns": null
}
```

## 5.6 Metrics sample schema

```json
{
  "event_type": "metric.sample",
  "metric_name": "http.server.duration.p95",
  "value": 0.381,
  "unit": "seconds",
  "temporality": "gauge",
  "dimensions": {
    "method": "POST",
    "route": "/payments"
  },
  "sample_interval_seconds": 60
}
```

## 5.7 Deployment event schema

```json
{
  "event_type": "deployment.completed",
  "deployment_id": "deploy-20260726-441",
  "service_id": "payments-api",
  "environment": "production",
  "version": "payments-api:2.14.0",
  "commit": "25d874c",
  "started_at": "2026-07-26T20:25:00Z",
  "completed_at": "2026-07-26T20:31:42Z",
  "status": "succeeded",
  "changed_assets": [
    "host-payments-01",
    "host-payments-02",
    "host-payments-03"
  ]
}
```

## 5.8 Data validation

The ingestion gateway must:

- Verify authentication before parsing large payloads.
- Enforce tenant-specific quotas.
- Validate event size and schema.
- Reject timestamps beyond configurable future skew.
- Mark excessively old records as late.
- Preserve original payload hashes for auditability.
- Prevent decompression bombs and oversized batches.
- Publish invalid records to a dead-letter topic with sanitized failure details.
- Expose validation counters by tenant and source.

# 6. Model A: log anomaly detection

## 6.1 Objective

Detect unexpected log templates, parameter categories, event ordering, and sequence context for a particular service, host, process, session, or trace.

## 6.2 Inputs

- Normalized log template ID
- Severity
- Logger or subsystem
- Relative time delta
- Asset role
- Service
- Environment
- Parameter categories
- Optional trace or session identifier
- Optional deployment version

Do not place raw secrets, access tokens, full IP addresses, email addresses, or unbounded identifiers into the model vocabulary.

## 6.3 Parsing and normalization

Use Drain3 or an equivalent streaming template miner.

Preprocessing stages:

1. Parse known structured formats such as JSON, logfmt, syslog, and journald.
2. Separate timestamp, host, severity, process, and logger from the message.
3. Mask variable tokens:
   - IPv4 and IPv6 addresses
   - UUIDs
   - Request IDs
   - Session IDs
   - Long integers
   - File paths where appropriate
   - URLs
   - Email addresses
   - Tokens and secrets
4. Resolve or create a template ID.
5. Extract typed parameter categories.
6. Append the normalized event to one or more active sequence buffers.

Example:

```text
Raw:
Failed login for user alice from 10.0.4.21

Template:
Failed login for user <*> from <IP>

Template ID:
tpl-auth-failed-login-v2
```

## 6.4 Sequence construction

Supported sequence keys:

- Service plus host
- Service plus process
- Trace ID
- Session ID
- Kubernetes workload
- Authentication principal hash
- Configured application-specific key

Default behavior:

- Maximum sequence length: 128 events
- Maximum sequence duration: 15 minutes
- Minimum sequence length for model scoring: 4 events
- Sliding stride: 32 events
- Close sequence after inactivity timeout
- Persist truncated context for the next window

## 6.5 Vocabulary

The vocabulary contains:

- Special tokens:
  - `[PAD]`
  - `[CLS]`
  - `[SEP]`
  - `[MASK]`
  - `[UNK]`
- Template IDs
- Severity tokens
- Logger-category tokens
- Time-delta buckets
- Asset-role tokens
- Parameter-category tokens

Unknown templates must map to `[UNK]` plus an explicit novelty feature. They must not silently appear ordinary.

## 6.6 Model architecture

Initial configuration:

```yaml
model_type: log_transformer
hidden_size: 256
num_hidden_layers: 4
num_attention_heads: 4
intermediate_size: 512
max_position_embeddings: 128
dropout: 0.10
vocab_size: dynamic
parameter_count_target: 5_000_000_to_15_000_000
```

Model components:

- Token embedding
- Position embedding
- Time-delta embedding
- Severity embedding
- Asset-context embedding
- Four Transformer encoder blocks
- Masked-event prediction head
- Sequence representation head
- Optional parameter-category reconstruction head

## 6.7 Training objectives

### Masked event modeling

Randomly mask selected template IDs and predict them from surrounding context.

```text
Input:
[SERVICE_START, CONFIG_LOAD, MASK, HEALTH_CHECK]

Target:
LISTENER_READY
```

### Corruption discrimination

Generate synthetic abnormal sequences using:

- Event replacement
- Event insertion
- Event deletion
- Event duplication
- Local reordering
- Event insertion from another service
- Invalid severity transition
- Parameter-category mutation

The model predicts whether the sequence was corrupted and, optionally, which positions were modified.

### Representation compactness

Normal sequences from the same service and operating mode should produce nearby embeddings.

Possible objectives:

- Center loss
- Contrastive learning
- Triplet loss
- Deep support-vector-data-description-style objective

Start with masked modeling and corruption discrimination. Add representation objectives only when validation shows a measurable benefit.

## 6.8 Log anomaly score

```text
log_score =
    0.45 * masked_event_loss
  + 0.20 * corruption_probability
  + 0.15 * template_novelty
  + 0.10 * embedding_distance
  + 0.10 * parameter_anomaly
```

Weights are configuration, not source-code constants.

The model service returns both a raw score and a calibrated probability-like score.

## 6.9 Explainability output

Return:

- Top unexpected event positions
- Expected template candidates for each unexpected position
- Novel templates
- Unusual parameter categories
- Similar known-normal sequences
- Attention-derived evidence only as supplemental information
- Sequence time range
- Model and vocabulary versions

Example:

```json
{
  "model": "log-model",
  "model_version": "1.3.0",
  "raw_score": 4.82,
  "calibrated_score": 0.94,
  "top_contributors": [
    {
      "position": 17,
      "observed_template": "tpl-privilege-change",
      "expected_templates": [
        "tpl-auth-failure",
        "tpl-account-lock"
      ],
      "contribution": 0.41
    }
  ],
  "novel_templates": [],
  "sequence_start": "2026-07-26T20:39:00Z",
  "sequence_end": "2026-07-26T20:41:02Z"
}
```

## 6.10 Training dataset

- Use at least four weeks of representative normal data for the first production model where available.
- Include weekdays, weekends, deployments, backups, maintenance, scaling, and expected errors.
- Exclude confirmed incidents and compromised periods.
- Split chronologically.
- Preserve complete sequences within one split.
- Track dataset hashes and source query definitions.

Recommended split:

```text
Training: weeks 1-4
Validation: week 5
Test: week 6
```

## 6.11 Log-model acceptance criteria

- Can process at least 5,000 sequences per second per standard CPU serving replica in batch mode.
- P95 inference latency under 250 ms for a batch of 64 sequences.
- Returns at least one meaningful contributor for 95% of scores above the alert threshold.
- Detects at least 80% of seeded sequence anomalies in validation.
- Unknown-template rate and template churn are visible in monitoring.
- Model behavior is stable when event identifiers and IP values change but templates remain equivalent.

# 7. Model B: source-code anomaly and risk detection

## 7.1 Objective

Score code changes for contextual unusualness and security or operational risk. The model must examine changes, not repeatedly classify entire repositories.

## 7.2 Triggering events

- Pull request opened or updated
- Commit pushed to a protected branch
- Release tag created
- Deployment commit selected
- Manual repository scan requested

## 7.3 Inputs

- Changed function before and after text
- Unified diff
- Programming language
- File path category
- Repository identifier
- Nearby imports or dependencies
- Static-analysis findings
- Secret-scanner findings
- Dependency changes
- Ownership and historical context
- Whether the file affects authentication, authorization, cryptography, networking, deployment, or infrastructure
- Change size and complexity delta

## 7.4 Repository processing

The code processor must:

1. Validate the webhook signature.
2. Resolve the tenant and repository.
3. Fetch only required commit data using a scoped credential.
4. Identify changed files.
5. Skip unsupported binary and generated files unless explicitly configured.
6. Detect language.
7. Parse files with Tree-sitter or language-native parsers.
8. Extract changed functions, methods, classes, and configuration blocks.
9. Run configured static-analysis tools.
10. Construct one or more model inputs per changed unit.
11. Delete temporary repository data after processing.

## 7.5 Input representation

Recommended format:

```text
[CLS]
[LANG=python]
[PATH_CATEGORY=authentication]
[CHANGE_TYPE=modified]
[BEFORE]
def create_session(...):
    ...
[SEP]
[AFTER]
def create_session(...):
    ...
[SEP]
[SCANNER]
semgrep: python.lang.security.audit.subprocess-shell-true
[SEP]
```

Input-size handling:

- Maximum 512 subword tokens per segment for the first implementation.
- Prefer function-level segmentation.
- For large changes, use overlapping chunks.
- Aggregate chunk scores with maximum, weighted maximum, and change-size context.
- Never truncate all newly added lines merely to preserve unchanged context.

## 7.6 Model architecture

Start with a compact CodeBERT-compatible encoder or distilled student.

Target configuration:

```yaml
model_type: distilled_code_encoder
hidden_size: 384
num_hidden_layers: 6
num_attention_heads: 6
intermediate_size: 1536
max_position_embeddings: 512
dropout: 0.10
parameter_count_target: 20_000_000_to_50_000_000
```

This model may be larger than the runtime telemetry models because it runs in CI or asynchronous commit processing rather than continuously on every server.

## 7.7 Prediction heads

The model should produce:

1. Overall change-risk score
2. Repository-relative anomaly score
3. Multi-label risk categories:
   - Authentication or authorization
   - Command execution
   - Injection
   - Unsafe deserialization
   - Cryptography
   - Secret handling
   - Network egress
   - File-system access
   - Privilege change
   - Dependency or supply-chain risk
   - Infrastructure exposure
   - Logging or audit weakening
   - Resource exhaustion
   - Error-handling regression
4. Optional embedding for nearest-neighbor search

## 7.8 Hybrid features

The final code-risk classifier must combine neural output with structured signals.

Example feature vector:

```json
{
  "code_model_score": 0.76,
  "repository_embedding_distance": 0.43,
  "new_dangerous_api": true,
  "semgrep_high_findings": 1,
  "semgrep_medium_findings": 2,
  "codeql_findings": 0,
  "secret_findings": 0,
  "dependency_change": false,
  "auth_sensitive_path": true,
  "change_size_log": 2.31,
  "author_file_familiarity": 0.18
}
```

Use logistic regression or gradient-boosted trees for the hybrid layer before considering a more complicated model.

## 7.9 Training data

Sources may include:

- Historical repository changes accepted as normal
- Confirmed vulnerability-fixing commits
- Security-review labels
- Reverted changes
- Static-analysis findings
- Synthetic changes that introduce controlled risky patterns
- Public vulnerability datasets where licenses permit
- Repository-specific normal-change history

Avoid labeling every unreviewed historical commit as safe. “It merged” is evidence of human confidence, not proof of security. Humans have merged credentials into public repositories with astonishing consistency.

## 7.10 Negative sampling

Build hard negatives:

- Large but safe refactors
- Generated-code updates
- Dependency lockfile changes
- Test-only modifications
- Security-sensitive code changed safely
- Scanner findings marked false positive
- Unusual but approved infrastructure changes

## 7.11 Explainability

Return:

- Highest-scoring changed lines or chunks
- Triggered risk categories
- Static-analysis findings
- Newly introduced API calls
- Similar historical changes
- Repository-relative novelty
- File and function location
- Model limitations warning

Example:

```json
{
  "model_version": "2.1.0",
  "risk_score": 0.88,
  "risk_categories": [
    {
      "category": "command_execution",
      "score": 0.93
    },
    {
      "category": "authentication",
      "score": 0.71
    }
  ],
  "evidence": [
    {
      "file": "src/auth/session.py",
      "start_line": 104,
      "end_line": 104,
      "summary": "New shell execution uses externally influenced input.",
      "scanner_rule": "subprocess-shell-true"
    }
  ]
}
```

## 7.12 Enforcement policy

For MVP:

- The model may annotate a pull request.
- The model may create a check-run result.
- The model must not block merging by default.
- Blocking requires an explicit repository policy and should depend on deterministic scanner findings or a combined high-confidence rule.
- A model-only score must be labeled advisory.

## 7.13 Code-model acceptance criteria

- Supports at least Python, JavaScript or TypeScript, Java, Go, and C# in the first production release.
- Processes a typical pull request with fewer than 20 changed functions in under 60 seconds, excluding third-party scanner queues.
- Maps every high-risk result to file and line evidence.
- Does not transmit source code to external model APIs.
- Allows repositories to configure excluded paths and generated-code patterns.
- Provides repository-specific calibration.
- Demonstrates improved precision over static analysis alone on the pilot repository set.

# 8. Model C: network-flow anomaly detection

## 8.1 Objective

Detect unusual communication patterns, services, destinations, volumes, timing, and connection sequences for hosts, workloads, users, or service roles.

## 8.2 Inputs

Preferred sources:

- Zeek connection logs
- Zeek DNS logs
- Zeek TLS logs
- Zeek HTTP metadata
- NetFlow
- IPFIX
- Cloud virtual-network flow logs — **implemented** for AWS VPC Flow Logs, Azure
  NSG Flow Logs (v2), and GCP VPC Flow Logs. Collector profiles:
  `detection/collectors/network/{aws_vpc_flow_logs,azure_nsg_flow_logs,gcp_vpc_flow_logs}.toml`.
  Adapters/normalization: `services/flow-processor/flow_processor/{aws,azure,gcp}_flow_adapter.py`.
- Kubernetes network telemetry — **not yet implemented**; no CNI/eBPF flow
  collector exists under `detection/collectors/`. Roadmap item.

Do not require raw packet payloads for the MVP.

## 8.3 Normalization

Convert vendor records into the canonical network-flow schema.

Derived fields:

- Source and destination asset IDs
- Source and destination roles
- Internal or external classification
- Network zones
- Protocol
- Service
- Port category
- Duration bucket
- Bytes and packets buckets
- Connection state
- Hour-of-week bucket
- Peer novelty
- Destination-country category
- Destination-ASN category
- TLS version and cipher category
- Server-name category
- DNS-query category
- Failed-connection indicator
- Direction relative to the asset
- Fan-out and fan-in counts
- Distinct-peer counts

Raw IP addresses should be hashed or converted into asset, zone, subnet, country, or ASN categories according to privacy policy.

## 8.4 Sequence construction

Primary sequence keys:

- Source asset
- Source workload
- Service identity
- User identity hash where legally and operationally appropriate
- Source-destination asset pair

Default window:

```yaml
window_duration: 5m
max_events: 256
stride_events: 64
minimum_events: 4
late_event_tolerance: 2m
```

Also compute aggregate windows for low-volume assets.

## 8.5 Event embedding

Each flow event embedding is the sum or concatenation of:

```text
protocol embedding
service embedding
source-role embedding
destination-role embedding
zone embedding
connection-state embedding
time embedding
direction embedding
numerical-feature projection
novelty flags
```

Numerical features should be log-scaled and normalized using training-set statistics.

## 8.6 Model architecture

```yaml
model_type: flow_transformer
hidden_size: 128
num_hidden_layers: 3
num_attention_heads: 4
intermediate_size: 384
max_position_embeddings: 256
dropout: 0.10
parameter_count_target: 2_000_000_to_8_000_000
```

## 8.7 Training objectives

### Masked categorical prediction

Mask and predict:

- Service
- Destination role
- Protocol
- Connection state
- Direction
- Peer category

### Numerical reconstruction

Mask and reconstruct bucketed:

- Duration
- Bytes
- Packets
- Fan-out
- Distinct peers

### Corruption detection

Generate anomalies by:

- Replacing a destination role
- Introducing a novel external peer
- Changing service or port
- Inflating byte volume
- Reordering events
- Adding repeated failed connections
- Simulating beacon-like periodicity
- Simulating scanning fan-out
- Inserting traffic from another asset role

### Contrastive context

Encourage windows from the same asset and normal operating mode to cluster while separating corrupted windows.

## 8.8 Network anomaly score

```text
network_score =
    0.25 * masked_category_loss
  + 0.20 * numerical_reconstruction_error
  + 0.20 * corruption_probability
  + 0.15 * peer_novelty
  + 0.10 * topology_violation
  + 0.10 * embedding_distance
```

## 8.9 Deterministic companion detectors

The network pipeline should also calculate non-neural indicators:

- New external destination
- New destination country or ASN
- Port scan
- Horizontal scan
- Vertical scan
- Beaconing
- Excessive failed connections
- DNS volume spike
- High-entropy or suspicious domain characteristics
- Unexpected cleartext protocol
- Deprecated TLS
- Known-denylist match
- Impossible topology relationship

These features become correlation evidence and model inputs. Do not make a Transformer rediscover every simple rule from scratch just because attention layers are fashionable.

## 8.10 Explainability

Return:

- Unusual destination or service
- First-seen timestamps
- Baseline frequency
- Volume deviation
- Top contributing events
- Topology violation
- Similar normal windows
- Flow time range
- Whether the score depends on peer novelty

Example:

```json
{
  "model_version": "1.4.0",
  "calibrated_score": 0.91,
  "asset_id": "host-payments-03",
  "window_start": "2026-07-26T20:40:00Z",
  "window_end": "2026-07-26T20:45:00Z",
  "contributors": [
    {
      "type": "new_external_peer",
      "destination_category": "external-asn-64500",
      "service": "https",
      "contribution": 0.36
    },
    {
      "type": "unexpected_service",
      "service": "ssh",
      "destination_role": "external",
      "contribution": 0.24
    }
  ]
}
```

## 8.11 Network-model acceptance criteria

- Sustains the expected peak flow rate with 50% capacity headroom.
- Scores a completed window within 60 seconds.
- Detects at least 90% of seeded scan and beacon scenarios.
- Identifies new peer and unexpected-service evidence without exposing unnecessary raw IP data.
- Supports asset-relative and role-relative baselines.
- Handles low-volume assets without producing empty or unstable scores.
- Produces bounded memory usage when a single host generates extreme flow volume.

# 9. Model D: server-metrics anomaly detection

## 9.1 Objective

Detect anomalous multivariate behavior in server, container, service, and application metrics, including failures that may not violate a single static threshold.

## 9.2 Inputs

Initial metric set:

### Host metrics

- CPU utilization
- Load average
- Memory usage
- Swap usage
- Disk utilization
- Disk read and write throughput
- Disk latency
- Network bytes and packets
- File-descriptor usage
- Process count

### Container and Kubernetes metrics

- CPU usage and throttling
- Working-set memory
- Restart count
- Pending pods
- Scheduling latency
- Replica count
- OOM events

### Service metrics

- Request rate
- Error rate
- P50, P95, and P99 latency
- Queue depth
- Active workers
- Retry rate
- Timeout rate
- Cache hit rate
- Database connection-pool use

## 9.3 Metric-set configuration

Each monitored entity uses a named metric profile.

```yaml
profile: web_service_v1
interval_seconds: 60
metrics:
  - cpu.utilization
  - memory.working_set
  - http.request_rate
  - http.error_rate
  - http.duration.p95
  - queue.depth
  - db.pool.utilization
```

Profiles provide stable dimensions and prevent arbitrary metric combinations from reaching the model.

## 9.4 Window construction

Default:

```yaml
sample_interval_seconds: 60
window_length: 60
window_duration: 60m
stride: 5
maximum_missing_fraction: 0.10
```

Processing stages:

1. Resample onto a fixed interval.
2. Aggregate multiple samples according to metric semantics.
3. Impute small gaps with forward fill, interpolation, or seasonal value depending on metric type.
4. Mark every imputed value with a missingness indicator.
5. Reject or route windows with excessive missingness.
6. Apply log transform to heavy-tailed metrics.
7. Normalize using robust training statistics.
8. Add time features such as hour of day and day of week.
9. Add deployment and maintenance flags.

## 9.5 Model architecture

Use a compact Transformer encoder over numerical vectors rather than tokenizing numbers as text.

```yaml
model_type: multivariate_metric_transformer
input_features: profile_dependent
hidden_size: 96
num_hidden_layers: 3
num_attention_heads: 4
intermediate_size: 256
window_length: 60
dropout: 0.10
parameter_count_target: 500_000_to_3_000_000
```

Components:

- Numerical projection
- Metric-identity embedding
- Missingness projection
- Time-feature projection
- Position embedding
- Transformer encoder
- Reconstruction head
- Forecasting head
- Window-classification head
- Metric-contribution output

## 9.6 Training objectives

### Masked-value reconstruction

Mask values and reconstruct them from other metrics and surrounding time points.

### Forecasting

Predict the next one to five intervals.

### Corruption detection

Generate:

- Spikes
- Drops
- Level shifts
- Gradual drift
- Variance changes
- Broken metric relationships
- Delayed response between dependent metrics
- Seasonal-pattern disruptions
- Stuck-at-constant sensors

### Cross-metric consistency

Learn relationships such as:

- Request rate rising with CPU
- Error rate rising with timeout rate
- Queue depth affecting latency
- Memory pressure preceding OOM events

## 9.7 Metrics anomaly score

```text
metrics_score =
    0.30 * reconstruction_error
  + 0.30 * forecast_error
  + 0.20 * corruption_probability
  + 0.10 * cross_metric_inconsistency
  + 0.10 * baseline_distance
```

Compute both:

- Point-level score
- Window-level score

## 9.8 Baseline companion methods

Run simple baselines during development:

- Static thresholds
- Rolling z-score
- Robust median absolute deviation
- Seasonal residual
- Isolation Forest
- Autoencoder

The Transformer must beat these on incident-level usefulness or it should not be promoted merely for possessing more matrix multiplication.

## 9.9 Explainability

Return:

- Top contributing metrics
- Observed values
- Expected ranges or forecasts
- Time of first divergence
- Cross-metric inconsistencies
- Missing-data impact
- Similar historical windows

Example:

```json
{
  "model_version": "1.2.0",
  "calibrated_score": 0.87,
  "window_start": "2026-07-26T19:45:00Z",
  "window_end": "2026-07-26T20:45:00Z",
  "contributors": [
    {
      "metric": "http.error_rate",
      "observed": 0.082,
      "expected": 0.011,
      "contribution": 0.34
    },
    {
      "metric": "db.pool.utilization",
      "observed": 0.98,
      "expected": 0.61,
      "contribution": 0.27
    }
  ],
  "missing_fraction": 0.01
}
```

## 9.10 Metrics-model acceptance criteria

- Supports at least 20 metrics per profile.
- Scores a window in under 100 ms at P95 on standard CPU hardware.
- Detects at least 85% of seeded spikes, level shifts, drift, and broken-correlation anomalies.
- Returns ranked metric contributors for 95% of high-score windows.
- Distinguishes missing-data problems from behavioral anomalies.
- Outperforms the best simple baseline on incident-level F1 or provides materially better lead time.

# 10. Correlation and incident scoring

## 10.1 Purpose

Convert individual model findings into coherent incidents. Correlation must reduce alert volume, preserve evidence, and distinguish isolated novelty from multi-signal risk.

## 10.2 Finding schema

```json
{
  "schema_version": "1.0",
  "finding_id": "finding-01J...",
  "tenant_id": "tenant-acme",
  "finding_type": "network_anomaly",
  "asset_id": "host-payments-03",
  "service_id": "payments-api",
  "model_name": "flow-transformer",
  "model_version": "1.4.0",
  "raw_score": 4.19,
  "calibrated_score": 0.91,
  "severity_hint": "high",
  "window": {
    "start": "2026-07-26T20:40:00Z",
    "end": "2026-07-26T20:45:00Z"
  },
  "contributors": [],
  "evidence_refs": [],
  "context": {
    "deployment_id": "deploy-20260726-441"
  },
  "compliance": {
    "profile_pack_ids": ["cis-v8-ig1"],
    "check_ids": ["cis.v8.8.audit-log-management"],
    "surfaces": ["host", "identity"],
    "automation": "auto"
  }
}
```

Optional `compliance` tags findings to Security Profile packs and checks (see §10.11). Schema: `contracts/findings/finding.schema.json`.
## 10.3 Correlation keys

- Tenant
- Asset
- Service
- Trace
- Deployment
- Repository commit
- User identity hash
- Source and destination asset pair
- Kubernetes workload
- Time window
- Shared anomaly category

## 10.4 Correlation window

Default:

- Initial incident window: 15 minutes
- Extend incident while related findings arrive
- Maximum inactivity before closure eligibility: 30 minutes
- Configurable by service and finding type

## 10.5 Feature vector

```json
{
  "max_log_score": 0.94,
  "max_code_score": 0.63,
  "max_network_score": 0.91,
  "max_metrics_score": 0.87,
  "model_count": 3,
  "finding_count": 8,
  "asset_criticality": 0.90,
  "deployment_age_minutes": 12,
  "new_external_peer": true,
  "auth_related_log": true,
  "error_rate_anomaly": true,
  "affected_asset_count": 3,
  "known_maintenance": false,
  "vector_novelty": 0.42
}
```

`vector_novelty` is optional and only populated when `VECTOR_NOVELTY_ENABLED` is true (correlation-engine / profile-evaluator). Soft-fail if Qdrant is unavailable.

## 10.6 Initial scoring model

Use a transparent calibrated logistic regression or gradient-boosted tree.

Example conceptual formula:

```text
incident_risk =
  sigmoid(
      b0
    + b1 * max_log_score
    + b2 * max_code_score
    + b3 * max_network_score
    + b4 * max_metrics_score
    + b5 * asset_criticality
    + b6 * model_count
    + b7 * recent_deployment
    + b8 * new_external_peer
    - b9 * known_maintenance
    + b10 * vector_novelty   # only when VECTOR_NOVELTY_ENABLED
  )
```

## 10.7 Deterministic rules

Examples:

```text
IF network_score >= 0.85
AND new_external_peer = true
AND log finding category = privilege_change
THEN minimum severity = high
```

```text
IF metrics_score >= 0.80
AND deployment_age <= 30 minutes
AND error_rate contributor exists
THEN category includes deployment_regression
```

```text
IF code_score >= 0.85
AND code category = network_egress
AND network finding reaches a new external peer
AND commit matches active deployment
THEN minimum severity = critical
```

```text
IF all findings occur during approved maintenance
AND no deterministic security indicator exists
THEN suppress notification but retain incident
```

## 10.8 Incident schema

```json
{
  "incident_id": "inc-01J...",
  "tenant_id": "tenant-acme",
  "title": "Payments API contacted a new external peer after authentication change",
  "status": "open",
  "severity": "critical",
  "risk_score": 0.96,
  "category": [
    "suspicious_egress",
    "authentication_change"
  ],
  "first_seen": "2026-07-26T20:39:12Z",
  "last_seen": "2026-07-26T20:45:00Z",
  "assets": [
    "host-payments-03"
  ],
  "services": [
    "payments-api"
  ],
  "deployment_id": "deploy-20260726-441",
  "commit": "25d874c",
  "finding_ids": [],
  "summary": "A newly deployed authentication change was followed by an unexpected privilege event, elevated errors, and first-seen outbound traffic.",
  "evidence": [],
  "assigned_to": null,
  "disposition": null
}
```

## 10.9 Incident lifecycle

Statuses:

- Open
- Acknowledged
- Investigating
- Resolved
- Closed
- Suppressed

Dispositions:

- True positive
- False positive
- Expected change
- Maintenance
- Benign anomaly
- Duplicate
- Unknown

Every transition must be audited.

## 10.10 Deduplication

Use a deduplication fingerprint based on:

- Tenant
- Service or asset
- Incident category
- Dominant contributor
- Destination category where relevant
- Deployment version
- Fixed time bucket

Do not deduplicate incidents that involve different tenants or materially different destinations.

## 10.11 Security Profiles and compliance coverage

Security Profiles let a tenant multi-select **framework**, **industry**, **surface**, and **certification** packs. Selection **unions** checks (strictest wins). Profiles produce evidence-oriented coverage — they do **not** claim legal certification.

| Concept | Location |
| --- | --- |
| Pack YAML | `detection/profiles/packs/`, `detection/profiles/surfaces/`, `detection/profiles/packs/certification/` |
| Presets | `detection/profiles/presets.yaml` |
| Detector / scanner bindings | `detection/profiles/bindings/` |
| Pack JSON Schema | `contracts/profiles/security_pack.schema.json` |
| API + DB | `services/incident-api` (`profiles_api.py`, Alembic `0005_security_profiles`) |
| Continuous evaluation | `services/profile-evaluator` (TLS/header probes, regression findings) |
| Semgrep profile rules | `detection/scanners/semgrep/rules/profiles/` |
| Ops guide | `docs/operations/security-profiles.md` |

**Coverage states:** `pass`, `fail`, `unknown`, `attested`, `not_applicable`.

**No silent pass:** `auto` / `hybrid` checks stay `unknown` with reason `telemetry_missing` until positive evidence exists (`probe_ok`, `compliance_ok`, `telemetry_ok`, attestation, or an open finding → `fail`).

**Roles:** `auditor` is an alias of `viewer` (read-only). Certification package export evaluates coverage **without** persisting check-state side effects.

## 10.12 Vector search (Qdrant)

Qdrant **complements** Postgres (system of record) and OpenSearch (full-text hunt). It answers similarity questions: similar findings/incidents, semantic TI, ATT&CK technique narratives, feature baselines for novelty.

| Piece | Location |
| --- | --- |
| Compose | `qdrant` + `embedding-worker` under profile **`vector`** |
| Client / collections | `packages/black_onyx_vector` — `findings_v1`, `incidents_v1`, `features_baseline_v1`, `ti_text_v1`, `attack_tech_v1`, `runbooks_v1` (768-d Cosine dense) |
| Payload schemas | `contracts/qdrant/` |
| Embedding worker | `services/embedding-worker` (Kafka consumer off by default in Compose; requires the configured real embedding model when vector search is enabled) |
| Similar / hunt APIs | `services/incident-api` `vector_api.py`, `federated_hunt.py` |
| Semantic TI | `services/threat-intel-service` `POST /api/v1/match/semantic` |
| ADR | `docs/architecture/ADR-002-vector-qdrant.md` |
| Ops guide | `docs/operations/qdrant-vector-search.md` |

**Feature flags (default off):** `VECTOR_SEARCH_ENABLED`, `FEDERATED_HUNT_ENABLED`, `VECTOR_NOVELTY_ENABLED`. Soft-fail when Qdrant is down. Tenant payload filters are mandatory; shared CTI / ATT&CK may use tenant `__global__`.

# 11. Application services and APIs

## 11.1 API conventions

- Base path: `/api/v1`
- JSON request and response bodies
- RFC 3339 timestamps in UTC
- Cursor-based pagination
- Idempotency key for create operations
- OpenAPI documentation
- Structured errors
- Request ID in every response
- Tenant derived from identity, not client-supplied headers alone

Error format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The request payload is invalid.",
    "details": [
      {
        "field": "occurred_at",
        "reason": "timestamp is too far in the future"
      }
    ],
    "request_id": "req-01J..."
  }
}
```

## 11.2 Authentication and authorization

Authentication:

- OpenID Connect for users
- OAuth 2.0 client credentials or signed API keys for collectors
- Short-lived service tokens inside the cluster
- Mutual TLS where feasible

Roles:

- Viewer
- Analyst
- ML engineer
- Administrator
- Integration service

Example permissions:

| Action | Viewer | Analyst | ML engineer | Administrator |
| --- | --- | --- | --- | --- |
| View incidents | Yes | Yes | Yes | Yes |
| Change incident status | No | Yes | Yes | Yes |
| Submit disposition | No | Yes | Yes | Yes |
| View raw code evidence | Limited | Policy based | Policy based | Yes |
| Start training | No | No | Yes | Yes |
| Promote model | No | No | With approval | Yes |
| Configure collectors | No | No | No | Yes |

## 11.3 Ingestion endpoints

### Submit logs

```http
POST /api/v1/ingest/logs
```

Request:

```json
{
  "events": [
    {
      "schema_version": "1.0",
      "event_id": "01J...",
      "occurred_at": "2026-07-26T20:41:02Z",
      "asset_id": "host-payments-03",
      "service_id": "payments-api",
      "severity": "ERROR",
      "message": "Failed login for user alice from 10.0.4.21"
    }
  ]
}
```

Response:

```json
{
  "accepted": 1,
  "rejected": 0,
  "batch_id": "batch-01J..."
}
```

### Submit flows

```http
POST /api/v1/ingest/network-flows
```

### Submit metric samples

```http
POST /api/v1/ingest/metrics
```

### Receive code webhook

```http
POST /api/v1/integrations/code/{provider}/webhook
```

### Submit deployment event

```http
POST /api/v1/ingest/deployments
```

## 11.4 Incident endpoints

```http
GET /api/v1/incidents
GET /api/v1/incidents/{incident_id}
PATCH /api/v1/incidents/{incident_id}
POST /api/v1/incidents/{incident_id}/comments
POST /api/v1/incidents/{incident_id}/disposition
GET /api/v1/incidents/{incident_id}/timeline
GET /api/v1/incidents/{incident_id}/related
```

Supported filters:

- Status
- Severity
- Category
- Service
- Asset
- Model
- Assignee
- Time range
- Deployment
- Repository
- Minimum score
- Disposition

## 11.5 Findings endpoints

```http
GET /api/v1/findings
GET /api/v1/findings/{finding_id}
GET /api/v1/findings/{finding_id}/evidence
```

## 11.6 Asset endpoints

```http
GET /api/v1/assets
POST /api/v1/assets
GET /api/v1/assets/{asset_id}
PATCH /api/v1/assets/{asset_id}
GET /api/v1/assets/{asset_id}/topology
GET /api/v1/assets/{asset_id}/baseline
```

## 11.7 Model-management endpoints

```http
GET /api/v1/models
GET /api/v1/models/{model_name}/versions
POST /api/v1/models/{model_name}/training-jobs
GET /api/v1/training-jobs/{job_id}
POST /api/v1/models/{model_name}/versions/{version}/promote
POST /api/v1/models/{model_name}/versions/{version}/rollback
GET /api/v1/models/{model_name}/drift
```

Promotion must require:

- Successful evaluation
- Artifact signature
- Compatible input schema
- Approval identity
- Rollback target
- Deployment strategy

## 11.8 Search endpoint

```http
POST /api/v1/search
```

Request:

```json
{
  "query": "service:payments-api severity:high after:2026-07-26T00:00:00Z",
  "types": [
    "incident",
    "finding",
    "log",
    "flow",
    "deployment"
  ],
  "limit": 50
}
```

## 11.9 Health endpoints

```http
GET /health/live
GET /health/ready
GET /health/dependencies
GET /metrics
```

Readiness must fail when required dependencies are unavailable. Liveness should only indicate whether the process must restart.

## 11.10 Security profile endpoints

Served by **incident-api** (`:8083`):

```http
GET  /api/v1/security-packs
GET  /api/v1/security-packs/{pack_id}
GET  /api/v1/security-profiles
POST /api/v1/security-profiles
GET  /api/v1/security-profiles/{profile_id}
PATCH /api/v1/security-profiles/{profile_id}
DELETE /api/v1/security-profiles/{profile_id}
POST /api/v1/security-profiles/{profile_id}/evaluate
GET  /api/v1/security-profiles/{profile_id}/coverage
GET  /api/v1/security-profiles/{profile_id}/export
POST /api/v1/security-profiles/{profile_id}/attest
POST /api/v1/security-profiles/{profile_id}/exceptions
GET  /api/v1/security-profiles/{profile_id}/exceptions
POST /api/v1/security-profiles/{profile_id}/certification-package?export_format=json|csv|zip
```

Profile-evaluator (`:8116`):

```http
POST /api/v1/profile-evaluator/evaluate
POST /api/v1/profile-evaluator/probe
```

## 11.11 Vector and federated hunt endpoints

Requires `VECTOR_SEARCH_ENABLED` / `FEDERATED_HUNT_ENABLED` as applicable (soft-fail / empty results when off or Qdrant down):

```http
GET  /api/v1/findings/{finding_id}/similar
GET  /api/v1/incidents/{incident_id}/similar
POST /api/v1/hunt/vector
POST /api/v1/hunt/federated
GET  /api/v1/hunt/search?q=          # OpenSearch full-text (existing)
```

Threat intel semantic match (`threat-intel-service` `:8098`):

```http
POST /api/v1/match/semantic
```

Federated hunt merges OpenSearch, Qdrant similarity, and TI exact/semantic hits into one operator response. See `docs/operations/opensearch-hunt.md`.

## 11.12 Response orchestration (SOAR)

**response-orchestrator** (`:8111`) queues playbook requests. Vector-only / non-auto signals force `dry_run` and human approval. UI: `/response-queue`.

```http
GET  /api/v1/response/pending
POST /api/v1/response/{id}/approve
POST /api/v1/response/{id}/reject
```

Policy: `services/response-orchestrator/response_orchestrator/policy.py`. Ops: `docs/operations/response-orchestrator.md`.

## 11.13 Identity connectors

**integration-hub** (`:8105`) syncs IdP/HR inventories and emits identity findings with `compliance` tags (surface-identity checks). Failures map to profile check IDs for coverage evaluation.

# 12. User interface

## 12.1 Primary navigation

- Overview
- Incidents
- Findings
- Hunt (OpenSearch and federated modes)
- Security Profiles
- Response queue
- Assets
- Services
- Code changes
- Network
- Metrics
- Models
- ATT&CK coverage
- Data health
- Administration

## 12.2 Overview dashboard

Display:

- Open incidents by severity
- Incident trend
- Findings by model
- Top affected services
- Top affected assets
- Recent deployments
- Model-health summary
- Ingestion lag
- Data-quality warnings
- False-positive trend

## 12.3 Incident list

Columns:

- Severity
- Risk score
- Title
- Status
- Service
- Assets
- Models involved
- First seen
- Last seen
- Assignee
- Deployment
- Disposition

Functions:

- Filter and sort
- Bulk acknowledge
- Assign
- Export selected metadata
- Save views
- Suppress matching pattern with policy controls

## 12.4 Incident detail

Sections:

### Summary

- Generated title
- Risk score
- Severity
- Status
- Owner
- Affected assets and services
- Deployment and commit
- Generated plain-language summary

### Unified timeline

Chronological display of:

- Log anomalies
- Metric divergences
- Network flows
- Code changes
- Deployments
- Analyst actions

### Model evidence

Separate tabs for:

- Logs
- Code
- Network
- Metrics
- Correlation

### Related activity

- Similar incidents
- Same destination
- Same deployment
- Same repository change
- Same asset
- Same anomaly pattern

### Analyst workflow

- Acknowledge
- Assign
- Comment
- Change severity
- Set disposition
- Resolve
- Create suppression
- Open external ticket

## 12.5 Log evidence view

Display:

- Event sequence with anomalous positions highlighted
- Template text
- Expected templates
- Relative score contribution
- Nearby raw events subject to permissions
- Trace or session linkage
- Similar normal sequences

## 12.6 Code evidence view

Display:

- Unified diff
- Highlighted risky lines
- Risk categories
- Static-analysis results
- Historical similarity
- Deployment state
- Repository and pull-request link
- Advisory disclaimer

## 12.7 Network evidence view

Display:

- Source and destination roles
- Connection timeline
- Service and protocol
- First-seen status
- Baseline frequency
- Volume deviation
- Topology graph
- Related DNS and TLS metadata

## 12.8 Metrics evidence view

Display:

- Observed series
- Expected band
- Anomaly score over time
- Deployment markers
- Top contributing metrics
- Missing-data intervals
- Comparable historical windows

## 12.9 Model operations view

Display:

- Deployed version
- Candidate versions
- Evaluation metrics
- Drift status
- Inference throughput and latency
- Error rates
- Training dataset period
- Threshold
- Calibration plot
- Rollback action

## 12.10 Security Profiles view

Operators multi-select packs/presets, activate a profile, run evaluate, inspect coverage heatmap (pass/fail/unknown/attested), manage exceptions/attestations, and download certification packages (JSON/CSV/ZIP). Disclaimers must state evidence packages are not certificates.

## 12.11 Hunt, similar entities, and response queue

- **Hunt:** OpenSearch full-text mode and federated mode (OpenSearch + Qdrant + TI).
- **Findings / incident detail:** “Similar” neighbors when `VECTOR_SEARCH_ENABLED`.
- **Response queue:** Human approve/reject for SOAR requests; vector-only suggestions remain dry-run.
- **ATT&CK coverage:** Optional filter to active profile’s MITRE-oriented packs.

# 13. Model training and MLOps

## 13.1 Training pipeline

```text
Dataset definition
       |
       v
Raw event snapshot
       |
       v
Validation and exclusion rules
       |
       v
Feature generation
       |
       v
Chronological split
       |
       v
Training
       |
       v
Evaluation
       |
       v
Bias, leakage, and drift checks
       |
       v
ONNX export and quantization
       |
       v
Artifact signing
       |
       v
Registry candidate stage
       |
       v
Human approval
       |
       v
Canary deployment
       |
       v
Production promotion
```

## 13.2 Dataset manifest

Every training run must store:

```json
{
  "dataset_id": "logs-payments-2026-07-v3",
  "tenant_id": "tenant-acme",
  "model_type": "log",
  "schema_version": "1.2",
  "feature_version": "3.0",
  "source_query": "...",
  "time_range": {
    "start": "2026-06-01T00:00:00Z",
    "end": "2026-07-15T00:00:00Z"
  },
  "excluded_incidents": [
    "inc-..."
  ],
  "event_count": 84219342,
  "sequence_count": 4812731,
  "content_hash": "sha256:...",
  "created_by": "user-or-service-id"
}
```

## 13.3 Experiment tracking

Track:

- Source commit
- Container image digest
- Dataset ID
- Feature version
- Hyperparameters
- Random seed
- Training duration
- Hardware
- Validation metrics
- Test metrics
- Calibration metrics
- Threshold candidates
- Artifact hashes
- ONNX compatibility
- Quantization comparison

## 13.4 Model artifact package

```text
model-package/
  model.onnx
  model-card.md
  config.json
  tokenizer-or-feature-schema.json
  calibration.json
  thresholds.json
  metrics.json
  dataset-manifest.json
  signature.json
  checksums.txt
```

## 13.5 Model card

Each model card must include:

- Intended use
- Prohibited use
- Supported data sources
- Training period
- Evaluation summary
- Known limitations
- Sensitive-data considerations
- Expected drift patterns
- Threshold rationale
- Rollback version
- Owner
- Approval history

## 13.6 Model versioning

Format:

```text
MAJOR.MINOR.PATCH
```

Increment:

- Major for incompatible feature or behavior changes
- Minor for compatible retraining or architecture improvements
- Patch for calibration, threshold, or packaging fixes

Feature schemas are versioned independently.

## 13.7 Promotion stages

- Development
- Candidate
- Shadow
- Canary
- Production
- Archived

### Shadow

The model receives production data but cannot create operator-visible incidents.

### Canary

Route a configurable percentage of entities or tenants to the candidate model.

### Production

Use as the default scoring version.

## 13.8 Drift detection

Monitor:

### Input drift

- Template distribution
- Unknown-template rate
- Code-language and path distribution
- Network service and peer distribution
- Metrics-value distribution
- Missingness
- Sequence length
- Event rate

### Output drift

- Score distribution
- Alert rate
- Contributor distribution
- Calibration against analyst feedback

### Concept drift indicators

- Falling precision
- Rising false-positive rate
- Missed seeded incidents
- Changes after major architecture or deployment shifts

## 13.9 Retraining policy

Trigger candidate retraining when:

- Drift exceeds a sustained threshold.
- Unknown-template rate remains elevated.
- A major application release changes behavior.
- Sufficient new feedback exists.
- Scheduled retraining interval is reached.
- Model quality degrades.

Retraining does not imply automatic promotion.

## 13.10 Threshold calibration

Use validation data and operator-capacity constraints.

Store thresholds by:

- Tenant
- Environment
- Service
- Asset role
- Model version
- Severity level

Example:

```json
{
  "model": "log-model",
  "version": "1.3.0",
  "scope": {
    "tenant_id": "tenant-acme",
    "service_id": "payments-api",
    "environment": "production"
  },
  "thresholds": {
    "medium": 0.72,
    "high": 0.86,
    "critical": 0.95
  }
}
```

# 14. Security, privacy, and compliance

## 14.1 Threat model

Protect against:

- Unauthorized data ingestion
- Tenant-data leakage
- Malicious telemetry payloads
- Prompt-like or code-like content attempting to affect processing
- Poisoned training data
- Compromised collectors
- Model artifact tampering
- Webhook forgery
- Repository-token theft
- Stored cross-site scripting in log or code content
- Denial of service through event floods
- Sensitive-data exposure in evidence
- Unauthorized model promotion
- Malicious serialized model formats

## 14.2 Data minimization

- Mask secrets before persistent storage where possible.
- Hash user identifiers with a tenant-specific keyed hash.
- Prefer asset IDs and categories over raw IP addresses.
- Store raw code only when required and allowed.
- Provide path-level exclusions.
- Make packet payload collection out of scope by default.
- Apply retention by data class.
- Separate raw evidence permissions from incident-summary permissions.

## 14.3 Encryption

- TLS 1.2 or later for all external communication.
- Mutual TLS for sensors where practical.
- Encryption at rest for databases, object storage, and backups.
- Per-tenant encryption keys where required.
- Rotate secrets and certificates.
- Never place credentials in model inputs or logs.

## 14.4 Repository access

- Use provider applications or short-lived installation tokens.
- Request read-only repository metadata and contents.
- Scope access to selected repositories.
- Do not persist full clones.
- Delete temporary workspaces after each job.
- Audit every repository fetch.

## 14.5 Model security

- Use ONNX or safetensors-style non-executable formats.
- Do not load arbitrary pickle artifacts.
- Verify artifact signatures and hashes.
- Scan model containers.
- Restrict registry write access.
- Record promotion approvals.
- Validate model input dimensions and schema before activation.
- Sandbox training jobs.

## 14.6 Training-data poisoning controls

- Exclude confirmed incidents.
- Require review for large new baseline periods.
- Compare distributions before merging new training data.
- Preserve immutable manifests.
- Limit the influence of recently collected data.
- Detect sudden label or template changes.
- Do not automatically treat analyst “false positive” labels as clean training truth.
- Require minimum sample counts before repository- or service-specific retraining.

## 14.7 Audit log

Audit:

- Authentication
- Configuration changes
- Collector registration
- Data exports
- Incident changes
- Suppression creation
- Feedback
- Training requests
- Model promotion and rollback
- Repository access
- Permission changes
- Retention-policy changes

Audit records must be append-only and independently retained.

## 14.8 Retention defaults

| Data type | Default retention |
| --- | --- |
| Raw logs | 14 days |
| Normalized logs | 30 days |
| Log templates and features | 90 days |
| Raw flow metadata | 30 days |
| Aggregated network features | 180 days |
| Raw metric samples | 30 days |
| Downsampled metrics | 365 days |
| Source-code snapshots | Job lifetime only |
| Code findings and selected diff evidence | 90 days |
| Incidents and audit records | 365 days or policy-defined |
| Training manifests and model artifacts | Model lifetime plus audit period |
| Qdrant vectors (findings/incidents) | Align with finding/incident retention; baselines and ATT&CK reference data may be longer |

## 14.9 Security Profiles and certification exports

- Profiles map telemetry and scanners to framework/industry checks; they are **not** legal certifications.
- Certification package exports are auditor-oriented evidence bundles with an explicit disclaimer.
- `auditor` role is read-only (viewer-equivalent); export must not persist evaluation side effects.
- Semantic TI and vector similarity are **advisory** — never sole justification for auto-destructive SOAR actions.
- Vector-only response suggestions force dry-run + human approval (`response-orchestrator`).

# 15. Reliability, scalability, and observability

## 15.1 Availability targets

| Component | Target |
| --- | --- |
| Ingestion Gateway | 99.9% |
| Broker | 99.9% |
| Incident API | 99.9% |
| Model services | 99.5% for MVP, 99.9% production |
| Training system | Best effort with resumable jobs |
| Web UI | 99.9% |

## 15.2 Backpressure

- Ingestion publishes to the broker and returns after durable acknowledgment.
- Consumers commit offsets only after successful processing.
- Use bounded internal queues.
- Pause partitions when dependencies are unavailable.
- Route repeatedly failing records to dead-letter topics.
- Expose consumer lag.
- Support replay by time range or offset.
- Limit per-tenant throughput.

## 15.3 Idempotency

Use:

- Event ID
- Tenant ID
- Processing-stage version

Example deduplication key:

```text
tenant_id:event_id:processor_version
```

Findings should include a deterministic fingerprint to prevent duplicates during replay.

## 15.4 Scaling model services

- Batch compatible requests.
- Scale on queue depth, inference latency, and CPU use.
- Keep model artifacts memory-mapped where supported.
- Warm new replicas before marking ready.
- Use one serving deployment per model and version.
- Cap batch wait time to preserve detection latency.
- Quantize to INT8 after accuracy verification.

## 15.5 Observability

Every service must expose:

- Request rate
- Error rate
- Latency
- Queue depth
- Consumer lag
- Batch size
- CPU and memory
- Dependency health
- Rejected-event count
- Dead-letter count
- Tenant throttling
- Build version

Model services additionally expose:

- Model version
- Inference count
- P50, P95, and P99 latency
- Batch-size distribution
- Score distribution
- Threshold-crossing rate
- Input-shape errors
- Unknown-token rate
- Missing-feature rate
- Quantization status

## 15.6 Distributed tracing

Use OpenTelemetry to trace:

```text
ingestion
 -> broker publication
 -> normalization
 -> feature generation
 -> inference
 -> finding creation
 -> correlation
 -> incident update
 -> notification
```

Include event IDs and finding IDs as trace attributes, but do not attach full sensitive payloads.

## 15.7 Disaster recovery

- Automated PostgreSQL backups.
- Object-storage replication.
- Broker-topic replication.
- Infrastructure rebuilt from code.
- Model registry replicated.
- Quarterly restore test.
- Defined recovery-point and recovery-time objectives.

Initial targets:

```text
RPO: 15 minutes
RTO: 4 hours
```

# 16. Testing strategy

## 16.1 Unit tests

Test:

- Schema validation
- Timestamp handling
- Normalization
- Masking
- Sequence windows
- Feature calculations
- Score aggregation
- Correlation rules
- Deduplication
- Authorization
- Retention logic
- Model-version routing

## 16.2 Contract tests

Every producer and consumer pair must share versioned contract fixtures.

Required contracts:

- Raw log event
- Normalized log event
- Code change
- Network flow
- Metric sample
- Feature batches
- Model requests
- Model responses
- Findings
- Incidents
- Notifications

## 16.3 Model tests

For each model:

- Deterministic inference for a fixed artifact and input
- Shape validation
- NaN and infinity handling
- Empty and maximum-size batches
- Unknown-category handling
- Quantized versus unquantized score comparison
- Explanation completeness
- Threshold behavior
- Regression fixtures for known anomalies
- Performance benchmark

## 16.4 Synthetic anomaly suite

### Logs

- Event deletion
- Event insertion
- Event order change
- Novel template
- Privilege event inserted into authentication sequence
- Burst of repeated failures
- Parameter-category mutation

### Code

- Shell execution with external input
- Removed authorization check
- Logging disabled
- New outbound request
- Hard-coded credential
- Unsafe deserialization
- Public infrastructure exposure
- Safe refactor control case

### Network

- Horizontal scan
- Vertical scan
- Periodic beacon
- Data-volume spike
- First-seen external peer
- Unexpected protocol
- Excessive DNS activity
- Normal backup transfer control case

### Metrics

- Spike
- Drop
- Level shift
- Slow drift
- Variance increase
- Stuck metric
- Broken CPU/request relationship
- Missing-data control case

## 16.5 Integration tests

Test complete paths:

```text
raw log -> normalized log -> sequence -> model -> finding -> incident
```

```text
Git webhook -> diff extraction -> scanners -> code model -> finding
```

```text
Zeek record -> normalized flow -> window -> model -> finding
```

```text
metric samples -> resampling -> window -> model -> finding
```

```text
four findings -> correlation -> notification -> analyst feedback
```

## 16.6 Load tests

Test:

- Sustained expected throughput
- Twice expected peak
- Ten-minute burst at five times expected flow
- Large code pull request
- Broker replay
- Model-service cold start
- Search under concurrent analyst use
- One noisy tenant without affecting others

## 16.7 Failure tests

Inject:

- Broker outage
- PostgreSQL outage
- OpenSearch outage
- Object-storage outage
- Model-service timeout
- Invalid model artifact
- Collector clock skew
- Duplicate events
- Out-of-order events
- Partial metric gaps
- Repository provider outage
- Notification failure

## 16.8 Security tests

- Dependency scanning
- Container scanning
- Static application security testing
- Secret scanning
- API fuzzing
- Authorization matrix tests
- Cross-tenant access tests
- Webhook-signature tests
- Stored-XSS tests on logs and code
- Oversized-payload tests
- Malicious archive and decompression tests
- Model-artifact signature tests
- Penetration test before production launch

## 16.9 Evaluation methodology

Use chronological datasets and incident-level metrics.

Report:

- Precision
- Recall
- F1
- Area under precision-recall curve
- False alerts per entity per day
- Detection delay
- Recall on unseen anomaly types
- Calibration error
- Evidence completeness
- CPU and memory
- Inference latency
- Analyst usefulness

Event-level metrics must not be the only reported results.

# 17. Deployment architecture

## 17.1 Single-node development deployment

Docker Compose services:

- PostgreSQL
- Redpanda
- OpenSearch
- MinIO
- Redis
- MLflow
- API
- Four processors
- Four model services
- Correlation engine
- Frontend

Use reduced retention and one replica.

## 17.2 Production Kubernetes deployment

Namespaces:

```text
anomaly-ingestion
anomaly-processing
anomaly-models
anomaly-application
anomaly-observability
anomaly-training
```

## 17.3 Kubernetes requirements

- Pod disruption budgets
- Horizontal pod autoscaling
- Resource requests and limits
- Readiness and liveness probes
- Network policies
- Non-root containers
- Read-only root filesystems where possible
- Dedicated service accounts
- Topology-spread constraints
- Anti-affinity for broker and database components
- Secrets from an external secret manager
- Signed images
- Admission policies

## 17.4 Model deployment pattern

Each model version gets a distinct immutable deployment.

```text
log-model-1-3-0
log-model-1-4-0-candidate
code-model-2-1-0
network-model-1-4-0
metrics-model-1-2-0
```

The Model Gateway chooses the active deployment based on tenant, environment, model stage, and canary policy.

## 17.5 Resource starting points

| Service | CPU request | Memory request |
| --- | ---: | ---: |
| Ingestion Gateway | 500m | 512 MiB |
| Log Processor | 1 CPU | 1 GiB |
| Code Processor | 1 CPU | 2 GiB |
| Flow Processor | 1 CPU | 1 GiB |
| Metrics Processor | 500m | 1 GiB |
| Log Model | 2 CPU | 2 GiB |
| Code Model | 2 CPU | 4 GiB |
| Network Model | 2 CPU | 2 GiB |
| Metrics Model | 1 CPU | 1 GiB |
| Correlation Engine | 1 CPU | 1 GiB |
| Incident API | 500m | 512 MiB |

These are initial requests, not sacred truths delivered from a mountain. Tune them using measured workloads.

## 17.6 Environments

- Local
- Development
- Integration
- Staging
- Production

Production data must not be copied into lower environments without approved sanitization.

# 18. Repository structure

```text
anomaly-platform/
  README.md
  ANOMALY_DETECTION_PLATFORM.md
  docs/
    architecture/          # ADR-001 stack, ADR-002 Qdrant
    operations/            # hunt, Qdrant, security profiles, SOAR
    operations/runbooks/
    deployment/
    defender/
  docs_implemented/        # Design history (Security Profiles, Qdrant, upgrades)
  contracts/
    common/ logs/ code/ network/ metrics/
    findings/ incidents/
    profiles/              # security_pack.schema.json
    qdrant/                # payload schemas per collection
  packages/
    black_onyx_contracts/
    black_onyx_otel/
    black_onyx_vector/
  detection/profiles/      # pack YAML, presets, bindings
  detection/scanners/semgrep/rules/profiles/
  services/
    ingestion-gateway/
    asset-registry/
    *-processor/           # log, code, flow, metrics, host-state, firewall, ids, malware
    model-gateway/
    inference-worker/
    correlation-engine/
    incident-api/          # profiles, vector, federated hunt
    threat-intel-service/
    embedding-worker/      # Compose profile vector
    profile-evaluator/
    response-orchestrator/
    integration-hub/
    notification-service/
    training-orchestrator/
    malware-triage/ malware-orchestrator/
  models/
  frontend/
  infrastructure/docker-compose/
  tests/contract/          # includes pack + qdrant payload schema tests
  scripts/development/     # restore_qdrant_attack_tech, seed_attack_tech_vectors
```

(See `README.md` for the authoritative short layout; keep this tree illustrative.)

## 18.1 Shared model interface

```python
from typing import Protocol

class AnomalyModel(Protocol):
    model_name: str
    model_version: str
    feature_version: str

    def validate_input(self, batch: dict) -> None:
        ...

    def predict(self, batch: dict) -> dict:
        ...

    def health(self) -> dict:
        ...
```

## 18.2 Model service endpoint

```http
POST /v1/predict
```

Request:

```json
{
  "request_id": "req-01J...",
  "tenant_id": "tenant-acme",
  "model_name": "log-model",
  "requested_version": "production",
  "feature_version": "3.0",
  "items": []
}
```

Response:

```json
{
  "request_id": "req-01J...",
  "model_name": "log-model",
  "model_version": "1.3.0",
  "feature_version": "3.0",
  "predictions": [],
  "timing_ms": {
    "queue": 3,
    "inference": 41,
    "total": 47
  }
}
```

# 19. Delivery plan

## 19.1 Phase 0: foundation, weeks 1-2

Deliver:

- Monorepo or coordinated repositories
- CI pipeline
- Local Docker environment
- Common event envelope
- PostgreSQL and broker
- Authentication skeleton
- Asset registry
- Basic observability
- Architecture decision records

Exit criteria:

- A test event can enter the gateway and reach a consumer.
- Tenant isolation tests pass.
- Services expose health and metrics.

## 19.2 Phase 1: log pipeline and shared incident workflow, weeks 3-6

Deliver:

- Log ingestion
- Drain3 processing
- Sequence builder
- Initial log Transformer
- Finding schema
- Correlation skeleton
- Incident API
- Incident list and detail UI
- Analyst disposition workflow

Exit criteria:

- Seeded log anomalies create explainable incidents.
- Raw-to-incident latency is under five minutes.
- Log model can be replaced by version.

## 19.3 Phase 2: network and metrics models, weeks 7-10

Deliver:

- Zeek or flow ingestion
- Flow normalization and windowing
- Network Transformer
- Metrics ingestion and profiles
- Metrics windowing
- Metrics Transformer
- Unified timeline
- Cross-model correlation rules

Exit criteria:

- Network and metrics findings appear in the same incident.
- Seeded scan, beacon, spike, and drift tests pass.
- Throughput tests meet pilot volume.

## 19.4 Phase 3: code model and deployment correlation, weeks 11-13

Deliver:

- Git provider integration
- Diff and function extraction
- Semgrep integration
- Distilled CodeBERT service
- Pull-request annotation
- Deployment events
- Commit-to-deployment correlation
- Code evidence UI

Exit criteria:

- A risky change can be linked to a deployed service and subsequent runtime findings.
- Source-code access is audited and temporary clones are deleted.

## 19.5 Phase 4: MLOps and pilot hardening, weeks 14-16

Deliver:

- Training orchestrator
- MLflow tracking and registry
- ONNX export and quantization
- Candidate, shadow, canary, and production stages
- Drift dashboards
- Model rollback
- Security testing
- Backup and restore test
- Pilot documentation

Exit criteria:

- All four models can be trained, registered, promoted, and rolled back.
- Pilot tenants can operate independently.
- Incident evaluation meets MVP targets or documented exceptions.

## 19.6 Production hardening, weeks 17-24

Deliver:

- High availability
- Capacity expansion
- Advanced correlation tuning
- Saved searches
- Notification integrations
- Retention automation
- Disaster-recovery validation
- Penetration-test remediation
- Operator runbooks
- Service-level objectives
- Production-readiness review

## 19.7 Phase 6: Security Profiles and vector plane (shipped)

Delivered after the original MVP baseline (see `docs_implemented/` for design history):

- Security Profile pack catalog + incident-api CRUD / evaluate / coverage / exceptions / certification export
- Semgrep profile rule packs + detector/scanner bindings tagging finding `compliance`
- profile-evaluator continuous evaluation and TLS/header probes (no silent pass)
- Qdrant Compose profile + `black_onyx_vector` + embedding-worker
- Similar findings/incidents, federated hunt, semantic TI, optional vector novelty
- Response-orchestrator approval queue + vector-aware dry-run policy
- Integration-hub IdP/HR identity findings mapped to surface-identity checks
- Frontend: Security Profiles, Response queue, federated Hunt, similar entities

Exit criteria:

- Contract tests validate pack YAML and Qdrant payload schemas.
- Vector features default off; golden path remains healthy without Qdrant.
- Certification export does not claim legal compliance.

# 20. Acceptance criteria

## 20.1 End-to-end functional acceptance

The application must demonstrate this scenario:

1. A code change modifies authentication behavior.
2. The code model marks it as moderately risky.
3. A deployment event associates the commit with the production service.
4. The log model detects an unexpected privilege-related sequence.
5. The metrics model detects an increase in errors and database-pool utilization.
6. The network model detects a first-seen external destination.
7. The Correlation Engine creates one high- or critical-severity incident.
8. The incident contains a unified timeline and evidence from all four models.
9. An analyst can acknowledge, assign, comment, set a disposition, and resolve it.
10. The feedback is retained for later calibration but does not immediately retrain a model.

## 20.2 Data acceptance

- All incoming events use versioned schemas.
- Invalid events are rejected or dead-lettered.
- Duplicate events do not create duplicate findings.
- Late events are handled according to policy.
- Sensitive values are masked or permission-controlled.
- Data retention is enforced.

## 20.3 Model acceptance

- Four independently deployable model services exist.
- Each service supports batch inference.
- Each output includes model version, feature version, score, and contributors.
- ONNX artifacts are signed and verified.
- Quantized-model deviations remain within approved tolerances.
- Each model has a model card and evaluation report.
- Each model can be placed in shadow and canary mode.
- Each model can be rolled back without data migration.

## 20.4 Security acceptance

- OIDC authentication is enabled.
- Role-based authorization tests pass.
- Cross-tenant tests pass.
- Webhooks are verified.
- Repository credentials are scoped and short-lived.
- Model artifacts cannot execute arbitrary serialized code.
- Logs and code are safely escaped in the UI.
- Audit events exist for privileged actions.
- No critical security findings remain open.

## 20.5 Operational acceptance

- Dashboards cover ingestion, processing, models, APIs, and storage.
- Alerts exist for consumer lag, model errors, pipeline failure, and data-quality degradation.
- Backup restore is demonstrated.
- Runbooks exist for each critical dependency.
- Capacity testing provides at least 50% headroom over expected pilot peak.
- A model rollback is demonstrated.
- A broker replay is demonstrated without duplicate incidents.

# Appendix A: Configuration examples

## A.1 Platform configuration

```yaml
platform:
  environment: production
  tenant_isolation: strict
  default_timezone: UTC

broker:
  bootstrap_servers:
    - redpanda-0:9092
    - redpanda-1:9092
    - redpanda-2:9092
  delivery_semantics: at_least_once
  dead_letter_suffix: ".dlq"

storage:
  postgres_dsn_secret: anomaly-postgres
  opensearch_endpoint: https://opensearch:9200
  object_store_bucket: anomaly-models

retention:
  raw_logs_days: 14
  normalized_logs_days: 30
  network_flows_days: 30
  raw_metrics_days: 30
  incidents_days: 365
```

## A.2 Log-model configuration

```yaml
log_model:
  model_version: "1.3.0"
  feature_version: "3.0"

  sequence:
    max_length: 128
    stride: 32
    inactivity_timeout_seconds: 300
    maximum_duration_seconds: 900

  architecture:
    hidden_size: 256
    layers: 4
    attention_heads: 4
    intermediate_size: 512
    dropout: 0.10

  scoring:
    masked_event_loss: 0.45
    corruption_probability: 0.20
    template_novelty: 0.15
    embedding_distance: 0.10
    parameter_anomaly: 0.10

  thresholds:
    medium: 0.72
    high: 0.86
    critical: 0.95
```

## A.3 Code-model configuration

```yaml
code_model:
  model_version: "2.1.0"
  max_tokens: 512
  chunk_overlap: 64
  supported_languages:
    - python
    - javascript
    - typescript
    - java
    - go
    - csharp

  scanners:
    semgrep: true
    codeql: true
    secret_scanner: true
    dependency_scanner: true

  policy:
    advisory_only: true
    allow_model_only_blocking: false
```

## A.4 Network-model configuration

```yaml
network_model:
  model_version: "1.4.0"

  window:
    duration_seconds: 300
    max_events: 256
    stride_events: 64
    minimum_events: 4

  architecture:
    hidden_size: 128
    layers: 3
    attention_heads: 4
    intermediate_size: 384

  privacy:
    store_raw_ip: false
    hash_ip: true
    retain_country: true
    retain_asn: true
```

## A.5 Metrics-model configuration

```yaml
metrics_model:
  model_version: "1.2.0"
  profile: web_service_v1

  window:
    interval_seconds: 60
    length: 60
    stride: 5
    max_missing_fraction: 0.10

  architecture:
    hidden_size: 96
    layers: 3
    attention_heads: 4
    intermediate_size: 256
```

## A.6 Correlation policy

```yaml
correlation:
  initial_window_minutes: 15
  inactivity_close_minutes: 30

  severity_thresholds:
    medium: 0.60
    high: 0.80
    critical: 0.93

  rules:
    - id: new-peer-after-privilege-change
      when:
        network_score_gte: 0.85
        new_external_peer: true
        log_category: privilege_change
      set_minimum_severity: high

    - id: deployed-risky-egress
      when:
        code_score_gte: 0.85
        code_category: network_egress
        network_new_external_peer: true
        deployment_commit_matches: true
      set_minimum_severity: critical
```

# Appendix B: Reference event payloads

## B.1 Log finding

```json
{
  "finding_id": "finding-log-01J...",
  "finding_type": "log_anomaly",
  "tenant_id": "tenant-acme",
  "asset_id": "host-payments-03",
  "service_id": "payments-api",
  "model_name": "log-transformer",
  "model_version": "1.3.0",
  "feature_version": "3.0",
  "raw_score": 4.82,
  "calibrated_score": 0.94,
  "window": {
    "start": "2026-07-26T20:39:00Z",
    "end": "2026-07-26T20:41:02Z"
  },
  "contributors": [
    {
      "type": "unexpected_template",
      "template_id": "tpl-privilege-change",
      "position": 17,
      "contribution": 0.41
    }
  ]
}
```

## B.2 Code finding

```json
{
  "finding_id": "finding-code-01J...",
  "finding_type": "code_risk",
  "repository_id": "repo-payments",
  "commit": "25d874c",
  "model_name": "code-transformer",
  "model_version": "2.1.0",
  "calibrated_score": 0.88,
  "categories": [
    "command_execution",
    "authentication"
  ],
  "contributors": [
    {
      "file": "src/auth/session.py",
      "start_line": 104,
      "end_line": 104,
      "contribution": 0.52,
      "summary": "Shell execution introduced with externally influenced input."
    }
  ]
}
```

## B.3 Network finding

```json
{
  "finding_id": "finding-network-01J...",
  "finding_type": "network_anomaly",
  "asset_id": "host-payments-03",
  "service_id": "payments-api",
  "model_name": "flow-transformer",
  "model_version": "1.4.0",
  "calibrated_score": 0.91,
  "contributors": [
    {
      "type": "new_external_peer",
      "destination_category": "external-asn-64500",
      "service": "https",
      "contribution": 0.36
    }
  ]
}
```

## B.4 Metrics finding

```json
{
  "finding_id": "finding-metrics-01J...",
  "finding_type": "metrics_anomaly",
  "asset_id": "host-payments-03",
  "service_id": "payments-api",
  "model_name": "metrics-transformer",
  "model_version": "1.2.0",
  "calibrated_score": 0.87,
  "contributors": [
    {
      "metric": "http.error_rate",
      "observed": 0.082,
      "expected": 0.011,
      "contribution": 0.34
    },
    {
      "metric": "db.pool.utilization",
      "observed": 0.98,
      "expected": 0.61,
      "contribution": 0.27
    }
  ]
}
```

## B.5 Correlated incident

```json
{
  "incident_id": "inc-01J...",
  "title": "Payments API contacted a new external peer after authentication change",
  "status": "open",
  "severity": "critical",
  "risk_score": 0.96,
  "first_seen": "2026-07-26T20:39:00Z",
  "last_seen": "2026-07-26T20:45:00Z",
  "models": [
    "log-transformer",
    "code-transformer",
    "flow-transformer",
    "metrics-transformer"
  ],
  "assets": [
    "host-payments-03"
  ],
  "services": [
    "payments-api"
  ],
  "deployment_id": "deploy-20260726-441",
  "commit": "25d874c",
  "summary": "A newly deployed authentication change was followed by an unexpected privilege event, elevated errors, and first-seen outbound traffic.",
  "disposition": null
}
```

# Appendix C: Research references

The implementation should review and cite the current versions of these primary projects and papers during detailed model design:

1. LogBERT: self-supervised log anomaly detection using BERT-style objectives.
2. LAnoBERT: Transformer-based log anomaly detection.
3. Drain and Drain3: online log-template mining.
4. CodeBERT: pretrained programming-language and natural-language representations.
5. GraphCodeBERT and related graph-aware code models for incorporating structural information.
6. FlowTransformer: Transformer-based network intrusion and flow analysis.
7. Self-supervised network Transformer research incorporating communication topology.
8. OpenTelemetry documentation for logs, metrics, traces, resources, and context propagation.
9. Zeek documentation for connection, DNS, TLS, and HTTP metadata.
10. ONNX Runtime documentation for graph optimization and quantization.
11. MLflow documentation for experiment tracking and model registry.
12. LogHub datasets for log anomaly benchmarks.
13. CICIDS and other licensed network-intrusion datasets for implementation validation.

Public benchmark results must not be treated as proof of production effectiveness. Final thresholds and acceptance decisions must be based on the monitored environment, realistic seeded incidents, and analyst-reviewed pilot outcomes.
