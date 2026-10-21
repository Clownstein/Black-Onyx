# Configuration

Administrators can change day-to-day runtime configuration from **Administration → Settings**. The browser editor covers LLM provider routing, model names, compatible base URLs, write-only API keys, RAG behavior, ingestion limits and processing defaults, chunking, feed policy, and Qdrant connectivity. Changes are validated, audited, persisted in the canonical state database, and hot-applied to newly initialized services.

Stored secrets are encrypted and are never returned by the API; the UI only reports whether a key is configured. Clearing a UI-managed secret falls back to its deployment environment value. Runtime UI overrides take precedence over YAML/environment values until changed again. Deployment-only security, filesystem roots, SMTP, and model mount paths remain intentionally unavailable in the browser.

Copy `config.example.yaml` to ignored `config.yaml`. Nested settings can be overridden with `QDRANT_` environment variables and double underscores, for example `QDRANT_SECURITY__PRODUCTION=true`. Secrets should use their dedicated environment-variable references instead of YAML values.

## Storage and ingestion

- `storage.state_dir` contains the canonical authentication database, uploads, reports, job history, service databases, and migration backups.
- `ingestion.allowed_data_roots` confines administrator server-directory ingestion.
- `ingestion.max_upload_bytes` and `max_upload_files` bound browser uploads.
- ingestion model, chunking, classifier, NER, OCR, image, and CSV options control the shared document pipeline.

## Authentication and network

- `security.external_url` is the exact browser origin and must be HTTPS in production.
- `allowed_hosts` protects the Host header; `allowed_origins` is for deliberately separate browser origins and defaults empty.
- `trusted_proxies` lists the only proxy CIDRs whose forwarding headers may be honored.
- `auth_secret_env` names the preferred environment variable holding the encryption/token secret (default `BLACK_ONYX_AUTH_SECRET`). Startup fails when neither that name nor `BLACK_ONYX_AUTH_SECRET` is set, including in local development.
- Compose / Vite helpers: `BLACK_ONYX_PORT` (host publish / dev proxy; lab often **8100**), `QDRANT_HTTP_PORT` (lab often **16333**), `BLACK_ONYX_MODEL_DIR`, and production `BLACK_ONYX_EXTERNAL_URL` / `BLACK_ONYX_ALLOWED_HOSTS` / `BLACK_ONYX_HOSTNAME`.
- `secure_cookies`, `session_idle_minutes`, and `session_absolute_hours` control session cookies and expiry.
- `production` enables fail-closed validation; `docs_enabled` does not make documentation public in production.
- MCP machine auth (TIP process and matching `black-onyx-tools` env):

| Environment variable | Purpose |
| --- | --- |
| `BLACK_ONYX_MCP_SERVICE_KEY` | Shared secret; callers send it as `X-MCP-Service-Key`. Empty/unset → MCP auth fails closed. |
| `BLACK_ONYX_MCP_ACTOR_USER_ID` | Active TIP `user_id` whose role (`admin` or `analyst`) is used for RBAC after a successful key match. |
| `BLACK_ONYX_DEFAULT_TENANT_ID` | Required detection tenant sent by the MCP client as `X-Tenant-Id`; there is no implicit tenant fallback. |
| `ALLOW_DEMO_KEYS` | When `1`/`true`/`yes`/`on`, permits demo-shaped MCP service keys (`dev-`, `demo-`, `changeme`, `minioadmin`). Leave unset in production. |

## Providers and RAG

`llm.provider` selects the default. Each chat session binds its provider when created. Provider API-key settings name environment variables. `llm.rag.enabled` controls retrieval; collections, result count, threshold, neighbor window, and the chat system prompt (used for plain, image, and evidence-backed chat) are configured below `llm.rag`.

**Qwen3 AI profile:** copy `config.operator.local.example.yaml` for Qwen3 embeddings via Ollama (2560-dim, collection `all-knowledge-qwen3`) and Black Onyx 5B via `openai_compatible` → `http://127.0.0.1:8081/v1`. `config.example.yaml` uses SentenceTransformers `all-mpnet-base-v2` (768-dim) with collection `all-knowledge`. See [qwen3-embeddings.md](operations/qwen3-embeddings.md).

Enrichment provider names, timeout, concurrency, and cache lifetime are below `enrichment`. Keep actual keys in the provider environment variables. The capability API reports names and availability, never values.

## TIP embeddings

| Setting | Purpose |
| --- | --- |
| `embedding.backend` | `sentence_transformers` (code default) or `ollama` (operator Qwen3 path) |
| `embedding.model_name` / Ollama model tag | Embedder id |
| `embedding.dimensions` | Must match Qdrant collection size (**2560** for Qwen3; **768** for mpnet) |
| `embedding.ollama_base_url` | Default `http://localhost:11434` |
| `ingestion.collection_name` | Default ingest target (`all-knowledge-qwen3` in the Qwen3 profile) |
| `llm.rag.collections` | RAG search collections (keep in step with `ingestion.collection_name`) |

Host Qdrant publish port often remaps via `QDRANT_HTTP_PORT` (lab example **16333**); set `qdrant.port` / `QDRANT_QDRANT__PORT` to match.

## Detection BFF upstream overrides (host TIP)

When TIP runs on the host (outside the Compose network), override Docker DNS defaults before starting `black-onyx-web`:

| Environment variable | Default (Compose DNS) | Host lab example |
| --- | --- | --- |
| `BLACK_ONYX_INCIDENT_API_URL` | `http://incident-api:8083` | `http://127.0.0.1:8083` |
| `BLACK_ONYX_ASSET_REGISTRY_URL` | `http://asset-registry:8081` | `http://127.0.0.1:8081` |
| `BLACK_ONYX_INGEST_URL` | `http://ingestion-gateway:8080` | `http://127.0.0.1:8080` |
| `BLACK_ONYX_THREAT_INTEL_URL` | `http://threat-intel-service:8098` | `http://127.0.0.1:8098` |
| `BLACK_ONYX_INTEGRATION_HUB_URL` | `http://integration-hub:8105` | `http://127.0.0.1:8105` |
| `BLACK_ONYX_RESPONSE_URL` | `http://response-orchestrator:8111` | `http://127.0.0.1:8111` |
| `BLACK_ONYX_NOTIFY_URL` | `http://notification-service:8086` | `http://127.0.0.1:8086` |
| `BLACK_ONYX_TRAINING_URL` | `http://training-orchestrator:8096` | `http://127.0.0.1:8096` |
| `BLACK_ONYX_MODEL_GATEWAY_URL` | `http://model-gateway:8091` | `http://127.0.0.1:8091` |
| `BLACK_ONYX_DETECTION_TENANT` | `default` | tenant id stamped on proxied calls |

Response actions require two distinct server-side secrets. Set
`RESPONSE_ORCHESTRATOR_API_KEY` to one value on the TIP BFF, orchestrator and
integration hub. The orchestrator returns 503 when this key is
unset. `RESPONSE_ORCHESTRATOR_APPROVER_API_KEY` is separate and is the only
credential allowed to change a reviewed request from dry-run to live execution;
never expose either value through `VITE_*` variables.

All other detection service credentials are also fail-closed and have no
predictable defaults. Configure matching producer/consumer values for
`INCIDENT_API_SERVICE_KEY`, `ASSET_REGISTRY_SERVICE_KEY`,
`THREAT_INTEL_SERVICE_API_KEY`, `INTEGRATION_HUB_API_KEY`,
`MALWARE_SERVICE_API_KEY`, `NOTIFICATION_API_KEY`, and `TRAINING_API_KEY`.
Training additionally requires an independent `TRAINING_ARTIFACT_SIGNING_KEY`.
The inference worker's manual score endpoint requires `INFER_API_KEY`.
The model gateway requires `MODEL_GATEWAY_API_KEY`; configure that same value
for the inference worker and TIP BFF producer paths.
The TIP BFF receives only the producer-side names and never exposes them to the
browser.

Publish loopback ports with `docker-compose.detection-lab-ports.yml`. Unreachable upstreams yield **502** `Detection upstream unavailable: ConnectError` on `/incidents`, `/malware`, `/hunt`, etc.

## Settings inventory, deployment controller and retention

`GET /api/v1/admin/settings/inventory` lists every application setting (resolved
from runtime override → `QDRANT_<SECTION>__<FIELD>` env → YAML → default) and every
managed deployment setting from `src/black_onyx/settings_registry.py`, with its
consumer, whether it needs a restart and whether production requires a fixed
value. Deployment settings are changed through revisions:
[operations/deployment-controller.md](operations/deployment-controller.md).

| Variable | Default | Purpose |
| --- | --- | --- |
| `BLACK_ONYX_DEPLOY_HANDOFF_DIR` | (unset) | Directory shared with `scripts/deploy_applier.py`; apply is refused until set |
| `BLACK_ONYX_DEPLOY_SIGNING_KEY` | (unset) | ≥32-char HMAC key for revision bundles (TIP and applier) |
| `BLACK_ONYX_DEPLOY_TWO_PERSON` | `false` | Require a different administrator to approve revisions |
| `BLACK_ONYX_BACKUP_RETENTION` | `7` | Backup archives kept after each backup (`0` keeps all) |
| `BLACK_ONYX_AUDIT_RETENTION_DAYS` | `365` | Audit events older than this are pruned when schedulers start (`0` keeps all) |

## Model serving

Model replicas serve orchestrator-managed signed packages per alias, and
promotion waits for them to confirm. Variables and runbook:
[operations/model-serving.md](operations/model-serving.md).

## Correlation engine synchronous endpoint

`POST /v1/correlate` on the correlation engine creates incidents with the
engine's incident-api credential, so it is disabled by default. Enable it for
golden-scenario testing only with `CORRELATION_SYNC_ENDPOINT_ENABLED=true` and
`CORRELATION_API_KEY`; callers must send `X-API-Key` and `X-Tenant-Id`, and a
body `tenant_id` must match the header.

## Python optional extras

| Extra | Enables |
| --- | --- |
| `dev` | pytest, ruff, mypy, audits (CI baseline) |
| `llm` | `openai`, `anthropic`, `google-genai`, `ollama` |
| `threat-intel` | `feedparser`, TAXII/STIX, markdown/weasyprint reports |
| `image` | CLIP / OCR stack (`open-clip-torch`, Pillow, …) |

In-process `llama-cpp-python` support is not included. Its dependency chain
contains DiskCache releases affected by unsafe pickle deserialization. Run
`llama-server` separately and configure the `openai_compatible` provider to use
its HTTP endpoint; this keeps model execution isolated from the TIP process.

## Feeds and ATT&CK

`feeds.allowed_hosts` is mandatory for network polling. Response bytes and global concurrency are bounded. TAXII feed records store `password_env`; set that named variable in the runtime secret store.

ATT&CK refresh remains disabled until both `threat_intel.mitre_attack_source_url` and the matching SHA-256 digest are configured. The source must be HTTPS and fit `mitre_attack_max_bytes`; no refresh occurs automatically at startup.

## Images

`image.dedup_threshold` controls collection-scoped perceptual-hash matching. CLIP and OCR settings select models/devices. Browser image search and vision chat use temporary bounded uploads; server paths are never accepted from browser requests.

## Security tools (MCP gateway + runner)

The security-tools stack (`docker-compose.security-tools.yml`) catalogs 45
defensive tools, an LLM-backed agent loop, and an ephemeral-container runner.
Tool gates and image attestation control offline-tool availability; network tools
remain disabled until per-job egress is enforced. All browser traffic goes through
the BFF (`/api/v1/security/*`); the browser never talks to the security gateway
directly.

### LLM backend

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLM_BASE_URL` | `http://llama-server:8081` | Main LLM endpoint (security gateway) |
| `LLM_MODEL_NAME` | `Black-Onyx-5B:Q8_0` | Main LLM model name |
| `LLM_TIMEOUT` | `300` | LLM request timeout (seconds) |

### Tool router (optional)

| Variable | Default | Purpose |
| --- | --- |
| `TOOL_ROUTER_ENABLED` | `false` | Enable FunctionGemma first-stage tool router |
| `TOOL_ROUTER_BASE_URL` | `http://tool-router:8080` | Tool router endpoint |
| `TOOL_ROUTER_MODEL` | `functiongemma-270m-it` | Tool router model name |

### Security gateway and runner

| Variable | Required | Purpose |
| --- | --- | --- |
| `SECURITY_GATEWAY_KEY` | yes | Shared secret between BFF and security gateway |
| `SECURITY_RUNNER_TOKEN` | yes | Shared secret between gateway and runner |
| `SECURITY_SANDBOX_IMAGE` | yes | Published toolbox image for ephemeral execution, pinned as `repository@sha256:<digest>` |
| `SECURITY_GUARD_IMAGE` | no | Published nftables/tcpdump helper pinned by digest; network jobs stay unavailable without it |
| `SECURITY_APPROVAL_DB` | no | Gateway SQLite store for single-use approvals and paused agent runs (default `/app/state/approvals.db`; schema is migrated on open) |
| `SECURITY_TWO_PERSON_TIERS` | no | Comma-separated tiers (e.g. `destructive,transaction`) whose approval must come from a different administrator |
| `SECURITY_RUNNER_MAX_JOBS_PER_SESSION` | no | Concurrent runner jobs per session workspace (default `2`, `0` = unlimited); excess returns 429 |
| `SECURITY_RUNNER_WORKSPACE_QUOTA_BYTES` | no | Session workspace size limit checked before each job (default 1 GiB, `0` disables); over quota returns 507 |
| `SECURITY_AGENT_TOOL_HTTP_TIMEOUT` | no | Agent → gateway tool-call timeout in seconds (default `330`, above the 300 s tool maximum) |
| `SECURITY_EGRESS_NETWORK` | no | Dedicated labeled Docker bridge for per-job guarded public egress. The runner never joins this bridge. |
| `SECURITY_EGRESS_VERIFIED` | no | Default `false`; operator attestation after independent packet-escape testing. |
| `SECURITY_CAPTURE_VERIFIED` | no | Separate default `false`; attestation for the trusted registered-lab capture helper. |
| `SECURITY_LAB_PROFILES_JSON` | no | Operator-owned lab IDs, internal Docker network labels, private CIDRs, and allowed TCP ports. |
| `SHODAN_API_KEY` | no | Gateway-only Shodan credential; never sent to executor containers. |
| `BLACK_ONYX_BFF_INTERNAL_URL` | no | Internal TIP BFF origin for the actor-assertion-bound case IOC adapter. |
| `SECURITY_CHALLENGE_PROVIDERS_JSON` | no | Operator-registered challenge IDs with fixed status/submit URLs and exact IPv4 allowlists; submissions are bounded text/JSON and never executed. |
| `SECURITY_CHALLENGE_DB` | no | Persistent SQLite state for the bundled `reference-basic` challenge (Compose uses `/app/state/challenges.sqlite3`). |
| `SECURITY_DOCKER_SOCKET_GID` | no | GID of the Docker socket; the runner container's `group_add` uses this to access `/var/run/docker.sock` |

### Tool gates (fail-closed)

| Variable | Default | Purpose |
| --- | --- | --- |
| `ENABLE_BASH_TOOL` | `false` | Enable `Bash` tool |
| `ENABLE_HYDRA` | `false` | Enable `hydra_brute` |
| `ENABLE_TCPDUMP` | `false` | Enable `tcpdump_capture` |
| `ENABLE_CAST_SEND` | `false` | Enable `cast_send` (blockchain broadcast) |
| `SQLMAP_EXPLOIT_MODE` | `false` | Allow sqlmap exploit mode |

### Target policy

| Variable | Default | Purpose |
| --- | --- | --- |
| `ALLOW_PRIVATE_TARGETS` | `false` | Allow scanning private IPs |
| `ALLOW_PUBLIC_TARGETS` | `false` | Allow security-gateway tools to reach **public** third-party targets outside lab networks (`network_profile=public`). Does not bypass Security Lab profile gating or tool approvals. |
| `ALLOWED_TARGETS` | (empty) | Comma-separated allowlist of scan targets |
| `TOOL_APPROVAL` | `required` | Approval mode for non-read tools |

### Antares (vulnerability localization)

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANTARES_ENDPOINT` | `http://vllm-antares:8000/v1` | Antares completions endpoint (code-enrichment-worker) |

See [MODELS.md](../MODELS.md) for the full model architecture and
[BLACK_ONYX_5B_INTEGRATION.md](BLACK_ONYX_5B_INTEGRATION.md) for LLM serve details.
