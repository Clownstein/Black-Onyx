# API

Every route is versioned under `/api/v1`. OpenAPI documentation is disabled in production by default.

## Administrator settings

- `GET /api/v1/admin/settings` returns editable safe configuration and boolean secret-status flags. It never returns secret values or sensitive filesystem paths.
- `PUT /api/v1/admin/settings` validates and hot-applies LLM, RAG, ingestion, chunking, feed, and Qdrant settings. Secret fields are write-only; an empty string removes the stored override and omission leaves it unchanged.

Both endpoints require an authenticated administrator. Updates require CSRF and same-origin validation and create an audit event.

`GET /api/v1/admin/settings` also returns `metadata`: for every editable field its
`desired` (stored runtime override), `effective`, `default`, `source`
(`runtime`, `environment`, `config_file`, `default`), `restart_required` and
`validation`.

### Settings inventory and deployment revisions

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/admin/settings/inventory` | Every application setting and managed deployment setting with desired/effective/source/consumer/restart metadata; secrets report only `configured` |
| `GET` | `/api/v1/admin/deployments?target=compose\|helm` | Revisions (applying revisions are refreshed from the applier) |
| `POST` | `/api/v1/admin/deployments` | Draft `{target, env, values, lab_exception_hours}` |
| `GET` | `/api/v1/admin/deployments/{id}` | One revision |
| `POST` | `/api/v1/admin/deployments/{id}/approve` | `{preview_digest}` must match the draft preview |
| `POST` | `/api/v1/admin/deployments/{id}/reject` | Reject a draft or approved revision |
| `POST` | `/api/v1/admin/deployments/{id}/apply` | Write the signed bundle for the host applier |
| `POST` | `/api/v1/admin/deployments/rollback/{target}` | Draft a revision restoring the previous applied state |

Runbook: [operations/deployment-controller.md](operations/deployment-controller.md).

## Browser security contract

Authentication uses an opaque server-side session cookie (`blackonyx_session`, or `__Host-blackonyx_session` when secure cookies are enabled). Unsafe browser requests require the `X-CSRF-Token` value from the readable `blackonyx_csrf` cookie and an allowed `Origin`. SSE chat uses an authenticated POST body. Ingestion WebSockets use the session cookie and validate `Origin` before accepting.

Machine-authenticated connector push and webhook ingest skip session/CSRF/origin checks **only** when a machine token header is present (`X-Connector-Token`, `X-Webhook-Token`, or `Authorization: Bearer …`). Browser sessions without those headers remain fully CSRF- and origin-protected.

MCP tool servers authenticate with `X-MCP-Service-Key` (not session cookies). A matching `BLACK_ONYX_MCP_SERVICE_KEY` resolves to the configured `BLACK_ONYX_MCP_ACTOR_USER_ID` principal (`admin`/`analyst`); that actor's RBAC applies to subsequent route checks. See [SECURITY.md](SECURITY.md) and [CONFIGURATION.md](CONFIGURATION.md).

Errors use `application/problem+json` with a correlation `request_id`; internal exceptions and secrets are not returned.

## Endpoint groups

| Group | Key endpoints | Minimum role |
|---|---|---|
| Authentication | `/auth/login`, `/auth/logout`, `/auth/me`, `/auth/register`, `/auth/password-*`, `/auth/mfa/*` | Public or authenticated as appropriate |
| Administration | `/admin/users`, `/admin/invitations`, `/admin/attack/refresh`, `/admin/settings` | Admin |
| Backup / continuity | `/admin/backup`, `/admin/backup/inventory`, `/admin/backup/create`, `/admin/backup/restore`, `/admin/backup/upload`, `/admin/backup/{id}/download` | Admin |
| Capabilities | `/health`, `/capabilities`, `/info` | Health public; remaining viewer |
| Jobs and ingestion | `/ingest/upload`, `/ingest/{id}/status`, `/ingest/{id}/stop`, `/jobs`, `/ws/ingest/{id}` | Analyst; server directory admin |
| Search and query | `/search`, `/search/image`, `POST /query` | Viewer for semantic search; query/analyst per RBAC |
| Collections | `/collections`, `/collections/{name}/points` | Viewer; delete admin |
| Chat | `/chat`, `/chat/stream`, `/chat/images`, `/sessions` | Analyst for mutations; owner-only sessions |
| IOC intelligence | `/ioc/*`, `/enrich`, `/threat/score`, `/stix/export` | Analyst for mutations |
| ATT&CK and graphs | `/attack/*`, `/graph/*` | Viewer reads; analyst mutations; refresh admin |
| Rules and reports | `/rules/*`, `/detection-rules/*`, `/reports/*` | Analyst generation; shared viewer-readable reports |
| Cases | `/cases/*` | Viewer reads; analyst mutations |
| Watchlists and alerts | `/watchlists/*`, `/alerts/*`, `/alerts/{id}/disposition`, `/alerts/{id}/promote` | Viewer reads; analyst mutations |
| Triage | `/triage` | Operational roles |
| Connectors / detections | `/connectors`, `/connectors/{id}/poll`, `/connectors/{id}/push-token`, `/connectors/{id}/push`, `/connectors/detections/recent`, `/detections/*` | Admin for connector CRUD; analyst for triage actions |
| Webhooks | `/webhooks`, `/webhooks/events`, webhook event disposition/ack/promote | Admin define; token for ingest |
| Feeds | `/feeds` | Viewer lists, analyst polls, admin defines/deletes |
| Assets | `/assets`, `/assets/findings`, `/assets/posture/board`, `/assets/import/csv` | Viewer reads; analyst mutations |
| Analytics | `/analytics/overview`, `/analytics/timeseries`, `/analytics/distributions`, `/analytics/kpis`, `/analytics/attack/coverage`, `/analytics/cti/impact`, `/analytics/connectors/health`, `/analytics/playbooks`, `/analytics/views` | Viewer reads; admin for role-default views |
| Playbooks | `/playbooks`, `/playbooks/{id}/run` | Viewer lists; analyst run; admin manage |
| Gallery sites | `/sites`, `/sites/{id}/credential`, `/sites/{id}/favicon`, `/sites/{id}/probe` | Authenticated owner scope |
| Collaboration | `/annotations`, `/notes`, `/tags`, `/bookmarks`, `/confidence`, `/ioc-status` | Viewer reads; analyst mutations |
| Decay | `/decay/*` | Viewer reads; analyst score updates |
| Security tools | `/security/health`, `/security/capabilities`, `/security/tools/{name}`, `/security/agent/run` | Analyst+; non-read tools require approval |
| TAXII | TAXII 2.1 discovery/collections under the TAXII router | Per TAXII auth configuration |

Collection pagination returns `next_cursor`; callers must treat it as opaque and return it through the `cursor` query parameter unchanged.

## Detection BFF

Session-authenticated proxies under `/api/v1/detection/*` mint a short-lived detection JWT server-side and forward to detection-plane upstreams (`incident-api`, `asset-registry`, `threat-intel-service`, `integration-hub`, `response-orchestrator`, `notification-service`, `training-orchestrator`, `ingestion-gateway`, `model-gateway`). Defaults are Compose DNS names; override with `BLACK_ONYX_*_URL` when TIP runs on the host ([CONFIGURATION.md](CONFIGURATION.md)). Unreachable upstreams return **502** with `Detection upstream unavailable: …`. Implementation: `src/black_onyx/api/routes_detection.py`.

| Path | Upstream | Notes |
|---|---|---|
| `GET /api/v1/detection/health` | (BFF only) | Viewer+; lists configured upstream **keys** (does not live-ping services) |
| `/api/v1/detection/incident/{path}` | incident-api | Viewer reads; analyst/admin mutations |
| `/api/v1/detection/assets/{path}` | asset-registry | Viewer reads; analyst/admin mutations |
| `/api/v1/detection/ti/{path}` | threat-intel-service | Analyst+; injects `THREAT_INTEL_SERVICE_KEY` |
| `/api/v1/detection/hub/{path}` | integration-hub | Analyst+; injects `INTEGRATION_HUB_API_KEY` |
| `/api/v1/detection/response/{path}` | response-orchestrator | Analyst+; injects `RESPONSE_ORCHESTRATOR_API_KEY` |
| `/api/v1/detection/notify/{path}` | notification-service | Analyst+; injects `NOTIFICATION_API_KEY` |
| `/api/v1/detection/training/{path}` | training-orchestrator | Analyst+ |
| `/api/v1/detection/ingest/{path}` | ingestion-gateway | Analyst+; injects `API_KEYS` |
| `/api/v1/detection/models/{path}` | model-gateway | Analyst+ |
| `POST /api/v1/auth/detection-token` |   | **410 Gone**: browser-held detection JWTs are not supported |

**Operation adapters.** Every mutation the BFF forwards is declared in
`src/black_onyx/api/detection_adapters.py` with the identity fields its upstream
schema expects: `tenant_id` is injected only where the upstream model has it and
stripped elsewhere (tenant then travels in `X-Tenant-Id`); `actor` / `created_by`
are set from the session. Client-supplied identity fields are overwritten or
removed, a conflicting `tenant_id` is **403**, fields a strict upstream model
would reject are **422**, and undeclared mutations are **404**.
`tests/test_detection_adapters.py` checks each adapter against the upstream
Pydantic model.

Promote a detection-plane incident into a TIP case with `POST /api/v1/detection-incidents/promote` (TIP analytics router; not a BFF proxy). Triage promote for watchlist alerts / connector detections / webhook events remains under `/api/v1/alerts|detections|webhook-events/…/promote`.

## Security tools API

The BFF proxies security tool requests to the security gateway. The browser never
talks to the gateway directly. All routes require an authenticated analyst+ session.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/security/health` | Security gateway health |
| `GET` | `/api/v1/security/capabilities` | List all 45 security tools with tiers and schemas |
| `POST` | `/api/v1/security/tools/{name}` | Execute a single tool (non-read tools require approval) |
| `POST` | `/api/v1/security/tools/{name}/preview` | Validate a call and return its `preview_hash` |
| `POST` | `/api/v1/security/tools/{name}/approve` | Exchange a preview for a single-use `approval_id` |
| `POST` | `/api/v1/security/agent/run` | Run the agent loop; pauses with `status=pending_approval` and a `run_id` at the first non-read tool |
| `GET` | `/api/v1/security/agent/runs/{run_id}` | Paused run status (owner only) |
| `POST` | `/api/v1/security/agent/runs/{run_id}/resume` | `{approval_id}` or `{deny: true}` |

Read-tier tools execute without approval; all others require a single-use
approval bound to the previewed request (see [SECURITY.md](SECURITY.md)). Tool
availability and behavior: [SECURITY_TOOLS.md](SECURITY_TOOLS.md).

## Chat API

`POST /api/v1/chat` and `POST /api/v1/chat/stream` accept the following parameters:

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `message` | string | (required) | User message |
| `session_id` | string\|null | null | Session ID (creates new if null) |
| `provider` | string\|null | config default | LLM provider |
| `collections` | string[] | [] | RAG collections to search |
| `use_rag` | bool | true | Enable RAG retrieval |
| `use_web_search` | bool | false | Enable web search (mutually exclusive with MCP) |
| `use_mcp_tools` | bool | false | Enable MCP tool loop (mutually exclusive with web) |
| `purpose` | "chat"\|"investigation"\|null | null | System prompt selection |
| `temperature` | float\|null | null (config default) | Sampling temperature (0.0–2.0) |
| `max_tokens` | int\|null | null (config default) | Max generation tokens (1–32768) |
| `thinking_level` | "OFF"\|"LOW"\|"MEDIUM"\|"HIGH"\|null | null | Thinking instruction for Gemma 4 |
| `system_prompt` | string\|null | null | Override system prompt (plain/RAG only, not MCP) |

Streaming chat returns SSE events: `session`, `token`, `reasoning`, `source`,
`tool`, `done`.

Use the application-generated OpenAPI document in non-production development for exact schemas. Bounded Pydantic models reject invalid identifiers, formats, limits, and payload sizes.

Model catalog rows expose `trainable`, `artifact_state`, aliases, readiness, and an
optional capability reason. `host-state-model` is intentionally inference-only.
Training creation requires `dataset_path` and `dataset_reviewed=true` unless explicit
demo-synthetic mode is enabled; the worker verifies the reviewed file is present and
non-empty before invoking a trainer;
asynchronous creation returns a persisted `queued` job for the training worker.
`run_async=false` is rejected unless the development/test-only synchronous setting is
explicitly enabled.

Notification outbox rows distinguish `pending`, `sent`, `logged-only`, and `failed`,
include attempts/errors, and expose retry only for failed rows. Email requests require an
explicit recipient or server-configured default; no dummy address is substituted.
