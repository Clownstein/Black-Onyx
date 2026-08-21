# Secured API reference

The supported API prefix is `/api/v1`. Legacy unversioned routes are intentionally unsupported. OpenAPI documentation is disabled in production by default.

## Administrator settings

- `GET /api/v1/admin/settings` returns editable safe configuration and boolean secret-status flags. It never returns secret values or sensitive filesystem paths.
- `PUT /api/v1/admin/settings` validates and hot-applies LLM, RAG, ingestion, chunking, feed, and Qdrant settings. Secret fields are write-only; an empty string removes the stored override and omission leaves it unchanged.

Both endpoints require an authenticated administrator. Updates require CSRF and same-origin validation and create an audit event.

## Browser security contract

Authentication uses an opaque server-side session cookie (`blackonyx_session`, or `__Host-blackonyx_session` when secure cookies are enabled). Unsafe browser requests require the `X-CSRF-Token` value from the readable `blackonyx_csrf` cookie and an allowed `Origin`. SSE chat uses an authenticated POST body. Ingestion WebSockets use the session cookie and validate `Origin` before accepting.

Machine-authenticated connector push and webhook ingest skip session/CSRF/origin checks **only** when a machine token header is present (`X-Connector-Token`, `X-Webhook-Token`, or `Authorization: Bearer …`). Browser sessions without those headers remain fully CSRF- and origin-protected.

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
| TAXII | TAXII 2.1 discovery/collections under the TAXII router | Per TAXII auth configuration |

Collection pagination returns `next_cursor`; callers must treat it as opaque and return it through the `cursor` query parameter unchanged.

## Detection BFF

Session-authenticated proxies under `/api/v1/detection/*` mint a short-lived detection JWT server-side and forward to Compose-internal upstreams (`incident-api`, `asset-registry`, `threat-intel-service`, `integration-hub`, `response-orchestrator`, `notification-service`, `training-orchestrator`, `ingestion-gateway`, `model-gateway`). Implementation: `src/black_onyx/api/routes_detection.py`.

| Path | Upstream | Notes |
|---|---|---|
| `GET /api/v1/detection/health` | (BFF only) | Viewer+; lists configured upstream keys |
| `/api/v1/detection/incident/{path}` | incident-api | Viewer reads; analyst/admin mutations |
| `/api/v1/detection/assets/{path}` | asset-registry | Viewer reads; analyst/admin mutations |
| `/api/v1/detection/ti/{path}` | threat-intel-service | Analyst+; injects `THREAT_INTEL_SERVICE_KEY` |
| `/api/v1/detection/hub/{path}` | integration-hub | Analyst+; injects `INTEGRATION_HUB_API_KEY` |
| `/api/v1/detection/response/{path}` | response-orchestrator | Analyst+; injects `RESPONSE_API_KEY` |
| `/api/v1/detection/notify/{path}` | notification-service | Analyst+; injects `NOTIFICATION_API_KEY` |
| `/api/v1/detection/training/{path}` | training-orchestrator | Analyst+ |
| `/api/v1/detection/ingest/{path}` | ingestion-gateway | Analyst+; injects `API_KEYS` |
| `/api/v1/detection/models/{path}` | model-gateway | Analyst+ |
| `POST /api/v1/auth/detection-token` | — | **410 Gone** — browser-held detection JWTs are not supported |

Promote a detection-plane incident into a TIP case with `POST /api/v1/detection-incidents/promote` (TIP analytics router; not a BFF proxy). Triage promote for watchlist alerts / connector detections / webhook events remains under `/api/v1/alerts|detections|webhook-events/…/promote`.

Use the application-generated OpenAPI document in non-production development for exact schemas. Bounded Pydantic models reject invalid identifiers, formats, limits, and payload sizes.
