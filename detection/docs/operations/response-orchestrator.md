# Response orchestrator (SOAR)

Human-gated playbook execution. Port **8111**. Default dry-run: `RESPONSE_ORCHESTRATOR_DRY_RUN_DEFAULT=true`.

## Policy

`services/response-orchestrator/response_orchestrator/policy.py` decides whether a request may auto-execute. Vector-only / non-auto signals force:

- `dry_run=true`
- `response_mode=suggest_only`
- Human approve/reject before real action

UI: `/response-queue` (frontend). Related runbooks: `docs/operations/runbooks/isolate-host.md`, `credential-reset.md`, `ti-enrich.md`.

## API

```http
GET  /api/v1/response/pending
POST /api/v1/response/{id}/approve
POST /api/v1/response/{id}/reject
```

Auth: the browser uses the Black Onyx session/CSRF BFF path. The server injects the response service key and tenant scope; no `VITE_*` service key is permitted.

## Verification

1. Create a suggest-only / vector-gated request.
2. Confirm it appears in `GET …/pending` and UI Response queue.
3. Approve or reject; confirm status transition and that dry-run requests do not mutate production systems.
