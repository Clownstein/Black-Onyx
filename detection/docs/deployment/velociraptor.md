# Velociraptor DFIR integration

Black Onyx does **not** embed Velociraptor. Use the platform to **queue** collection
requests; an operator (or Shuffle) fulfills them against a Velociraptor server.

## Architecture

```
Ops console / API
  → POST integration-hub /api/v1/dfir/collect
  → row in dfir_collect_requests (dry-run by default)
  → operator runs VQL / artifact against asset_id
```

## Prerequisites

1. Deploy [Velociraptor](https://docs.velociraptor.app/) (server + clients) on a management network.
2. Map Black Onyx `asset_id` to Velociraptor client id / hostname (inventory join).
3. Prefer read-only artifacts first (`Generic.Client.Info`, process lists) before disk/memory.

## API

```http
POST /api/v1/dfir/collect
Content-Type: application/json

{
  "tenant_id": "tenant-demo",
  "asset_id": "host-checkout-01",
  "incident_id": "inc-…",
  "artifact": "Windows.System.Pslist",
  "dry_run": true
}
```

Unset `VELOCIRAPTOR_URL` → request stays **queued** / dry-run with `queued_external`.
Set `VELOCIRAPTOR_URL` (+ optional `VELOCIRAPTOR_KEY`) on integration-hub and `dry_run: false`
to POST `/api/v1/CollectArtifact` for live submission.

## Safety

- Never auto-execute destructive artifacts from ML scores alone.
- Require incident context + analyst intent; keep dry_run default true in lab.
- Store collection notes / artifact names in the request `detail` / `notes` fields for audit.
