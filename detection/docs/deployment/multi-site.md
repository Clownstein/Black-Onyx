# Multi-site deployment (`site_id`)

Large environments often run collectors and correlation per **site** (DC, plant, region)
while presenting a unified ops console.

## Convention

- Tag ingested envelopes and correlated incidents with `context.site_id` (string), e.g.
  `us-east-1`, `plant-a`, `soc-lab`.
- Prefer stable site ids; avoid embedding secrets in the id.
- Collectors / Vector remaps should stamp `site_id` early (host label or static transform).

## Incident list filter

`incident-api` accepts:

```http
GET /api/v1/incidents?site_id=plant-a
```

Filtering matches `IncidentRow.context["site_id"]` (JSON). Correlation should copy site
from findings into incident `context` when present.

## Federation notes

- Per-site stacks may use separate Kafka / Postgres; federation is **search/list** via
  shared tenant + `site_id`, not automatic cross-DB joins in Phase 3.
- Keep `X-Tenant-Id` as the hard tenancy boundary; `site_id` is an operational facet.
