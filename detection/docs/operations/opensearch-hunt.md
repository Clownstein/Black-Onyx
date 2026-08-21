# OpenSearch hunt plane

Black Onyx (formerly AutoAnalyzer) indexes findings and incidents into OpenSearch for analyst hunts. Postgres remains the system of record; OpenSearch is best-effort search.

## Endpoints / config

| Setting | Default | Notes |
| --- | --- | --- |
| `OPENSEARCH_URL` | `http://localhost:9200` (host) / `http://opensearch:9200` (Compose) | Used by incident-api |
| `INCIDENT_API_OPENSEARCH_INDEXING` | `true` | Set `false` to disable writers |

Writers: `services/incident-api/incident_api/opensearch_client.py` on finding/incident create & update. Failures are logged and **never** fail the HTTP request.

Hunt proxy (via Black Onyx Detection BFF — session cookie + CSRF; JWT minted server-side):

```http
GET /api/v1/detection/incident/api/v1/hunt/search?q=
```

Do not call raw `incident-api:8083` from the browser without a detection JWT. For complex hunts prefer **OpenSearch Dashboards** or Grafana.

## Index naming

| Pattern | Contents |
| --- | --- |
| `aa-findings-YYYY.MM.DD` | Finding documents (`doc_type=finding`) |
| `aa-incidents-YYYY.MM.DD` | Incident documents (`doc_type=incident`) |

Alias wildcards for queries: `aa-findings-*`, `aa-incidents-*`.

Documents include `@timestamp`, `tenant_id`, ids, severity/scores, title/summary, and optional MITRE fields when present on the payload.

## Example queries

```http
GET aa-findings-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "tenant_id.keyword": "tenant-acme" } },
        { "match": { "title": "egress" } }
      ]
    }
  }
}
```

```http
GET aa-incidents-*/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "tenant_id.keyword": "tenant-acme" } },
        { "term": { "severity.keyword": "high" } }
      ]
    }
  }
}
```

```bash
# Via Black Onyx Detection BFF (session cookie + CSRF on unsafe methods)
curl -s -b "blackonyx_session=…" \
  "https://blackonyx.example/api/v1/detection/incident/api/v1/hunt/search?q=powershell"
```

## Grafana datasource

Compose observability already provisions an OpenSearch datasource at `http://opensearch:9200`
(`infrastructure/docker-compose/grafana/provisioning/datasources/datasources.yml`, uid `opensearch`).
Point Explore / panels at index patterns `aa-findings-*` and `aa-incidents-*` with time field `@timestamp`.

See also `docs/operations/grafana-assistants.md`.

## Federated hunt (OpenSearch + Qdrant + TI)

When `FEDERATED_HUNT_ENABLED=true` (and optionally `VECTOR_SEARCH_ENABLED=true`):

```http
POST /api/v1/detection/incident/api/v1/hunt/federated
```

Merges OpenSearch hits with Qdrant similarity (`findings_v1` / `incidents_v1`) and threat-intel exact/semantic matches. UI Hunt page supports **Federated** mode. Soft-fail each source independently.

Similar entity APIs (require vector search; same BFF prefix):

```http
GET /api/v1/detection/incident/api/v1/findings/{id}/similar
GET /api/v1/detection/incident/api/v1/incidents/{id}/similar
POST /api/v1/detection/incident/api/v1/hunt/vector
```

See `docs/operations/qdrant-vector-search.md`.

## ISM retention (notes)

OpenSearch Index State Management (ISM) should roll daily indices and delete after retention:

1. Hot: write to `aa-findings-YYYY.MM.DD` / `aa-incidents-YYYY.MM.DD`.
2. After N days (e.g. 30): transition to warm / read-only (optional).
3. After R days (e.g. 90): delete.

Example policy sketch (apply via Dev Tools; tune for your cluster):

```json
{
  "policy": {
    "description": "aa-findings retention",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          { "state_name": "delete", "conditions": { "min_index_age": "90d" } }
        ]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }],
        "transitions": []
      }
    ]
  }
}
```

Attach the policy to index patterns `aa-findings-*` and `aa-incidents-*`. Align Kafka topic retention separately (`redpanda.log_retention_ms` in Compose is intentionally short for lab).

## Dashboards-only path

If the hunt API is unused, analysts can:

1. Open OpenSearch Dashboards (or Grafana Explore → OpenSearch).
2. Create index patterns `aa-findings-*` / `aa-incidents-*`.
3. Save searches filtered by `tenant_id`.

Writers still populate indices whenever incident-api is up and OpenSearch is reachable.

## Ops console Hunt page

The frontend route `/hunt` calls the Detection BFF path
`GET /api/v1/detection/incident/api/v1/hunt/search` (mock mode searches in-memory
findings/incidents). Live mode requires OpenSearch reachable from incident-api.
