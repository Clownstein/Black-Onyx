# Qdrant vector search (ops)

Optional similarity plane. Postgres is SoR; OpenSearch is full-text hunt. Shared Black Onyx `qdrant` only (no second instance).

## Enable

```bash
# Platform + detection apps; embedding-worker is behind Compose profile `vector`
docker compose -f docker-compose.yml -f docker-compose.platform.yml \
  -f docker-compose.detection-apps.yml --profile vector up -d
```

Point services at `QDRANT_URL=http://qdrant:6333` (containers) or `http://127.0.0.1:6333` (host).

| Env | Default | Notes |
| --- | --- | --- |
| `QDRANT_URL` | `http://qdrant:6333` (Compose) | Shared TIP Qdrant |
| `VECTOR_SEARCH_ENABLED` | `false` | incident-api similar + vector hunt |
| `FEDERATED_HUNT_ENABLED` | `false` | `POST /api/v1/hunt/federated` |
| `VECTOR_NOVELTY_ENABLED` | `false` | correlation / profile-evaluator |
| `EMBEDDING_EMBED_MODEL` | `cisco-ai/SecureBERT2.0-biencoder` | Real SentenceTransformer model; readiness fails when it cannot load |

Ports: Qdrant **6333** / **6334**; embedding-worker **8115**.

## Seed ATT&CK technique vectors

```powershell
uv run python detection/scripts/development/restore_qdrant_attack_tech.py --dry-run
uv run python detection/scripts/development/restore_qdrant_attack_tech.py
```

## Verify

1. `curl http://127.0.0.1:6333/readyz`
2. With flags on: similar findings / federated hunt against incident-api (`:8083`) with `X-Tenant-Id` (via Black Onyx BFF in product UI).
