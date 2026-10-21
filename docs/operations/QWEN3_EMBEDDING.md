# Qwen3 embeddings (TIP plane)

Black Onyx embeds TIP evidence with SentenceTransformers `all-mpnet-base-v2` (768-dim) by default. The Qwen3 profile uses **2560-dim** Qwen3-Embedding-4B served by Ollama for higher-quality retrieval.

Choose the embedding backend before the first ingest: vectors of different dimensions cannot share a Qdrant collection. Detection SecureBERT collections (`findings_v1`, etc.) always stay **768-dim**; this guide covers the TIP plane only.

## Prerequisites

1. Ollama running with a stable Qwen3 embed tag:

```bash
# Preferred (HF GGUF registry via Ollama):
ollama pull hf.co/Qwen/Qwen3-Embedding-4B-GGUF:Q4_K_M
# Alternates:
# ollama pull dengcao/Qwen3-Embedding-4B:Q4_K_M
# ollama pull batiai/qwen3-embedding:4b
```

2. Configure the Qwen3 profile in `config.yaml` (or copy [`config.operator.local.example.yaml`](../../config.operator.local.example.yaml) / [`config.qwen3-ollama.example.yaml`](../../config.qwen3-ollama.example.yaml)):

```yaml
embedding:
  backend: ollama
  model_name: hf.co/Qwen/Qwen3-Embedding-4B-GGUF:Q4_K_M
  ollama_base_url: http://localhost:11434
  dimensions: 2560
```

Check that Ollama serves embeddings before starting Black Onyx:

```powershell
uv run python scripts/smoke_ollama_ai_platform.py
```

3. **Docker:** point the TIP container at host Ollama:

```env
QDRANT_EMBEDDING__OLLAMA_BASE_URL=http://host.docker.internal:11434
```

## New deployment

With the profile above in `config.yaml`, set the TIP collection names before the first start:

```yaml
ingestion:
  collection_name: all-knowledge-qwen3
llm:
  rag:
    collections: ["all-knowledge-qwen3"]
```

Start Black Onyx and verify:

- `GET /api/v1/capabilities` → `embedding.backend=ollama`, `dimensions=2560`
- The Qdrant collection vector size is **2560**

## Switching an existing deployment

To move evidence that is already embedded at 768 dimensions, re-index it into a new collection:

1. **Dry-run** re-index (counts points, no writes):

```powershell
uv run python scripts/reindex_tip_collections.py `
  --source all-knowledge `
  --target all-knowledge-qwen3 `
  --config config.yaml `
  --dry-run
```

2. **Re-index** into a new collection (recommended suffix `-qwen3`):

```powershell
# From existing Qdrant payloads (body_text/text):
uv run python scripts/reindex_tip_collections.py `
  --source all-knowledge `
  --target all-knowledge-qwen3 `
  --config config.yaml

# If all-knowledge is empty, re-embed feed collections (repeatable --source):
uv run python scripts/reindex_tip_collections.py `
  --source feed-MSRC-Security-Updates `
  --source feed-Microsoft-Security-Blog `
  --target all-knowledge-qwen3 `
  --config config.yaml

# Or re-chunk from an ingest directory:
uv run python scripts/reindex_tip_collections.py `
  --from-ingest-dir ./data `
  --target all-knowledge-qwen3 `
  --config config.yaml
```

3. Update config to use the new collection (manual or apply helper):

```powershell
uv run python scripts/cutover_embedding_collection.py `
  --target all-knowledge-qwen3 `
  --config config.yaml `
  --apply
```

```yaml
ingestion:
  collection_name: all-knowledge-qwen3
llm:
  rag:
    collections: ["all-knowledge-qwen3"]
```

4. Restart TIP and verify:

- `GET /api/v1/capabilities` → `embedding.backend=ollama`, `dimensions=2560`
- Semantic search and RAG chat return results from the new collection
- Qdrant collection vector size is **2560** (not 768)

5. After validation, delete or archive the **768-dim** TIP collections (feeds included) so ingest recreates them at 2560.

## Rollback

Set `embedding.backend: sentence_transformers`, point `ingestion.collection_name` and `llm.rag.collections` back at the 768-dim collection, and restart TIP.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Dimension mismatch errors in logs | Wrong collection still on 768-dim; re-run reindex or pick new target name |
| Ollama connection errors from Docker | Use `host.docker.internal:11434` (see `docker-compose.yml` comments) |
| Empty search after switching | Confirm RAG `collections` list matches `ingestion.collection_name` |
