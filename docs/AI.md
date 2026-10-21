# AI usage

Black Onyx runs two ML planes against **one Qdrant instance**. Generation LLMs
are not on the Kafka scoring path.

| Plane | System of record | Models |
| --- | --- | --- |
| TIP | SQLite + Qdrant | Text/image embeddings, RAG, chat, NER, optional classifier |
| Detection | Kafka + Postgres + Qdrant | Modality scorers, SecureBERT vectors, optional Antares enrichment |

Inventory, files, and download steps: [MODELS.md](../MODELS.md). Serve notes for
the 5B chat model: [BLACK_ONYX_5B_INTEGRATION.md](BLACK_ONYX_5B_INTEGRATION.md).

## TIP generation

Configured in `config.yaml` (`llm.provider`) and routed by
`src/black_onyx/llm/factory.py`.

| Provider | Backend |
| --- | --- |
| `local` | Ollama chat |
| `openai` / `openai_compatible` | OpenAI API or llama.cpp / vLLM / LM Studio |
| `claude` / `gemini` | Anthropic / Google |

**Black Onyx 5B** is the shipped cybersecurity LLM. Lab and Compose serve it with
llama.cpp (`llama-server`, GGUF). Point `openai_compatible` at
`http://llama-server:8081/v1` (Compose) or `http://127.0.0.1:8081/v1` (host).

Surfaces: `/chat`, Security Lab agent, investigation assist, reports, malware
summaries. MCP tools and web search are mutually exclusive on a single chat turn.

## TIP embeddings

| Backend | Dimension | When |
| --- | --- | --- |
| SentenceTransformers `all-mpnet-base-v2` | 768 | Default in `config.example.yaml` |
| Ollama **Qwen3-Embedding-4B** | 2560 | Operator profile (`config.operator.local.example.yaml`) |

Each dimension needs its own Qdrant collections, so pick the backend before the
first ingest. Setup and switching guide:
[operations/qwen3-embeddings.md](operations/qwen3-embeddings.md).

Images use OpenCLIP (`ViT-B-32`). NER uses GLiNER. The ingest classifier is off
by default.

## Detection scorers

Kafka `*.features` → `inference-worker` → `model-gateway` → modality HTTP
`/v1/predict` → `findings.*` → correlation → incidents.

| Service | Role |
| --- | --- |
| `log-model` | Log template-sequence Transformer |
| `network-model` | Flow Transformer |
| `metrics-model` | Metric Transformer (+ Isolation Forest) |
| `code-model` | Change-risk scorer |
| `host-state-model` | Rules-based, inference-only (no trained package) |
| `malware-static` | EMBER ONNX inside `malware-triage` |

Optional **Antares-1B** (vLLM) enriches code findings off the hot path.
**SecureBERT 2.0** (768-d) embeds findings/incidents/TI when vector search is on.

## Feature flags

| Flag | Default | Effect |
| --- | --- | --- |
| `VECTOR_SEARCH_ENABLED` | off | Similar findings, vector hunt |
| `FEDERATED_HUNT_ENABLED` | off | OpenSearch + Qdrant + TI merge |
| `VECTOR_NOVELTY_ENABLED` | off | Novelty signal in correlation / profiles |

LLM text is advisory. It does not approve SOAR actions or replace deterministic
detection.
