# Black Onyx documentation

Black Onyx is the shipped threat-intelligence workspace and detection platform
created by **Albert Clownstein**. Attribution: [AUTHORS.md](../AUTHORS.md).

Product name is **Black Onyx**. Python package `black_onyx`. CLIs `black-onyx`
and `black-onyx-web`. Cookies `blackonyx_session` / `blackonyx_csrf`.

## Start here

| Document | Contents |
| --- | --- |
| [../README.md](../README.md) | Product overview, hardware, Compose and host install |
| [FEATURES.md](FEATURES.md) | Analyst workflows, Gallery, Security Lab, detection UI |
| [API.md](API.md) | `/api/v1` HTTP surface (TIP, detection BFF, security tools) |
| [CONFIGURATION.md](CONFIGURATION.md) | `config.yaml`, secrets, BFF URLs, security-tool env |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Compose overlays, Helm, models, production contract |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Tests, local stacks, CI parity |
| [SECURITY.md](SECURITY.md) | Auth, CSRF, SSRF, MCP, sandbox, incident response |
| [SECURITY_TOOLS.md](SECURITY_TOOLS.md) | Per-tool catalog, gates, attestation, egress |
| [DETECTION_PLATFORM.md](DETECTION_PLATFORM.md) | Detection architecture and operating boundaries |
| [DATA_AND_BACKUP.md](DATA_AND_BACKUP.md) | First administrator, systems of record, backup |

## Models and AI

| Document | Contents |
| --- | --- |
| [../MODELS.md](../MODELS.md) | Model inventory, backends, download paths |
| [AI.md](AI.md) | Where models run (TIP, detection, MCP) |
| [BLACK_ONYX_5B_INTEGRATION.md](BLACK_ONYX_5B_INTEGRATION.md) | llama.cpp / vLLM serve and Gemma 4 prompts |
| [operations/qwen3-embeddings.md](operations/qwen3-embeddings.md) | Optional 2560-dim Qwen3 embeddings |
| [operations/model-serving.md](operations/model-serving.md) | Signed packages, promotion, rollback |

## Operations

| Document | Contents |
| --- | --- |
| [operations/backup-restore.md](operations/backup-restore.md) | SQLite + Qdrant backup and restore |
| [operations/deployment-controller.md](operations/deployment-controller.md) | Approved Compose/Helm revisions |
| [operations/response-reconciliation.md](operations/response-reconciliation.md) | SOAR outcome reconciliation |
| [security-acceptance.md](security-acceptance.md) | Image scans and egress acceptance |
| [security-tool-images.md](security-tool-images.md) | Toolbox / guard image build |
| [Detection ops and runbooks](../detection/docs/README.md) | Hunt, collectors, malware lab, ADRs |

## What ships vs what you configure

| Capability | Requirement |
| --- | --- |
| TIP (evidence, CTI, chat, Gallery) | Compose `docker-compose.yml` plus `BLACK_ONYX_AUTH_SECRET` |
| Security Lab | `docker-compose.security-tools.yml`, digest-pinned sandbox image, gateway keys |
| Detection plane | Platform + detection-apps overlays, Postgres/Kafka secrets |
| Vector / federated hunt | Explicit flags plus Qdrant and embedding-worker |
| CAPE / DRAKVUF | Operator-run CAPEv2 (`CAPE_URL`) and/or DRAKVUF Sandbox (`DRAKVUF_URL`) |
| Notifications | Configured provider; otherwise outbox is `logged-only` |
| Network security tools | Operator-verified per-job egress enforcement |
