# Model promotion, serving and rollback

Model aliases (`champion`, `canary`, `shadow`) describe what model replicas are
**actually serving**, not just a database label.

```
promote ─▶ verify signed package ─▶ write desired serving row ─▶ replicas pull + verify + load
        ─▶ every live replica reports the exact package ─▶ move model_aliases row
        └─ any load error / timeout ─▶ restore desired row, 502, alias unchanged
```

## Pieces

| Piece | Where |
| --- | --- |
| Serving registry + replica sync | `packages/black_onyx_model_package/src/black_onyx_model_package/serving.py` |
| Desired state, reports, two-phase commit | `services/training-orchestrator/training_orchestrator/serving.py` |
| Serving tables (migration `0004`) | `model_serving_desired`, `model_serving_instances` |
| Model services using the registry | log, network, metrics and code models (`detection/models/*/inference/app.py`) |
| Gateway routing against confirmed state | `services/model-gateway/model_gateway/serving_state.py` |

Host-state is a rules-based pass-through with no trained package, so it is not
managed by serving sync.

## Orchestrator API (service key + `X-Tenant-Id`)

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/serving/{model}/desired` | Alias → version + package signature (polled by replicas) |
| `POST` | `/api/v1/serving/{model}/report` | Replica report: loaded slots and load errors |
| `GET` | `/api/v1/serving/{model}` | Desired vs confirmed per alias |
| `GET` | `/api/v1/models/{model}/versions/{version}/package` | Signed package tar (verified before sending) |

Promotion (`POST …/versions/{v}/promote`) and champion rollback (`POST …/rollback`)
return **502** with `serving state restored` when replicas do not confirm.

## Replica behavior

- Replicas poll every `MODEL_SERVING_INTERVAL_S` (default 15 s), download any
  package they are not serving, verify signature, identity and version, load it
  through the service's own loader, and swap it into the alias slot atomically.
- A package that fails verification or loading is never served; the replica
  keeps its previous package and reports the error, which fails the promotion
  immediately.
- Canary and shadow fall back to the champion package when no separate package
  is loaded. The gateway only routes canary traffic to a *confirmed* canary.
- With `MODEL_SERVING_ENABLED=true`, prediction returns **503** until a signed
  package is loaded; the baked image artifact is used only when serving is off
  (development).
- Each response from the gateway carries `serving.expected_version`,
  `serving.served_version` and `serving.version_verified`.

## Configuration

| Variable | Service | Default |
| --- | --- | --- |
| `MODEL_SERVING_ENABLED` | model services | `true` in Compose/Helm |
| `MODEL_SERVING_ROOT` | model services | `/var/lib/black-onyx/model-serving` (tmpfs / emptyDir) |
| `MODEL_SERVING_ORCHESTRATOR_URL` | model services | training-orchestrator URL |
| `MODEL_SERVING_API_KEY` | model services | `TRAINING_API_KEY` |
| `MODEL_SERVING_TENANT` | model services | `BLACK_ONYX_DETECTION_TENANT` / `modelServing.tenantId` |
| `MODEL_SERVING_SIGNING_KEY` | model services | `TRAINING_ARTIFACT_SIGNING_KEY` |
| `TRAINING_ORCHESTRATOR_SERVING_CONFIRMATION_REQUIRED` | orchestrator | `true` |
| `TRAINING_ORCHESTRATOR_SERVING_CONFIRM_TIMEOUT_SECONDS` | orchestrator | `180` |
| `TRAINING_ORCHESTRATOR_SERVING_INSTANCE_TTL_SECONDS` | orchestrator | `90` (replica liveness window) |
| `TRAINING_ORCHESTRATOR_SERVING_MIN_INSTANCES` | orchestrator | `1` |
| `TRAINING_ORCHESTRATOR_URL`, `TRAINING_API_KEY`, `SERVING_TENANT` | model-gateway | serving-state lookups |

Helm: `modelServing.enabled`, `modelServing.tenantId`, `modelServing.sizeLimit`,
`modelServing.confirmationTimeoutSeconds`; a NetworkPolicy lets the models and
application namespaces reach the training orchestrator.

## Runbook

1. Train on a reviewed dataset; the job produces a signed package and a
   `candidate` alias.
2. Promote to `canary` first; confirm `GET /api/v1/serving/{model}` shows
   `confirmed: true` and watch gateway `serving.version_verified`.
3. Promote to `champion`. If replicas cannot load it, the call fails with 502
   and nothing changes.
4. Roll back with `POST /api/v1/models/{model}/versions/{current}/rollback`;
   the previous package must still verify and load.

## Deployment validation

Before production rollout, validate the selected model artifacts, hardware
capacity, package download and load times, replica health window, and canary
traffic profile in the target environment. The serving protocol rejects
unconfirmed or unverifiable packages; production capacity and latency depend on
the model, hardware, and cluster configuration.
