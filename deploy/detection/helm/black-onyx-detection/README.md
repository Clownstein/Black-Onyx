# black-onyx-detection Helm chart

Application Deployments/Services for Black Onyx.

## Values profiles

| Overlay | Purpose |
| --- | --- |
| `values.yaml` | Base (lab-friendly defaults) |
| `values-dev.yaml` | `OIDC_DISABLED=true`, demo keys allowed, external TI polling on |
| `values-prod.yaml` | `OIDC_DISABLED=false`, service keys required, **no** demo ingest key in values |
| `values-airgap.yaml` | Disables external TI polling (`airgapMode`); layer on prod |

```bash
# Render with a profile
helm template black-onyx-detection . -f values.yaml -f values-dev.yaml
helm template black-onyx-detection . -f values.yaml -f values-prod.yaml
helm template black-onyx-detection . -f values.yaml -f values-prod.yaml -f values-airgap.yaml
```

## Security / feature flags

| Key | Meaning |
| --- | --- |
| `security.oidcDisabled` | Maps to `OIDC_DISABLED` on incident-api / asset-registry |
| Secret key `oidcHsSecret` | Maps to `OIDC_HS_SECRET` (shared with Black Onyx BFF minting when using HS256) |
| `security.allowDemoKeys` | Dev-only; prod/airgap keep `false`; supply keys via Secret |
| `security.requireServiceKeys` | Prod expectation: workers present `X-Service-Key` |

The external Secret also supplies `codeEnrichmentApiKey` and
`profileEvaluatorApiKey` for the two operator-triggered processing endpoints.
| `featureFlags.externalTiPolling` | When false, blank TAXII/MISP URLs on threat-intel-service |
| `featureFlags.airgapMode` | Sets `THREAT_INTEL_AIRGAP_MODE=true` on threat-intel-service |
| `featureFlags.opensearchIndexing` | Incident-api best-effort OpenSearch writers |
| `externalDependencies.opensearchUrl` | Required `OPENSEARCH_URL`; no Kubernetes localhost/default fallback |
| `threatIntel.airgapMode` / `taxiiUrl` / `mispUrl` | Overlay knobs for threat-intel-service env |

Charted app services include firewall-processor (`8099`), threat-intel-service (`8098`), and integration-hub (`8105`).

Secrets live in `black-onyx-detection-secrets` (chart does not create it). Create the
Secret in every namespace used by the chart. In addition to service/OIDC keys, provide
`assetRegistryDatabaseUrl`, `incidentApiDatabaseUrl`, `integrationHubDatabaseUrl`,
`notificationDatabaseUrl`, `responseDatabaseUrl`, `smokeDatabaseUrl`,
`threatIntelDatabaseUrl`, `trainingDatabaseUrl`, `notificationApiKey`,
`notificationWebhookSecret`, and `trainingArtifactSigningKey`. Optional SMTP password is
`notificationSmtpPassword`; object-backed workflows additionally require
`objectStoreAccessKey` and `objectStoreSecretKey`. Never put live values in committed
values files.

## Model serving

| Key | Meaning |
| --- | --- |
| `modelServing.enabled` | Model replicas serve orchestrator-managed signed packages; promotion waits for replica confirmation |
| `modelServing.tenantId` | Tenant whose aliases this installation serves (required when enabled) |
| `modelServing.sizeLimit` | `emptyDir` size for verified packages per model pod |
| `modelServing.confirmationTimeoutSeconds` | Promotion wait before restoring serving state |

Model pods read `trainingApiKey` and `trainingArtifactSigningKey` from the chart
Secret. `allow-models-to-training-orchestrator` lets the models and application
namespaces reach the orchestrator. Runbook: `docs/operations/model-serving.md`.

Black Onyx web (TIP + detection BFF) is not part of this chart; run it with
Compose and point its upstream URLs at the cluster (see `docs/DEPLOYMENT.md`).
Chart values and Secret keys can be changed through the admin deployment
controller (`docs/operations/deployment-controller.md`).

## External data and model plane

Kafka/Postgres/Redis/OpenSearch/MinIO/Qdrant and trained model artifacts are **not**
bundled in this chart today. Point in-cluster DNS at the external data plane (Compose
uses `redpanda:9092`, `opensearch:9200`, and `qdrant:6333`) and provide reviewed model
artifacts before enabling model/vector workloads. Configure `externalDependencies.*` and
pre-create the PVCs named by `trainingOrchestrator.packageClaimName` and
`trainingOrchestrator.datasetClaimName`; the latter is mounted read-only in the worker.
Helm hook Jobs run
all mirrored Alembic migrations before install/upgrade; failures block rollout. The API
and worker share the training package PVC. `helm template` validation proves only
the manifest contract; it does not prove a cluster rollout, model inference, or Qdrant
readiness. Hunt indices: `detection/docs/operations/opensearch-hunt.md`.
