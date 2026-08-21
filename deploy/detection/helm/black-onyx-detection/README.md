# black-onyx-detection Helm chart

Application Deployments/Services for Black Onyx. Parent notes: [`AGENTS.md`](AGENTS.md), [`../AGENTS.md`](../AGENTS.md).

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
| `security.allowDemoKeys` | Dev-only; prod/airgap keep `false` — supply keys via Secret |
| `security.requireServiceKeys` | Prod expectation: workers present `X-Service-Key` |
| `featureFlags.externalTiPolling` | When false, blank TAXII/MISP URLs on threat-intel-service |
| `featureFlags.airgapMode` | Sets `THREAT_INTEL_AIRGAP_MODE=true` on threat-intel-service |
| `featureFlags.opensearchIndexing` | Incident-api best-effort OpenSearch writers |
| `opensearch.url` | `OPENSEARCH_URL` (default `http://opensearch:9200`) |
| `threatIntel.airgapMode` / `taxiiUrl` / `mispUrl` | Overlay knobs for threat-intel-service env |

Charted app services include firewall-processor (`8099`), threat-intel-service (`8098`), and integration-hub (`8105`).

Secrets live in `black-onyx-detection-secrets` (chart does not create it). Never put live ingest keys or OIDC HS secrets in values files.

## External data and model plane

Kafka/Postgres/Redis/OpenSearch/MinIO/Qdrant and trained model artifacts are **not**
bundled in this chart today. Point in-cluster DNS at the external data plane (Compose
uses `redpanda:9092`, `opensearch:9200`, and `qdrant:6333`) and provide reviewed model
artifacts before enabling model/vector workloads. `helm template` validation proves only
the manifest contract; it does not prove a cluster rollout, model inference, or Qdrant
readiness. See `docs/operations/opensearch-hunt.md` for hunt indices.
