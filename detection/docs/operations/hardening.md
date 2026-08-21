# Hardening notes (Vault / SOPS / cosign / Compose / mTLS / Helm)

Local Compose defaults bind detection datastores to **127.0.0.1** via root `docker-compose.platform.yml`. Demo credentials must not be used without `ALLOW_DEMO_KEYS=true`.

**Never use floating `:latest` image tags.** Prefer pinned tags under `detection/infrastructure/docker-compose/image-pins.yaml`.

## Recommended Compose install (hardened)

```bash
docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d
docker compose -f docker-compose.yml -f docker-compose.platform.yml \
  -f docker-compose.detection-core.yml up -d --build
# Full workers:
docker compose -f docker-compose.yml -f docker-compose.platform.yml \
  -f docker-compose.detection-apps.yml up -d --build
```

Optional overlays (join root Compose `default` network):

| Overlay | Purpose |
| --- | --- |
| `detection/infrastructure/docker-compose/docker-compose.otel.yml` | OTLP collector on loopback |
| `detection/infrastructure/docker-compose/docker-compose.observability.yml` | Grafana/Prometheus/Loki/Tempo |
| `detection/infrastructure/docker-compose/docker-compose.mtls.yml` | Inter-service TLS (legacy path; verify against current package names) |

Kubernetes: Helm chart [`deploy/detection/helm/black-onyx-detection/`](../../../deploy/detection/helm/black-onyx-detection/) with namespaces `black-onyx-*`.

## Secrets

| Concern | Guidance |
| --- | --- |
| Runtime secrets | Inject via Vault / cloud secret manager; never bake keys into images |
| Demo keys | `ALLOW_DEMO_KEYS=true` required for `dev-*` keys |
| Auth | Black Onyx session cookies; detection BFF issues short-lived JWTs — browsers never hold service keys |
