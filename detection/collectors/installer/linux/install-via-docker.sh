#!/usr/bin/env bash
# Rootless host install helper: privileged container + nsenter into host PID 1.
# Used when the operator cannot sudo interactively but can run Docker.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ASSET_ID="${BLACK_ONYX_COLLECTOR_ASSET_ID:-$(hostname -s 2>/dev/null || hostname)}"
: "${BLACK_ONYX_COLLECTOR_TENANT_ID:?BLACK_ONYX_COLLECTOR_TENANT_ID required}"
: "${BLACK_ONYX_COLLECTOR_INGEST_KEY:?BLACK_ONYX_COLLECTOR_INGEST_KEY required}"
: "${BLACK_ONYX_COLLECTOR_GATEWAY_URL:?BLACK_ONYX_COLLECTOR_GATEWAY_URL required}"
# Secrets pass to docker by name only so they never appear in argv.
export ASSET_REGISTRY_SERVICE_KEY="${ASSET_REGISTRY_SERVICE_KEY:-}"

docker run --rm --privileged --pid=host --network host \
  -v /:/host \
  -v "${ROOT}:/collectors:ro" \
  -e BLACK_ONYX_COLLECTOR_TENANT_ID \
  -e BLACK_ONYX_COLLECTOR_INGEST_KEY \
  -e BLACK_ONYX_COLLECTOR_GATEWAY_URL \
  -e BLACK_ONYX_COLLECTOR_ASSET_ID="${ASSET_ID}" \
  -e BLACK_ONYX_COLLECTOR_HOSTNAME="${BLACK_ONYX_COLLECTOR_HOSTNAME:-$ASSET_ID}" \
  -e BLACK_ONYX_COLLECTOR_OS_FAMILY="${BLACK_ONYX_COLLECTOR_OS_FAMILY:-linux}" \
  -e BLACK_ONYX_COLLECTOR_ID="${BLACK_ONYX_COLLECTOR_ID:-osquery-$ASSET_ID}" \
  -e ASSET_REGISTRY_URL="${ASSET_REGISTRY_URL:-}" \
  -e ASSET_REGISTRY_SERVICE_KEY \
  -e BLACK_ONYX_COLLECTOR_ENVIRONMENT="${BLACK_ONYX_COLLECTOR_ENVIRONMENT:-production}" \
  -e DEBIAN_FRONTEND=noninteractive \
  ubuntu:24.04 \
  bash /collectors/installer/linux/install-in-container.sh
