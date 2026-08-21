#!/usr/bin/env bash
# Phase 0 local bootstrap (Unix).
# From repo root: ./detection/scripts/development/bootstrap.sh
# Prefer: docker compose -f docker-compose.yml -f docker-compose.platform.yml up -d

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

COMPOSE_ARGS=(-f docker-compose.yml -f docker-compose.platform.yml)
BROKERS="${KAFKA_BOOTSTRAP_SERVERS:-localhost:19092}"

echo "==> Ensuring Kafka topics on ${BROKERS}"
for topic in logs.raw logs.raw.dlq; do
  docker compose "${COMPOSE_ARGS[@]}" exec -T redpanda \
    rpk topic create "$topic" --brokers redpanda:9092 \
    >/dev/null 2>&1 || echo "    topic create skipped or already exists: ${topic}"
done

echo "==> uv sync (workspace)"
if command -v uv >/dev/null 2>&1; then
  uv sync --all-packages --extra dev
else
  echo "uv not found; falling back to pip editable installs" >&2
  python -m pip install -U pip
  python -m pip install -e "packages/black_onyx_contracts"
  python -m pip install -e "services/asset-registry[dev]"
  python -m pip install -e "services/smoke-consumer"
  python -m pip install -e "services/incident-api[dev]"
  python -m pip install -e ".[dev]"
fi

echo "==> Alembic upgrade asset-registry"
(
  cd "$ROOT/services/asset-registry"
  if command -v uv >/dev/null 2>&1; then
    uv run alembic upgrade head
  else
    alembic upgrade head
  fi
)

echo "==> Alembic upgrade incident-api"
(
  cd "$ROOT/services/incident-api"
  if command -v uv >/dev/null 2>&1; then
    uv run alembic upgrade head
  else
    alembic upgrade head
  fi
)

echo "==> Bootstrap complete"
