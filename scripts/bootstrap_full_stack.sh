#!/usr/bin/env bash
# First-launch full platform: TIP + detection + security tools + MISP +
# external CAPEv2 (when CAPE_URL is set) + optional host Wazuh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example — fill secrets before production use"
fi
# .env holds generated credentials (admin password, service keys).
chmod 600 .env

rand_hex() { openssl rand -hex 32; }

ensure_env() {
  local key="$1" value="$2"
  if grep -q "^${key}=" .env; then
    local current
    current="$(grep "^${key}=" .env | head -1 | cut -d= -f2-)"
    if [[ -z "$current" ]]; then
      sed -i "s|^${key}=.*|${key}=${value}|" .env
    fi
  else
    printf '%s=%s\n' "$key" "$value" >> .env
  fi
}

ensure_env BLACK_ONYX_AUTH_SECRET "$(rand_hex)"
ensure_env BLACK_ONYX_DETECTION_TENANT "default"
ensure_env SECURITY_GATEWAY_KEY "$(rand_hex)"
ensure_env SECURITY_RUNNER_TOKEN "$(rand_hex)"
pg_pass="$(rand_hex)"
ensure_env POSTGRES_PASSWORD "$pg_pass"
# Re-read so a pre-existing password wins over the generated one.
pg_pass="$(grep '^POSTGRES_PASSWORD=' .env | head -1 | cut -d= -f2-)"
ensure_env BLACK_ONYX_DATABASE_URL "postgresql+psycopg://anomaly:${pg_pass}@postgres:5432/black_onyx"
ensure_env SECURITY_GATEWAY_DATABASE_URL "postgresql+psycopg://anomaly:${pg_pass}@postgres:5432/security_gateway"
ensure_env BLACK_ONYX_ADMIN_EMAIL "admin@example.com"
ensure_env BLACK_ONYX_ADMIN_PASSWORD "$(rand_hex)"
# Detection service-to-service credentials (compose fails closed without them).
for key in INCIDENT_API_SERVICE_KEY ASSET_REGISTRY_SERVICE_KEY THREAT_INTEL_SERVICE_API_KEY \
  INTEGRATION_HUB_API_KEY MALWARE_SERVICE_API_KEY NOTIFICATION_API_KEY NOTIFICATION_WEBHOOK_SECRET \
  TRAINING_API_KEY TRAINING_ARTIFACT_SIGNING_KEY INFER_API_KEY MODEL_GATEWAY_API_KEY \
  EMBEDDING_API_KEY CODE_ENRICHMENT_API_KEY PROFILE_EVALUATOR_API_KEY PROCESSOR_API_KEY \
  RESPONSE_ORCHESTRATOR_API_KEY RESPONSE_ORCHESTRATOR_APPROVER_API_KEY; do
  ensure_env "$key" "$(rand_hex)"
done
# Ingest gateway accepts a CSV of keys; collectors/shippers use the first one.
ensure_env API_KEYS "$(rand_hex)"
ensure_env BLACK_ONYX_COLLECTOR_INGEST_KEY "$(grep '^API_KEYS=' .env | head -1 | cut -d= -f2- | cut -d, -f1)"
ensure_env MINIO_ROOT_USER "blackonyx"
ensure_env MINIO_ROOT_PASSWORD "$(rand_hex)"
# OpenSearch requires upper, lower, digit and symbol characters.
ensure_env OPENSEARCH_INITIAL_ADMIN_PASSWORD "Bo1!$(rand_hex)"
ensure_env QDRANT_SECURITY__ALLOWED_HOSTS '["web","localhost","127.0.0.1"]'
ensure_env ALLOW_PRIVATE_TARGETS "true"
ensure_env ALLOW_PUBLIC_TARGETS "false"
ensure_env SECURITY_EGRESS_VERIFIED "true"
ensure_env SECURITY_CAPTURE_VERIFIED "true"
ensure_env SECURITY_EGRESS_NETWORK "blackonyx_sandbox_egress"
ensure_env INGEST_GATEWAY_REMOTE_BIND "127.0.0.1"
ensure_env INGEST_GATEWAY_REMOTE_PORT "18091"
ensure_env ASSET_REGISTRY_REMOTE_BIND "127.0.0.1"
ensure_env ASSET_REGISTRY_REMOTE_PORT "18082"
ensure_env BLACK_ONYX_MISP_INTERNAL_HOSTS "misp"
ensure_env SELF_MONITOR_TENANT_ID "${SELF_MONITOR_TENANT_ID:-default}"
ensure_env SELF_MONITOR_HEARTBEAT "true"
ensure_env MISP_DB_PASSWORD "$(rand_hex)"
ensure_env MISP_DB_ROOT_PASSWORD "$(rand_hex)"
ensure_env MISP_ADMIN_EMAIL "$(grep '^BLACK_ONYX_ADMIN_EMAIL=' .env | head -1 | cut -d= -f2-)"
ensure_env MISP_ADMIN_PASSPHRASE "$(rand_hex)"
if ! grep -q '^SECURITY_LAB_PROFILES_JSON=.' .env; then
  ensure_env SECURITY_LAB_PROFILES_JSON '{"anvil":{"network":"blackonyx_anvil","cidrs":["10.88.0.0/24"],"ports":[80,8545]}}'
fi
sessions_root="${ROOT}/.security-sessions"
mkdir -p "$sessions_root"
ensure_env SECURITY_SESSIONS_HOST_ROOT "$sessions_root"

mkdir -p models/Black-Onyx-5B models/tool-router
misp_ssl_dir="${ROOT}/data/misp-ssl"
mkdir -p "$misp_ssl_dir"
if [[ ! -f "$misp_ssl_dir/cert.pem" || ! -f "$misp_ssl_dir/key.pem" ]]; then
  if ! openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$misp_ssl_dir/key.pem" \
    -out "$misp_ssl_dir/cert.pem" \
    -days 3650 \
    -subj "/CN=misp" >/dev/null 2>&1; then
    echo "ERROR: failed to generate data/misp-ssl certs required by docker-compose.misp.yml" >&2
    exit 2
  fi
fi
if [[ ! -f "$misp_ssl_dir/dhparams.pem" ]]; then
  if ! openssl dhparam -out "$misp_ssl_dir/dhparams.pem" 2048 >/dev/null 2>&1; then
    echo "ERROR: failed to generate data/misp-ssl/dhparams.pem required by MISP nginx" >&2
    exit 2
  fi
fi
GGUF="models/Black-Onyx-5B/Black-Onyx-5B-Q8_0.gguf"
if [[ ! -f "$GGUF" ]]; then
  echo "Downloading Black-Onyx-5B GGUF (optional; chat stays unavailable until present)"
  if command -v huggingface-cli >/dev/null 2>&1; then
    huggingface-cli download Clownstein/Black-Onyx-5B-GGUF Black-Onyx-5B-Q8_0.gguf Black-Onyx-5B-mmproj.gguf \
      --local-dir models/Black-Onyx-5B || echo "Model download failed; continuing" >&2
  else
    echo "huggingface-cli not installed; place GGUF files under models/Black-Onyx-5B/" >&2
  fi
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

if [[ -z "${SECURITY_SANDBOX_IMAGE:-}" || -z "${SECURITY_GUARD_IMAGE:-}" ]]; then
  echo "Building security toolbox and guard (digest pin required by the runner)"
  if [[ -f services/security-runner/toolbox-build.env ]]; then
    # shellcheck disable=SC1091
    source services/security-runner/toolbox-build.env
  fi
  docker build --pull=false -f services/security-runner/toolbox.Dockerfile \
    --build-arg TOOLBOX_BASE_IMAGE="$TOOLBOX_BASE_IMAGE" \
    --build-arg DEBIAN_SNAPSHOT="$DEBIAN_SNAPSHOT" \
    --build-arg DEBIAN_SUITE="$TOOLBOX_DEBIAN_SUITE" \
    --build-arg GOBUSTER_DEBIAN_VERSION="$GOBUSTER_DEBIAN_VERSION" \
    --build-arg FOUNDRY_VERSION="$FOUNDRY_VERSION" \
    --build-arg FOUNDRY_SHA256="$FOUNDRY_SHA256" \
    --build-arg SOLC_DOWNLOAD_URL="$SOLC_DOWNLOAD_URL" \
    --build-arg SOLC_SHA256="$SOLC_SHA256" \
    --build-arg NIKTO_VERSION="$NIKTO_VERSION" \
    --build-arg NIKTO_SHA256="$NIKTO_SHA256" \
    --build-arg FILEBYTES_VERSION="$FILEBYTES_VERSION" \
    --build-arg FILEBYTES_SHA256="$FILEBYTES_SHA256" \
    -t blackonyx-security-toolbox:bootstrap .
  docker build --pull=false -f services/security-runner/guard.Dockerfile \
    --build-arg GUARD_BASE_IMAGE="$GUARD_BASE_IMAGE" \
    --build-arg DEBIAN_SNAPSHOT="$DEBIAN_SNAPSHOT" \
    --build-arg DEBIAN_SUITE="$GUARD_DEBIAN_SUITE" \
    -t blackonyx-security-guard:bootstrap .
  toolbox_id="$(docker image inspect blackonyx-security-toolbox:bootstrap --format '{{.Id}}')"
  guard_id="$(docker image inspect blackonyx-security-guard:bootstrap --format '{{.Id}}')"
  ensure_env SECURITY_SANDBOX_IMAGE "blackonyx-security-toolbox@${toolbox_id}"
  ensure_env SECURITY_GUARD_IMAGE "blackonyx-security-guard@${guard_id}"
fi

# Dynamic detonation needs a real CAPEv2 lab reached via CAPE_URL. Without one
# the orchestrator stays not-ready and no dynamic findings are produced.
if [[ -z "${CAPE_URL:-}" ]]; then
  echo "WARNING: CAPE_URL is unset — dynamic malware detonation is disabled" >&2
fi

compose=(
  docker compose
  -f docker-compose.yml
  -f docker-compose.platform.yml
  -f docker-compose.detection-apps.yml
  -f docker-compose.security-tools.yml
  -f docker-compose.security-lab.yml
  -f docker-compose.misp.yml
  -f docker-compose.self-monitor.yml
)

infra=(
  docker compose
  -f docker-compose.yml
  -f docker-compose.platform.yml
  -f docker-compose.security-tools.yml
)

"${infra[@]}" build cli security-gateway
"${infra[@]}" up -d postgres
# Database URLs carry the Postgres password: pass them by name, not on argv.
export ENSURE_DATABASE_URL="postgresql+psycopg://anomaly:${POSTGRES_PASSWORD}@postgres:5432/anomaly"
"${infra[@]}" run --rm --no-deps -e ENSURE_DATABASE_URL --entrypoint /app/.venv/bin/python cli \
  /app/scripts/ensure_postgres_databases.py
"${infra[@]}" run --rm --no-deps -e BLACK_ONYX_DATABASE_URL -e SECURITY_GATEWAY_DATABASE_URL \
  --entrypoint /app/.venv/bin/python cli \
  /app/scripts/migrate_sqlite_to_postgres.py \
  --state-dir /app/.checkpoints \
  --approval-db /app/security-state/approvals.db \
  --challenge-db /app/security-state/challenges.sqlite3

"${compose[@]}" up -d --build

if [[ "${SKIP_ADMIN_BOOTSTRAP:-0}" != "1" ]]; then
  # The generated password lives only in the mode-0600 .env; the Wazuh step
  # uses it to create the connector and issue a push token.
  docker compose -f docker-compose.yml run --rm -T \
    -e BLACK_ONYX_ADMIN_PASSWORD \
    cli users bootstrap-admin \
    --email "$BLACK_ONYX_ADMIN_EMAIL" --password-env BLACK_ONYX_ADMIN_PASSWORD || \
    echo "Admin bootstrap skipped (an administrator may already exist)" >&2
fi

wazuh_cmd=(env INSTALL_WAZUH="${INSTALL_WAZUH:-1}" ENV_FILE="$ROOT/.env" bash "$ROOT/scripts/install_wazuh_host.sh")
if [[ "${INSTALL_WAZUH:-1}" == "1" && "$(id -u)" -ne 0 ]]; then
  # Installing system packages and units needs root; sudo prompts if required.
  wazuh_cmd=(sudo "${wazuh_cmd[@]}")
fi
"${wazuh_cmd[@]}" || echo "Wazuh host step did not complete" >&2
# Pick up WAZUH_REGISTRATION_PASSWORD / WAZUH_API_PASSWORD written by the Wazuh step.
set -a
# shellcheck disable=SC1091
source .env
set +a
"${compose[@]}" up -d web

# Provision the MISP API key for TIP sync once MISP has finished INIT.
if ! grep -q '^MISP_API_KEY=.' .env; then
  echo "Waiting for MISP to accept CLI commands to issue an API key"
  misp_key=""
  for _ in $(seq 1 60); do
    if out="$("${compose[@]}" exec -T misp /var/www/MISP/app/Console/cake user change_authkey "$MISP_ADMIN_EMAIL" 2>/dev/null)"; then
      misp_key="$(printf '%s\n' "$out" | sed -n 's/.*: \([A-Za-z0-9]\{40\}\)[[:space:]]*$/\1/p' | tail -1)"
      [[ -n "$misp_key" ]] && break
    fi
    sleep 10
  done
  if [[ -n "$misp_key" ]]; then
    ensure_env MISP_API_KEY "$misp_key"
    export MISP_API_KEY="$misp_key"
    unset misp_key out
    # Recreate the services that read MISP_API_KEY from the environment.
    "${compose[@]}" up -d web malware-orchestrator
  else
    echo "WARNING: could not issue a MISP API key; set MISP_API_KEY in .env" >&2
  fi
fi

echo "Smoke checks"
smoke_failed=0
smoke() {
  local name="$1"
  shift
  if "$@"; then
    echo "ok   $name"
  else
    echo "FAIL $name" >&2
    smoke_failed=1
  fi
}
retry() {
  local tries="$1"
  shift
  for _ in $(seq 1 "$tries"); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 5
  done
  return 1
}
http_ok() { curl -fsS -o /dev/null --max-time 10 "$1"; }
in_container() {
  local service="$1" url="$2"
  "${compose[@]}" exec -T "$service" /usr/local/bin/python -c \
    "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=10)" "$url"
}

smoke "web API" retry 36 http_ok "http://127.0.0.1:${BLACK_ONYX_PORT:-8000}/api/v1/health"
smoke "ingestion gateway" retry 24 http_ok "http://127.0.0.1:${INGEST_GATEWAY_HOST_PORT:-18090}/health/live"
smoke "asset registry" retry 24 http_ok "http://127.0.0.1:${ASSET_REGISTRY_HOST_PORT:-18081}/health/live"
smoke "security gateway" retry 24 in_container security-gateway http://127.0.0.1:8000/health/ready
if [[ -n "${CAPE_URL:-}" ]]; then
  smoke "malware orchestrator" retry 24 in_container malware-orchestrator http://127.0.0.1:8113/health/ready
else
  smoke "malware orchestrator (detonation disabled)" retry 24 in_container malware-orchestrator http://127.0.0.1:8113/health/live
fi
smoke "MISP" retry 36 http_ok "http://127.0.0.1:${MISP_HOST_PORT:-8088}/users/login"
if [[ -n "${CAPE_URL:-}" ]]; then
  smoke "CAPE detonation" python3 scripts/smoke_malware_lab.py --require --base "$CAPE_URL"
fi
smoke "TIP config + collectors + security tools + MISP sync" \
  python3 scripts/bootstrap_post_deploy.py --tip-url "http://127.0.0.1:${BLACK_ONYX_PORT:-8000}"
if [[ "${INSTALL_WAZUH:-1}" == "1" ]]; then
  smoke "Wazuh manager" systemctl is-active --quiet wazuh-manager
  smoke "Black Onyx shipper" systemctl is-active --quiet black-onyx-shipper
fi

echo "Full stack compose finished (CAPE: ${CAPE_URL:-disabled})"
if [[ "$smoke_failed" -ne 0 ]]; then
  echo "One or more smoke checks failed; see FAIL lines above" >&2
  exit 1
fi
