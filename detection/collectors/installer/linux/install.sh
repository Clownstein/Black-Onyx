#!/usr/bin/env bash
# Install osquery + Vector profile for Black Onyx (Linux).
set -euo pipefail
GATEWAY_URL="${AA_GATEWAY_URL:-http://127.0.0.1:8080}"
TENANT_ID="${AA_TENANT_ID:-tenant-demo}"
ASSET_ID="${AA_ASSET_ID:-$(hostname)}"
INGEST_KEY="${AA_INGEST_KEY:-dev-ingest-key}"

echo "Installing osquery (requires root / package manager)…"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  # Prefer distro package; fall back to instructions if unavailable.
  apt-get install -y osquery || echo "Install osquery manually: https://osquery.io/downloads"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
mkdir -p /etc/osquery/packs
cp "$ROOT/osquery/packs/incident_response.conf" /etc/osquery/packs/ || true
cp "$ROOT/osquery/config/linux.conf" /etc/osquery/osquery.conf || true

echo "Export AA_TENANT_ID=$TENANT_ID AA_ASSET_ID=$ASSET_ID AA_INGEST_KEY=***"
echo "Point Vector at $GATEWAY_URL using collectors/vector/profiles/host_state_http.toml"
echo "Enable NTP (chrony/systemd-timesyncd) before production use."
