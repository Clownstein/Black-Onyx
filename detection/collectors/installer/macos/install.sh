#!/usr/bin/env bash
# Install osquery + Vector profile for Black Onyx (macOS).
set -euo pipefail
GATEWAY_URL="${AA_GATEWAY_URL:-http://127.0.0.1:8080}"
TENANT_ID="${AA_TENANT_ID:-tenant-demo}"
ASSET_ID="${AA_ASSET_ID:-$(hostname)}"
INGEST_KEY="${AA_INGEST_KEY:-dev-ingest-key}"

echo "Installing osquery (requires Homebrew)…"
if command -v brew >/dev/null 2>&1; then
  brew install --cask osquery || echo "Install osquery manually: https://osquery.io/downloads"
else
  echo "Homebrew not found; install osquery manually: https://osquery.io/downloads"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
sudo mkdir -p /var/osquery/packs
sudo cp "$ROOT/osquery/packs/incident_response.conf" /var/osquery/packs/ || true
sudo cp "$ROOT/osquery/config/darwin.conf" /var/osquery/osquery.conf || true

echo "Export AA_TENANT_ID=$TENANT_ID AA_ASSET_ID=$ASSET_ID AA_INGEST_KEY=***"
echo "Point Vector at $GATEWAY_URL using collectors/vector/profiles/host_state_http.toml"
echo "Enable automatic time sync (System Settings → Date & Time) before production use."
