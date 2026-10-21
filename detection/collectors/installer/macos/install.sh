#!/usr/bin/env bash
# Install osquery + Black Onyx shipper on macOS (run with sudo).
# Works from the repo tree or from a downloaded collector package ZIP.
#
# Required env:
#   BLACK_ONYX_COLLECTOR_TENANT_ID, BLACK_ONYX_COLLECTOR_INGEST_KEY, BLACK_ONYX_COLLECTOR_GATEWAY_URL
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run with sudo" >&2
  exit 1
fi

GATEWAY_URL="${BLACK_ONYX_COLLECTOR_GATEWAY_URL:-}"
TENANT_ID="${BLACK_ONYX_COLLECTOR_TENANT_ID:-}"
ASSET_ID="${BLACK_ONYX_COLLECTOR_ASSET_ID:-$(scutil --get LocalHostName 2>/dev/null || hostname -s)}"
HOSTNAME_VAL="${BLACK_ONYX_COLLECTOR_HOSTNAME:-$ASSET_ID}"
INGEST_KEY="${BLACK_ONYX_COLLECTOR_INGEST_KEY:-}"
COLLECTOR_ID="${BLACK_ONYX_COLLECTOR_ID:-osquery-$ASSET_ID}"
OS_FAMILY="${BLACK_ONYX_COLLECTOR_OS_FAMILY:-darwin}"

if [[ -z "$TENANT_ID" || -z "$INGEST_KEY" || -z "$GATEWAY_URL" ]]; then
  echo "BLACK_ONYX_COLLECTOR_TENANT_ID, BLACK_ONYX_COLLECTOR_INGEST_KEY, and BLACK_ONYX_COLLECTOR_GATEWAY_URL are required" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -d "$SCRIPT_DIR/osquery" && -d "$SCRIPT_DIR/shipper" ]]; then
  PKG_ROOT="$SCRIPT_DIR"
elif [[ -d "$SCRIPT_DIR/../../osquery" && -d "$SCRIPT_DIR/../../shipper" ]]; then
  PKG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
  echo "Cannot locate collector package root (osquery/ + shipper/)" >&2
  exit 1
fi

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

if ! command -v osqueryd >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    # brew should not run as root; use the invoking user when possible.
    BREW_USER="${SUDO_USER:-}"
    if [[ -n "$BREW_USER" && "$BREW_USER" != "root" ]]; then
      sudo -u "$BREW_USER" brew install --cask osquery || true
    else
      echo "Install osquery via Homebrew as a normal user: brew install --cask osquery" >&2
    fi
  fi
fi
if ! command -v osqueryd >/dev/null 2>&1; then
  echo "Install osquery manually: https://osquery.io/downloads/official" >&2
  exit 1
fi

mkdir -p /var/osquery/packs /var/log/osquery
install -m 0644 "$PKG_ROOT/osquery/packs/incident_response.conf" /var/osquery/packs/incident_response.conf
install -m 0644 "$PKG_ROOT/osquery/config/darwin.conf" /var/osquery/osquery.conf
cat >/var/osquery/osquery.flags <<'EOF'
--config_path=/var/osquery/osquery.conf
--logger_plugin=filesystem
--logger_path=/var/log/osquery
--disable_logging=false
--force=true
EOF

launchctl bootout system/com.facebook.osqueryd 2>/dev/null || true
if [[ -f /Library/LaunchDaemons/com.facebook.osqueryd.plist ]]; then
  launchctl bootstrap system /Library/LaunchDaemons/com.facebook.osqueryd.plist || true
else
  osqueryd --flagfile=/var/osquery/osquery.flags >/var/log/osquery/osqueryd.stdout 2>&1 &
fi

INSTALL_DIR=/opt/black-onyx-shipper
CONFIG_DIR=/etc/black-onyx-shipper
STATE_DIR=/var/lib/black-onyx-shipper
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"
install -m 0755 "$PKG_ROOT/shipper/black_onyx_shipper.py" "$INSTALL_DIR/black_onyx_shipper.py"

ENV_FILE="$CONFIG_DIR/shipper.env"
# The env file carries the ingest key: never world-readable, even briefly.
old_umask="$(umask)"
umask 077
cat >"$ENV_FILE" <<EOF
SHIPPER_SOURCES=osquery
BLACK_ONYX_COLLECTOR_TENANT_ID=${TENANT_ID}
BLACK_ONYX_COLLECTOR_GATEWAY_URL=${GATEWAY_URL}
BLACK_ONYX_COLLECTOR_INGEST_KEY=${INGEST_KEY}
BLACK_ONYX_COLLECTOR_ID=${COLLECTOR_ID}
BLACK_ONYX_COLLECTOR_ASSET_ID=${ASSET_ID}
BLACK_ONYX_COLLECTOR_HOSTNAME=${HOSTNAME_VAL}
BLACK_ONYX_COLLECTOR_OS_FAMILY=${OS_FAMILY}
OSQUERY_RESULTS_FILE=/var/log/osquery/osqueryd.results.log
SHIPPER_START_AT=beginning
SHIPPER_HEARTBEAT_SECONDS=300
SHIPPER_STATE_FILE=${STATE_DIR}/state.json
ASSET_REGISTRY_URL=${ASSET_REGISTRY_URL:-}
ASSET_REGISTRY_SERVICE_KEY=${ASSET_REGISTRY_SERVICE_KEY:-}
BLACK_ONYX_COLLECTOR_ENVIRONMENT=${BLACK_ONYX_COLLECTOR_ENVIRONMENT:-production}
BLACK_ONYX_COLLECTOR_ASSET_CRITICALITY=${BLACK_ONYX_COLLECTOR_ASSET_CRITICALITY:-0.5}
EOF
chmod 0640 "$ENV_FILE"
umask "$old_umask"

PLIST=/Library/LaunchDaemons/com.blackonyx.shipper.plist
cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.blackonyx.shipper</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>${INSTALL_DIR}/black_onyx_shipper.py</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SHIPPER_ENV_FILE</key><string>${ENV_FILE}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/osquery/black-onyx-shipper.out</string>
  <key>StandardErrorPath</key><string>/var/log/osquery/black-onyx-shipper.err</string>
</dict>
</plist>
EOF

# LaunchAgents don't source env files; wrap via a small loader.
LOADER="$INSTALL_DIR/run.sh"
cat >"$LOADER" <<'EOF'
#!/bin/bash
set -a
# shellcheck disable=SC1090
source "${SHIPPER_ENV_FILE:-/etc/black-onyx-shipper/shipper.env}"
set +a
exec /usr/bin/python3 /opt/black-onyx-shipper/black_onyx_shipper.py
EOF
chmod 0755 "$LOADER"
# Point plist at the loader instead of python directly.
plutil -replace ProgramArguments -json "[\"/bin/bash\",\"$LOADER\"]" "$PLIST"

launchctl bootout system/com.blackonyx.shipper 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl kickstart -k system/com.blackonyx.shipper

sleep 5
if ! pgrep -x osqueryd >/dev/null 2>&1; then
  echo "osqueryd is not running; check /var/log/osquery" >&2
  exit 1
fi
if ! launchctl print system/com.blackonyx.shipper 2>/dev/null | grep -q "state = running"; then
  launchctl print system/com.blackonyx.shipper >&2 || true
  echo "com.blackonyx.shipper is not running" >&2
  exit 1
fi

echo
echo "macOS collector installed."
echo "  asset_id=$ASSET_ID tenant=$TENANT_ID gateway=$GATEWAY_URL"
echo "Enable automatic time sync (System Settings → Date & Time) before production use."
