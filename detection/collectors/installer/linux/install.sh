#!/usr/bin/env bash
# Install osquery + Black Onyx shipper on Linux (run as root).
# Works from the repo tree or from a downloaded collector package ZIP.
#
# Required env:
#   BLACK_ONYX_COLLECTOR_TENANT_ID, BLACK_ONYX_COLLECTOR_INGEST_KEY, BLACK_ONYX_COLLECTOR_GATEWAY_URL
# Optional:
#   BLACK_ONYX_COLLECTOR_ASSET_ID (default: hostname), BLACK_ONYX_COLLECTOR_ID, BLACK_ONYX_COLLECTOR_HOSTNAME, BLACK_ONYX_COLLECTOR_OS_FAMILY
#   ASSET_REGISTRY_URL, ASSET_REGISTRY_SERVICE_KEY
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

GATEWAY_URL="${BLACK_ONYX_COLLECTOR_GATEWAY_URL:-}"
TENANT_ID="${BLACK_ONYX_COLLECTOR_TENANT_ID:-}"
ASSET_ID="${BLACK_ONYX_COLLECTOR_ASSET_ID:-$(hostname -s 2>/dev/null || hostname)}"
HOSTNAME_VAL="${BLACK_ONYX_COLLECTOR_HOSTNAME:-$ASSET_ID}"
INGEST_KEY="${BLACK_ONYX_COLLECTOR_INGEST_KEY:-}"
COLLECTOR_ID="${BLACK_ONYX_COLLECTOR_ID:-osquery-$ASSET_ID}"
OS_FAMILY="${BLACK_ONYX_COLLECTOR_OS_FAMILY:-linux}"

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
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || { echo "python3 3.10 or newer is required" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive

# osquery's package signing key (pkg.osquery.io), pinned by fingerprint.
OSQUERY_GPG_FINGERPRINT="${OSQUERY_GPG_FINGERPRINT:-1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B}"

fetch_osquery_key() {
  local url="$1" dest="$2" fpr
  curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
  fpr="$(gpg --show-keys --with-colons "$dest" | awk -F: '/^fpr/ {print $10; exit}')"
  if [[ "$fpr" != "$OSQUERY_GPG_FINGERPRINT" ]]; then
    echo "osquery signing key fingerprint mismatch (got ${fpr:-none})" >&2
    rm -f "$dest"
    exit 1
  fi
}

install_osquery() {
  if command -v osqueryd >/dev/null 2>&1; then
    echo "osqueryd already installed: $(command -v osqueryd)"
    return
  fi
  local key_tmp
  if command -v apt-get >/dev/null 2>&1; then
    local arch
    arch="$(dpkg --print-architecture)"
    if [[ "$arch" != "amd64" && "$arch" != "arm64" ]]; then
      echo "osquery packages are published for amd64/arm64 only (this host: $arch)" >&2
      exit 1
    fi
    apt-get update -qq
    apt-get install -y ca-certificates curl gnupg
    key_tmp="$(mktemp)"
    fetch_osquery_key https://pkg.osquery.io/deb/pubkey.gpg "$key_tmp"
    mkdir -p /etc/apt/keyrings
    gpg --dearmor < "$key_tmp" > /etc/apt/keyrings/osquery.gpg
    chmod 0644 /etc/apt/keyrings/osquery.gpg
    rm -f "$key_tmp"
    echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
      >/etc/apt/sources.list.d/osquery.list
    apt-get update -qq
    apt-get install -y osquery
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    local pm
    pm="$(command -v dnf || command -v yum)"
    "$pm" install -y ca-certificates curl gnupg2
    key_tmp="$(mktemp)"
    fetch_osquery_key https://pkg.osquery.io/rpm/GPG "$key_tmp"
    install -m 0644 "$key_tmp" /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
    rm -f "$key_tmp"
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
    cat >/etc/yum.repos.d/osquery-s3-rpm.repo <<'REPO'
[osquery-s3-rpm-repo]
name=osquery RPM repository - $basearch
baseurl=https://pkg.osquerypackages.com/rpm/$basearch/
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
gpgcheck=1
REPO
    "$pm" install -y osquery
  else
    echo "Unsupported package manager; install osquery from https://osquery.io/downloads/official" >&2
    exit 1
  fi
  command -v osqueryd >/dev/null 2>&1 || { echo "osquery installation did not provide osqueryd" >&2; exit 1; }
}

install_osquery

mkdir -p /etc/osquery/packs /var/log/osquery /var/osquery
install -m 0644 "$PKG_ROOT/osquery/packs/incident_response.conf" /etc/osquery/packs/incident_response.conf
install -m 0644 "$PKG_ROOT/osquery/config/linux.conf" /etc/osquery/osquery.conf

# Ensure results log path used by the shipper.
cat >/etc/osquery/osquery.flags <<'EOF'
--config_path=/etc/osquery/osquery.conf
--logger_plugin=filesystem
--logger_path=/var/log/osquery
--logger_mode=0640
--disable_logging=false
--force=true
EOF

if systemctl list-unit-files osqueryd.service >/dev/null 2>&1; then
  systemctl enable osqueryd.service
  systemctl restart osqueryd.service
elif command -v service >/dev/null 2>&1; then
  service osqueryd restart
fi

# Install shipper as osquery source only (no Wazuh/Suricata required).
SHIPPER_SOURCES=osquery bash "$PKG_ROOT/shipper/install.sh"

ENV_FILE=/etc/black-onyx-shipper/shipper.env
umask 027
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
ASSET_REGISTRY_URL=${ASSET_REGISTRY_URL:-}
ASSET_REGISTRY_SERVICE_KEY=${ASSET_REGISTRY_SERVICE_KEY:-}
BLACK_ONYX_COLLECTOR_ENVIRONMENT=${BLACK_ONYX_COLLECTOR_ENVIRONMENT:-production}
BLACK_ONYX_COLLECTOR_ASSET_CRITICALITY=${BLACK_ONYX_COLLECTOR_ASSET_CRITICALITY:-0.5}
EOF
chown root:black-onyx-shipper "$ENV_FILE"
chmod 0640 "$ENV_FILE"

# Shipper reads results via the osquery group. Keep the log directory
# group-readable only so other local users cannot read host telemetry.
if getent group osquery >/dev/null 2>&1; then
  usermod -aG osquery black-onyx-shipper || true
  chown root:osquery /var/log/osquery || true
  if [[ -f /var/log/osquery/osqueryd.results.log ]]; then
    chown root:osquery /var/log/osquery/osqueryd.results.log || true
  fi
fi
chmod 0750 /var/log/osquery || true
chmod 0640 /var/log/osquery/osqueryd.results.log 2>/dev/null || true

systemctl daemon-reload
systemctl restart black-onyx-shipper.service
sleep 3
for unit in osqueryd black-onyx-shipper; do
  if command -v systemctl >/dev/null 2>&1 && ! systemctl is-active --quiet "$unit"; then
    systemctl --no-pager --full status "$unit" >&2 || true
    echo "$unit failed to start" >&2
    exit 1
  fi
done

echo
echo "Linux collector installed."
echo "  asset_id=$ASSET_ID tenant=$TENANT_ID gateway=$GATEWAY_URL"
echo "  logs: journalctl -u black-onyx-shipper -f"
echo "Enable NTP (chrony/systemd-timesyncd) before production use."
