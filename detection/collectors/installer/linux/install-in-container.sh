#!/usr/bin/env bash
# Runs inside a privileged Ubuntu container with /host mounted and --pid=host.
set -euo pipefail

host_systemctl() {
  nsenter -t 1 -m -u -i -n -- systemctl "$@"
}

OSQUERY_GPG_FINGERPRINT="${OSQUERY_GPG_FINGERPRINT:-1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B}"

# Block service starts during package install; always restore on exit.
printf '%s\n' '#!/bin/sh' 'exit 0' >/host/usr/sbin/policy-rc.d
chmod +x /host/usr/sbin/policy-rc.d
trap 'rm -f /host/usr/sbin/policy-rc.d' EXIT

if ! chroot /host sh -c 'command -v apt-get' >/dev/null 2>&1; then
  echo "The Docker-based installer supports Debian/Ubuntu hosts; use install.sh elsewhere" >&2
  exit 1
fi

if ! chroot /host dpkg -s osquery >/dev/null 2>&1; then
  arch="$(chroot /host dpkg --print-architecture)"
  if [[ "$arch" != "amd64" && "$arch" != "arm64" ]]; then
    echo "osquery packages are published for amd64/arm64 only (host: $arch)" >&2
    exit 1
  fi
  chroot /host apt-get update -qq
  chroot /host apt-get install -y ca-certificates curl gnupg
  # curl/gpg run on the host: the helper container image ships neither.
  key_tmp="$(chroot /host mktemp)"
  chroot /host curl -fsSL --proto '=https' --tlsv1.2 -o "$key_tmp" https://pkg.osquery.io/deb/pubkey.gpg
  fpr="$(chroot /host gpg --show-keys --with-colons "$key_tmp" | awk -F: '/^fpr/ {print $10; exit}')"
  if [[ "$fpr" != "$OSQUERY_GPG_FINGERPRINT" ]]; then
    chroot /host rm -f "$key_tmp"
    echo "osquery signing key fingerprint mismatch (got ${fpr:-none})" >&2
    exit 1
  fi
  mkdir -p /host/etc/apt/keyrings
  chroot /host sh -c 'gpg --dearmor < "$1" > /etc/apt/keyrings/osquery.gpg' _ "$key_tmp"
  chmod 0644 /host/etc/apt/keyrings/osquery.gpg
  chroot /host rm -f "$key_tmp"
  echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
    >/host/etc/apt/sources.list.d/osquery.list
  chroot /host apt-get update -qq
  chroot /host apt-get install -y -o Dpkg::Options::=--force-confdef osquery
fi
# Finish configuring a package a previous attempt left half-installed.
chroot /host dpkg --configure -a

mkdir -p /host/etc/osquery/packs /host/var/log/osquery /host/var/osquery
install -m 0644 /collectors/osquery/packs/incident_response.conf /host/etc/osquery/packs/incident_response.conf
install -m 0644 /collectors/osquery/config/linux.conf /host/etc/osquery/osquery.conf
cat >/host/etc/osquery/osquery.flags <<'EOF'
--config_path=/etc/osquery/osquery.conf
--logger_plugin=filesystem
--logger_path=/var/log/osquery
--logger_mode=0640
--disable_logging=false
--force=true
EOF

if ! chroot /host id black-onyx-shipper >/dev/null 2>&1; then
  chroot /host useradd --system --no-create-home --shell /usr/sbin/nologin black-onyx-shipper
fi

install -d -m 0755 /host/opt/black-onyx-shipper
install -m 0755 /collectors/shipper/black_onyx_shipper.py /host/opt/black-onyx-shipper/black_onyx_shipper.py
install -d -m 0750 /host/etc/black-onyx-shipper
chroot /host chown root:black-onyx-shipper /etc/black-onyx-shipper
install -d -m 0755 /host/var/lib/black-onyx-shipper
chroot /host chown black-onyx-shipper:black-onyx-shipper /var/lib/black-onyx-shipper

cat >/host/etc/black-onyx-shipper/shipper.env <<EOF
SHIPPER_SOURCES=osquery
BLACK_ONYX_COLLECTOR_TENANT_ID=${BLACK_ONYX_COLLECTOR_TENANT_ID}
BLACK_ONYX_COLLECTOR_GATEWAY_URL=${BLACK_ONYX_COLLECTOR_GATEWAY_URL}
BLACK_ONYX_COLLECTOR_INGEST_KEY=${BLACK_ONYX_COLLECTOR_INGEST_KEY}
BLACK_ONYX_COLLECTOR_ID=${BLACK_ONYX_COLLECTOR_ID}
BLACK_ONYX_COLLECTOR_ASSET_ID=${BLACK_ONYX_COLLECTOR_ASSET_ID}
BLACK_ONYX_COLLECTOR_HOSTNAME=${BLACK_ONYX_COLLECTOR_HOSTNAME}
BLACK_ONYX_COLLECTOR_OS_FAMILY=${BLACK_ONYX_COLLECTOR_OS_FAMILY}
OSQUERY_RESULTS_FILE=/var/log/osquery/osqueryd.results.log
SHIPPER_START_AT=beginning
SHIPPER_HEARTBEAT_SECONDS=300
ASSET_REGISTRY_URL=${ASSET_REGISTRY_URL:-}
ASSET_REGISTRY_SERVICE_KEY=${ASSET_REGISTRY_SERVICE_KEY:-}
BLACK_ONYX_COLLECTOR_ENVIRONMENT=${BLACK_ONYX_COLLECTOR_ENVIRONMENT:-production}
BLACK_ONYX_COLLECTOR_ASSET_CRITICALITY=${BLACK_ONYX_COLLECTOR_ASSET_CRITICALITY:-0.5}
EOF
chroot /host chown root:black-onyx-shipper /etc/black-onyx-shipper/shipper.env
chmod 0640 /host/etc/black-onyx-shipper/shipper.env

groups=""
for group in osquery adm; do
  if chroot /host getent group "$group" >/dev/null 2>&1; then
    groups="$groups $group"
    chroot /host usermod -aG "$group" black-onyx-shipper || true
  fi
done
sed -e "s|^SupplementaryGroups=.*|SupplementaryGroups=${groups# }|" \
  -e '/^\[Service\]/a User=black-onyx-shipper' \
  /collectors/shipper/black-onyx-shipper.service >/host/etc/systemd/system/black-onyx-shipper.service
if [[ -z "${groups# }" ]]; then
  sed -i '/^SupplementaryGroups=$/d' /host/etc/systemd/system/black-onyx-shipper.service
fi
if chroot /host getent group osquery >/dev/null 2>&1; then
  chroot /host chown root:osquery /var/log/osquery || true
  if [[ -f /host/var/log/osquery/osqueryd.results.log ]]; then
    chroot /host chown root:osquery /var/log/osquery/osqueryd.results.log || true
  fi
fi
chmod 0750 /host/var/log/osquery || true
chmod 0640 /host/var/log/osquery/osqueryd.results.log 2>/dev/null || true

host_systemctl daemon-reload
rm -f /host/usr/sbin/policy-rc.d
host_systemctl enable osqueryd.service
host_systemctl restart osqueryd.service
host_systemctl enable black-onyx-shipper.service
host_systemctl restart black-onyx-shipper.service
for unit in osqueryd.service black-onyx-shipper.service; do
  if ! host_systemctl is-active --quiet "$unit"; then
    host_systemctl --no-pager --full status "$unit" >&2 || true
    echo "$unit failed to start" >&2
    exit 1
  fi
done
echo "Linux collector installed for asset_id=${BLACK_ONYX_COLLECTOR_ASSET_ID} gateway=${BLACK_ONYX_COLLECTOR_GATEWAY_URL}"
