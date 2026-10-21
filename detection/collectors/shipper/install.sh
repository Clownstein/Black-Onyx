#!/usr/bin/env bash
# Install the Black Onyx shipper as a systemd service (run as root).
#   SHIPPER_SOURCES=wazuh,suricata bash detection/collectors/shipper/install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR=/opt/black-onyx-shipper
CONFIG_DIR=/etc/black-onyx-shipper
UNIT=/etc/systemd/system/black-onyx-shipper.service

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || { echo "python3 3.10 or newer is required" >&2; exit 1; }

id black-onyx-shipper >/dev/null 2>&1 \
  || useradd --system --no-create-home --shell /usr/sbin/nologin black-onyx-shipper

install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$SCRIPT_DIR/black_onyx_shipper.py" "$INSTALL_DIR/black_onyx_shipper.py"
install -d -m 0750 -o root -g black-onyx-shipper "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/shipper.env" ]]; then
  install -m 0640 -o root -g black-onyx-shipper "$SCRIPT_DIR/shipper.env.example" "$CONFIG_DIR/shipper.env"
  if [[ -n "${SHIPPER_SOURCES:-}" ]]; then
    sed -i "s/^SHIPPER_SOURCES=.*/SHIPPER_SOURCES=${SHIPPER_SOURCES}/" "$CONFIG_DIR/shipper.env"
  fi
  echo "Wrote $CONFIG_DIR/shipper.env — fill in the gateway, connector, and tenant values."
fi

groups=""
# adm: Debian/Ubuntu logrotate recreates /var/log files with that group.
for group in wazuh suricata adm; do
  if getent group "$group" >/dev/null 2>&1; then
    groups="$groups $group"
  fi
done
sed -e "s|^SupplementaryGroups=.*|SupplementaryGroups=${groups# }|" \
  -e "/^\[Service\]/a User=black-onyx-shipper" \
  "$SCRIPT_DIR/black-onyx-shipper.service" >"$UNIT"
if [[ -z "${groups# }" ]]; then
  sed -i '/^SupplementaryGroups=$/d' "$UNIT"
fi

systemctl daemon-reload
systemctl enable black-onyx-shipper.service
echo "Installed. Edit $CONFIG_DIR/shipper.env, then: systemctl restart black-onyx-shipper"
echo "Logs: journalctl -u black-onyx-shipper -f"
