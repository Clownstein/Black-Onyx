#!/usr/bin/env bash
# Install Black Onyx pieces on a Wazuh manager (run as root):
#   * the shipper service (alerts.json -> connector push + host-state + heartbeats)
#   * optionally the custom-blackonyx integratord hook (WITH_INTEGRATOR=true)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTORS="$(cd "$SCRIPT_DIR/.." && pwd)"
WAZUH_DIR="${WAZUH_DIR:-/var/ossec}"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
if [[ ! -d "$WAZUH_DIR/integrations" ]]; then
  echo "$WAZUH_DIR/integrations not found; install wazuh-manager first" >&2
  exit 1
fi

SHIPPER_SOURCES="${SHIPPER_SOURCES:-wazuh}" bash "$COLLECTORS/shipper/install.sh"

if [[ "${WITH_INTEGRATOR:-false}" == "true" ]]; then
  for file in custom-blackonyx custom-blackonyx.py; do
    install -m 0750 -o root -g wazuh "$SCRIPT_DIR/integrations/$file" "$WAZUH_DIR/integrations/$file"
  done
  install -m 0640 -o root -g wazuh "$COLLECTORS/shipper/black_onyx_shipper.py" \
    "$WAZUH_DIR/integrations/black_onyx_shipper.py"
  sed -i 's/^SHIPPER_WAZUH_PUSH=.*/SHIPPER_WAZUH_PUSH=false/' /etc/black-onyx-shipper/shipper.env
  echo "Integrator installed. Add the <integration> block from $SCRIPT_DIR/ossec.conf.snippet.xml"
  echo "to $WAZUH_DIR/etc/ossec.conf, then: systemctl restart wazuh-manager"
fi

echo "Next: fill /etc/black-onyx-shipper/shipper.env and run: systemctl restart black-onyx-shipper"
