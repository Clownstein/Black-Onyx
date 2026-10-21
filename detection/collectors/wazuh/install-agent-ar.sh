#!/usr/bin/env bash
# Install the Black Onyx isolation active-response script on a Linux Wazuh agent (root).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WAZUH_DIR="${WAZUH_DIR:-/var/ossec}"
if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
if [[ ! -d "$WAZUH_DIR/active-response/bin" ]]; then
  echo "$WAZUH_DIR/active-response/bin not found; install wazuh-agent first" >&2
  exit 1
fi
command -v iptables >/dev/null 2>&1 || echo "warning: iptables not found; isolation will fail on this host" >&2
install -m 0750 -o root -g wazuh "$SCRIPT_DIR/active-response/black-onyx-isolate" \
  "$WAZUH_DIR/active-response/bin/black-onyx-isolate"
echo "Installed $WAZUH_DIR/active-response/bin/black-onyx-isolate"
