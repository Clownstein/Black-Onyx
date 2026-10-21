#!/usr/bin/env bash
# Install Suricata on a network sensor and ship EVE alerts to Black Onyx (run as root).
#
#   SURICATA_INTERFACE=eth1 bash detection/collectors/suricata/install.sh
#
# Deploy on SPAN/TAP or choke-point sensors, not on every endpoint. When Wazuh
# runs on the same host, the shipper reads both files (SHIPPER_SOURCES=wazuh,suricata).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTORS="$(cd "$SCRIPT_DIR/.." && pwd)"
INTERFACE="${SURICATA_INTERFACE:-}"
EVE_FILE="/var/log/suricata/eve.json"
CONF="/etc/suricata/suricata.yaml"
DROPIN_DIR="/etc/suricata/conf.d"
DROPIN="$DROPIN_DIR/black-onyx-eve.yaml"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
if [[ -z "$INTERFACE" ]]; then
  echo "SURICATA_INTERFACE is required (the SPAN/TAP or monitored NIC)" >&2
  exit 2
fi
ip link show "$INTERFACE" >/dev/null 2>&1 || { echo "interface $INTERFACE not found" >&2; exit 2; }

if ! command -v suricata >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y suricata
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y epel-release || true
    dnf install -y suricata
  elif command -v yum >/dev/null 2>&1; then
    yum install -y epel-release || true
    yum install -y suricata
  else
    echo "No supported package manager; install Suricata manually: https://suricata.io/download/" >&2
    exit 1
  fi
fi
[[ -f "$CONF" ]] || { echo "$CONF not found after install" >&2; exit 1; }

# EVE JSON alerts (with flow ids and ATT&CK metadata) to the path the shipper tails.
# Periodic stats records keep eve.json fresh so the shipper only sends the sensor
# heartbeat while Suricata is actually running. This drop-in replaces the stock
# outputs and af-packet lists; merge by hand if you rely on other outputs.
install -d -m 0755 "$DROPIN_DIR"
cat >"$DROPIN" <<YAML
%YAML 1.1
---
stats:
  enabled: yes
  interval: 30
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: ${EVE_FILE}
      community-id: yes
      types:
        - alert:
            metadata: yes
            tagged-packets: no
        - stats:
            totals: yes
            threads: no
            deltas: no
af-packet:
  - interface: ${INTERFACE}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
YAML
if ! grep -q "black-onyx-eve.yaml" "$CONF"; then
  if grep -qE '^include:' "$CONF"; then
    echo "$CONF already has a top-level include: key; add $DROPIN to it by hand, then rerun" >&2
    exit 1
  fi
  printf '\ninclude: %s\n' "$DROPIN" >>"$CONF"
fi

if command -v suricata-update >/dev/null 2>&1; then
  suricata-update || echo "warning: suricata-update failed; rules may be stale" >&2
fi
suricata -T -c "$CONF" -v >/dev/null || { echo "Suricata config test failed; see suricata -T -c $CONF" >&2; exit 1; }

if [[ -f /etc/default/suricata ]]; then
  sed -i "s/^IFACE=.*/IFACE=${INTERFACE}/" /etc/default/suricata
fi
if [[ -f /etc/sysconfig/suricata ]]; then
  sed -i "s/^OPTIONS=.*/OPTIONS=\"--af-packet=${INTERFACE}\"/" /etc/sysconfig/suricata
fi
systemctl enable --now suricata
systemctl restart suricata

if getent group suricata >/dev/null 2>&1; then
  install -d -m 0750 -o root -g suricata /var/log/suricata
  touch "$EVE_FILE"
  chgrp suricata "$EVE_FILE"
  chmod 0640 "$EVE_FILE"
fi

SOURCES="suricata"
if [[ -d /var/ossec/logs/alerts ]]; then
  SOURCES="wazuh,suricata"
fi
SHIPPER_SOURCES="$SOURCES" bash "$COLLECTORS/shipper/install.sh"
echo "Suricata writes $EVE_FILE. Fill BLACK_ONYX_COLLECTOR_ASSET_ID/BLACK_ONYX_COLLECTOR_SENSOR_ID and gateway values in"
echo "/etc/black-onyx-shipper/shipper.env, then: systemctl restart black-onyx-shipper"
