#!/usr/bin/env python3
"""Wazuh integratord hook: push one alert to a Black Onyx Wazuh connector.

integratord runs: custom-blackonyx <alert_file> <api_key> <hook_url>
  api_key  = connector push token (Administration -> Detections -> Issue push token)
  hook_url = https://<black-onyx>/api/v1/connectors/<connector_id>/push

Use this or the shipper's connector push (SHIPPER_WAZUH_PUSH), not both. The
connector dedupes on alert id, but running both doubles push traffic.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import black_onyx_shipper as shipper  # installed beside this hook

LOG_FILE = "/var/ossec/logs/integrations.log"


def log(message: str) -> None:
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(f"custom-blackonyx: {message}\n")
    except OSError:
        pass


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        log("usage: custom-blackonyx <alert_file> <api_key> <hook_url>")
        return 2
    alert_file, token, hook_url = argv[1], argv[2], argv[3]
    try:
        with open(alert_file, encoding="utf-8") as handle:
            alert = json.load(handle)
    except (OSError, ValueError) as exc:
        log(f"cannot read alert {alert_file}: {exc}")
        return 1
    if not isinstance(alert, dict) or shipper.is_suricata_alert(alert):
        return 0
    context = shipper.ssl_context(os.environ.get("SHIPPER_CA_FILE", ""))
    try:
        status, body = shipper.http_json(
            "POST", hook_url, body={"detections": [alert]},
            headers={"X-Connector-Token": token}, context=context,
        )
    except shipper.DeliveryError as exc:
        log(str(exc))
        return 1
    if status >= 400 or (isinstance(body, dict) and (body.get("error") or body.get("errors"))):
        log(f"push returned {status}: {body}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
