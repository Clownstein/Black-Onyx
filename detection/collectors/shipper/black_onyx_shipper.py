#!/usr/bin/env python3
"""Ship Wazuh alerts and Suricata EVE alerts into Black Onyx.

Runs beside the Wazuh manager and/or a Suricata sensor (stdlib only, Python 3.10+).

Routing (each source line is classified once):

* Wazuh alerts from Suricata/IDS rule groups are dropped; Suricata is ingested
  only from ``eve.json`` so one network alert never becomes two incidents.
* Other Wazuh alerts at or above ``WAZUH_MIN_LEVEL`` are pushed as raw JSON to
  the TIP connector push endpoint (triage, cases, analytics, asset sightings).
* Wazuh records that describe a process, network connection, or logon (Sysmon,
  auditd, Windows/Linux authentication) are also posted to the ingestion
  gateway's host-state route as already-normalized ``host_state.*`` payloads.
* Suricata EVE ``alert`` lines go to the gateway's Suricata route.
* Every ``SHIPPER_HEARTBEAT_SECONDS`` a ``host_state.agent_status`` event is
  posted per active Wazuh agent (and for the Suricata sensor) so the
  host-state heartbeat monitor can raise telemetry-gap incidents.

File offsets are committed only after every output of a read batch was
delivered, and gateway event ids are derived from the source line, so a retry
re-sends identical events instead of new ones.
"""

from __future__ import annotations

import base64
import glob
import hashlib
import json
import logging
import os
import queue
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

logger = logging.getLogger("black_onyx_shipper")

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SURICATA_GROUPS = frozenset({"suricata", "ids", "eve"})
CONNECTOR_PUSH_MAX = 500
CONNECTOR_PUSH_MAX_BYTES = 8 * 1024 * 1024
FINGERPRINT_BYTES = 256
MAX_READ_BYTES = 4 * 1024 * 1024
SYSMON_PROVIDER = "microsoft-windows-sysmon"
WINDOWS_LOGON_SUCCESS = {"4624"}
WINDOWS_LOGON_FAILED = {"4625"}
AUTH_SUCCESS_GROUPS = frozenset({"authentication_success"})
AUTH_FAILED_GROUPS = frozenset({"authentication_failed", "authentication_failures"})


# --------------------------------------------------------------------- ids


def _encode_crockford(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def ulid_from(timestamp_ms: int, entropy: bytes) -> str:
    """Build a ULID from a millisecond timestamp and 10 bytes of entropy."""
    if len(entropy) < 10:
        raise ValueError("ULID entropy must be at least 10 bytes")
    ts = max(0, min(int(timestamp_ms), (1 << 48) - 1))
    rand = int.from_bytes(entropy[:10], "big")
    return _encode_crockford((ts << 80) | rand, 26)


def deterministic_ulid(timestamp_ms: int, seed: str) -> str:
    return ulid_from(timestamp_ms, hashlib.sha256(seed.encode("utf-8")).digest())


def random_ulid() -> str:
    return ulid_from(int(time.time() * 1000), os.urandom(10))


# --------------------------------------------------------------- parsing


def parse_timestamp(value: Any) -> datetime | None:
    """Parse Wazuh/Suricata timestamps (``+0000`` offsets included)."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _basename(path: Any) -> str:
    text = str(path or "").replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1] if text else ""


def wazuh_asset_id(agent_id: Any) -> str:
    text = str(agent_id or "").strip()
    return f"wazuh:{text}" if text else ""


def os_family_from_platform(platform: Any) -> str:
    text = str(platform or "").strip().lower()
    if "windows" in text or text.startswith("win"):
        return "windows"
    if text in {"darwin", "macos", "mac", "osx"}:
        return "darwin"
    return "linux" if text else "unknown"


def rule_groups(alert: dict[str, Any]) -> list[str]:
    groups = _dict(alert.get("rule")).get("groups")
    if isinstance(groups, list):
        return [str(g).strip().lower() for g in groups]
    if isinstance(groups, str):
        return [groups.strip().lower()]
    return []


def is_suricata_alert(alert: dict[str, Any]) -> bool:
    return any(group in SURICATA_GROUPS for group in rule_groups(alert))


def alert_level(alert: dict[str, Any]) -> int:
    return _int(_dict(alert.get("rule")).get("level")) or 0


def _sysmon_hashes(value: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(value, str):
        return out
    for part in value.split(","):
        if "=" in part:
            algo, digest = part.split("=", 1)
            if algo.strip() and digest.strip():
                out[algo.strip().lower()] = digest.strip().lower()
    return out


def _process(
    *, path: Any, name: Any = None, cmdline: Any = None, pid: Any = None, ppid: Any = None,
    parent_path: Any = None, user: Any = None, action: str = "create", hashes: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    resolved_path = str(path).strip() if path else ""
    resolved_name = str(name).strip() if name else _basename(resolved_path)
    if not resolved_name and not resolved_path:
        return None
    process: dict[str, Any] = {
        "name": resolved_name,
        "path": resolved_path or None,
        "cmdline": str(cmdline) if cmdline else None,
        "user": str(user) if user else None,
        "action": action,
        "parent_path": str(parent_path) if parent_path else None,
        "parent_name": _basename(parent_path) or None,
    }
    for key, value in (("pid", pid), ("ppid", ppid)):
        number = _int(value)
        if number is not None:
            process[key] = number
    if hashes:
        process["hashes"] = hashes
    return process


def _sysmon_host_state(eid: int, ev: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    hashes = _sysmon_hashes(ev.get("hashes"))
    if eid == 1:
        process = _process(
            path=ev.get("image"), cmdline=ev.get("commandLine"), pid=ev.get("processId"), ppid=ev.get("parentProcessId"),
            parent_path=ev.get("parentImage"), user=ev.get("user"), hashes=hashes,
        )
        return ("host_state.process_event", {"process": process}) if process else None
    if eid == 3:
        local_port = _int(ev.get("sourcePort"))
        if local_port is None:
            return None
        socket = {
            "protocol": str(ev.get("protocol") or "tcp").lower(),
            "local_address": ev.get("sourceIp") or "0.0.0.0",
            "local_port": local_port,
            "remote_address": ev.get("destinationIp"),
            "remote_port": _int(ev.get("destinationPort")),
            "state": "established",
            "process_name": _basename(ev.get("image")) or None,
            "path": ev.get("image"),
            "pid": _int(ev.get("processId")),
        }
        return "host_state.socket_snapshot", {"socket": {k: v for k, v in socket.items() if v is not None}}
    if eid == 10:
        process = _process(
            path=ev.get("sourceImage"), pid=ev.get("sourceProcessId"), action="open",
            user=ev.get("sourceUser"),
        )
        if not process:
            return None
        return "host_state.process_event", {"process": process, "target_image": ev.get("targetImage")}
    if eid == 11:
        process = _process(path=ev.get("image"), pid=ev.get("processId"), user=ev.get("user"))
        if not process:
            return None
        return "host_state.process_event", {"process": process, "target_filename": ev.get("targetFilename")}
    if eid == 22:
        process = _process(path=ev.get("image"), pid=ev.get("processId"), user=ev.get("user"))
        if not process:
            return None
        return "host_state.process_event", {"process": process, "dns_query": ev.get("queryName")}
    return None


def wazuh_host_state_payload(alert: dict[str, Any], tenant_id: str) -> dict[str, Any] | None:
    """Map a Wazuh alert to an already-normalized host-state payload, or None."""
    agent = _dict(alert.get("agent"))
    asset_id = wazuh_asset_id(agent.get("id"))
    occurred = parse_timestamp(alert.get("timestamp"))
    if not asset_id or occurred is None:
        return None
    data = _dict(alert.get("data"))
    win = _dict(data.get("win"))
    system = _dict(win.get("system"))
    ev = _dict(win.get("eventdata"))
    audit = _dict(data.get("audit"))
    groups = set(rule_groups(alert))

    mapped: tuple[str, dict[str, Any]] | None = None
    os_family = "unknown"
    eid = _int(system.get("eventID"))
    provider = str(system.get("providerName") or "").lower()
    if win:
        os_family = "windows"
    if eid is not None and provider == SYSMON_PROVIDER:
        mapped = _sysmon_host_state(eid, ev)
    elif eid is not None and str(eid) in WINDOWS_LOGON_SUCCESS | WINDOWS_LOGON_FAILED:
        mapped = "host_state.user_session", {"session": {
            "user": str(ev.get("targetUserName") or "unknown"),
            "logon_type": ev.get("logonType"),
            "source_ip": ev.get("ipAddress"),
            "action": "logon" if str(eid) in WINDOWS_LOGON_SUCCESS else "failed_logon",
        }}
    elif audit.get("exe"):
        os_family = "linux"
        execve = _dict(audit.get("execve"))
        arg_keys = sorted(
            (key for key in execve if key.startswith("a") and key[1:].isdigit()), key=lambda k: int(k[1:]),
        )
        argv = [str(execve[key]) for key in arg_keys]
        process = _process(
            path=audit.get("exe"), cmdline=" ".join(argv) or audit.get("command"),
            pid=audit.get("pid"), ppid=audit.get("ppid"),
            user=audit.get("euid") or audit.get("auid"),
        )
        if process:
            mapped = "host_state.process_event", {"process": process}
    elif groups & (AUTH_SUCCESS_GROUPS | AUTH_FAILED_GROUPS):
        user = data.get("dstuser") or data.get("srcuser")
        if user:
            mapped = "host_state.user_session", {"session": {
                "user": str(user),
                "logon_type": None,
                "source_ip": data.get("srcip"),
                "action": "failed_logon" if groups & AUTH_FAILED_GROUPS else "logon",
            }}
    if mapped is None:
        return None

    event_type, fields = mapped
    payload: dict[str, Any] = {
        "event_type": event_type,
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "occurred_at": iso(occurred),
        "hostname": agent.get("name"),
        "os_family": os_family,
        "wazuh_agent_id": str(agent.get("id")),
        "wazuh_rule_id": str(_dict(alert.get("rule")).get("id") or ""),
        **fields,
    }
    return payload


@dataclass
class WazuhRouting:
    push: bool = False
    host_state: dict[str, Any] | None = None
    agent: dict[str, Any] | None = None


def classify_wazuh_alert(alert: dict[str, Any], *, tenant_id: str, min_level: int) -> WazuhRouting:
    if is_suricata_alert(alert):
        return WazuhRouting()
    agent = _dict(alert.get("agent"))
    return WazuhRouting(
        push=alert_level(alert) >= min_level,
        host_state=wazuh_host_state_payload(alert, tenant_id),
        agent=agent if agent.get("id") else None,
    )


# -------------------------------------------------------------- envelopes


def build_envelope(
    *, event_type: str, tenant_id: str, collector_id: str, source_type: str, asset_id: str,
    occurred_at: datetime, payload: dict[str, Any], event_id: str,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "1.0",
        "event_id": event_id,
        "event_type": event_type,
        "tenant_id": tenant_id,
        "occurred_at": iso(min(occurred_at, now)),
        "ingested_at": iso(now),
        "source": {"collector_id": collector_id, "source_type": source_type},
        "asset": {"asset_id": asset_id},
        "payload": payload,
    }


def host_state_envelope(
    payload: dict[str, Any], *, collector_id: str, seed: str, source_type: str = "wazuh",
) -> dict[str, Any]:
    occurred = parse_timestamp(payload["occurred_at"]) or datetime.now(timezone.utc)
    return build_envelope(
        event_type=payload["event_type"], tenant_id=payload["tenant_id"], collector_id=collector_id,
        source_type=source_type, asset_id=payload["asset_id"], occurred_at=occurred, payload=payload,
        event_id=deterministic_ulid(int(occurred.timestamp() * 1000), seed),
    )


_OSQUERY_QUERY_TO_EVENT = {
    "process_snapshot": "host_state.process_snapshot",
    "processes": "host_state.process_snapshot",
    "listening_ports": "host_state.socket_snapshot",
    "logged_in_users": "host_state.user_session",
    "startup_items": "host_state.autorun_snapshot",
    "services": "host_state.autorun_snapshot",
    "scheduled_tasks": "host_state.autorun_snapshot",
}


def _osquery_query_name(raw_name: str) -> str:
    """Normalize pack-prefixed names like ``pack_incident_response_process_snapshot``."""
    name = raw_name.strip()
    if name in _OSQUERY_QUERY_TO_EVENT:
        return name
    for key in _OSQUERY_QUERY_TO_EVENT:
        if name.endswith("_" + key) or name == key:
            return key
    if name.startswith("pack_"):
        parts = name.split("_")
        if len(parts) >= 3:
            candidate = parts[-1]
            # multi-word keys (listening_ports, logged_in_users, …)
            for key in _OSQUERY_QUERY_TO_EVENT:
                if name.endswith(key):
                    return key
            return candidate
    return name


def osquery_envelope(
    raw: dict[str, Any],
    *,
    tenant_id: str,
    asset_id: str,
    collector_id: str,
    hostname: str | None,
    os_family: str,
    seed: str,
) -> dict[str, Any] | None:
    """Map one osquery result line into a host-state envelope (columns flattened)."""
    if not isinstance(raw, dict):
        return None
    query_name = _osquery_query_name(str(raw.get("name") or ""))
    event_type = _OSQUERY_QUERY_TO_EVENT.get(query_name)
    if not event_type:
        return None
    columns = raw.get("columns") if isinstance(raw.get("columns"), dict) else {}
    unix_time = raw.get("unixTime") or raw.get("unix_time")
    occurred: datetime | None = None
    if unix_time is not None:
        try:
            occurred = datetime.fromtimestamp(float(unix_time), tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            occurred = None
    if occurred is None:
        occurred = parse_timestamp(raw.get("calendarTime") or raw.get("calendar_time"))
    if occurred is None:
        occurred = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        **columns,
        "event_type": event_type,
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "occurred_at": iso(occurred),
        "hostname": hostname or raw.get("hostIdentifier") or asset_id,
        "os_family": os_family,
        "name": query_name,
    }
    return host_state_envelope(payload, collector_id=collector_id, seed=seed, source_type="osquery")


def agent_status_envelope(
    *, tenant_id: str, asset_id: str, hostname: str | None, os_family: str, collector_id: str,
    source_type: str,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    payload = {
        "event_type": "host_state.agent_status",
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "occurred_at": iso(now),
        "hostname": hostname,
        "os_family": os_family,
    }
    return build_envelope(
        event_type="host_state.agent_status", tenant_id=tenant_id, collector_id=collector_id,
        source_type=source_type, asset_id=asset_id, occurred_at=now, payload=payload,
        event_id=random_ulid(),
    )


def suricata_envelope(
    raw: dict[str, Any], *, tenant_id: str, collector_id: str, sensor_id: str, asset_id: str, seed: str,
) -> dict[str, Any] | None:
    if raw.get("event_type") != "alert" or not isinstance(raw.get("alert"), dict):
        return None
    occurred = parse_timestamp(raw.get("timestamp")) or datetime.now(timezone.utc)
    payload = {**raw, "event_type": "suricata.alert", "sensor_id": sensor_id, "asset_id": asset_id}
    return build_envelope(
        event_type="suricata.alert", tenant_id=tenant_id, collector_id=collector_id,
        source_type="suricata", asset_id=asset_id, occurred_at=occurred, payload=payload,
        event_id=deterministic_ulid(int(occurred.timestamp() * 1000), seed),
    )


# ------------------------------------------------------------------ config


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name)
    if not value:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass
class ShipperConfig:
    tenant_id: str
    collector_id: str
    gateway_url: str
    ingest_key: str
    sources: set[str]
    state_file: Path
    wazuh_alerts_file: Path
    suricata_eve_file: Path
    osquery_results_file: Path
    tip_url: str = ""
    connector_id: str = ""
    connector_token: str = ""
    wazuh_push: bool = True
    min_level: int = 7
    sensor_asset_id: str = ""
    sensor_id: str = ""
    hostname: str = ""
    os_family: str = "linux"
    asset_registry_url: str = ""
    asset_registry_key: str = ""
    environment: str = "production"
    criticality: float = 0.5
    wazuh_api_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_api_ca_file: str = ""
    wazuh_api_insecure: bool = False
    ca_file: str = ""
    heartbeat_seconds: float = 300.0
    flush_seconds: float = 5.0
    start_at_end: bool = True
    # ingestion-gateway defaults: MAX_BATCH_SIZE=100, MAX_BODY_BYTES=1 MiB.
    gateway_batch: int = 100
    gateway_max_bytes: int = 900_000
    wazuh_rotated_glob: str = "/var/ossec/logs/alerts/*/*/ossec-alerts-*.json"
    suricata_rotated_glob: str = ""
    osquery_rotated_glob: str = ""
    sensor_stale_seconds: float = 600.0

    @classmethod
    def from_env(cls) -> ShipperConfig:
        sources = {s.strip().lower() for s in _env("SHIPPER_SOURCES", "wazuh,suricata").split(",") if s.strip()}
        unknown = sources - {"wazuh", "suricata", "osquery"}
        if unknown:
            raise ValueError(f"SHIPPER_SOURCES has unknown entries: {', '.join(sorted(unknown))}")
        config = cls(
            tenant_id=_env("BLACK_ONYX_COLLECTOR_TENANT_ID"),
            collector_id=_env("BLACK_ONYX_COLLECTOR_ID", "black-onyx-shipper"),
            gateway_url=_env("BLACK_ONYX_COLLECTOR_GATEWAY_URL").rstrip("/"),
            ingest_key=_env("BLACK_ONYX_COLLECTOR_INGEST_KEY"),
            sources=sources,
            state_file=Path(_env("SHIPPER_STATE_FILE", "/var/lib/black-onyx-shipper/state.json")),
            wazuh_alerts_file=Path(_env("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")),
            suricata_eve_file=Path(_env("SURICATA_EVE_FILE", "/var/log/suricata/eve.json")),
            osquery_results_file=Path(
                _env("OSQUERY_RESULTS_FILE", "/var/log/osquery/osqueryd.results.log")
            ),
            tip_url=_env("BLACK_ONYX_URL").rstrip("/"),
            connector_id=_env("BLACK_ONYX_CONNECTOR_ID"),
            connector_token=_env("BLACK_ONYX_CONNECTOR_TOKEN"),
            wazuh_push=_env_bool("SHIPPER_WAZUH_PUSH", True),
            min_level=int(_env("WAZUH_MIN_LEVEL", "7")),
            sensor_asset_id=_env("BLACK_ONYX_COLLECTOR_ASSET_ID"),
            sensor_id=_env("BLACK_ONYX_COLLECTOR_SENSOR_ID") or _env("BLACK_ONYX_COLLECTOR_ASSET_ID"),
            hostname=_env("BLACK_ONYX_COLLECTOR_HOSTNAME") or _env("BLACK_ONYX_COLLECTOR_ASSET_ID"),
            os_family=_env("BLACK_ONYX_COLLECTOR_OS_FAMILY", "linux").lower(),
            asset_registry_url=_env("ASSET_REGISTRY_URL").rstrip("/"),
            asset_registry_key=_env("ASSET_REGISTRY_SERVICE_KEY"),
            environment=_env("BLACK_ONYX_COLLECTOR_ENVIRONMENT", "production"),
            criticality=float(_env("BLACK_ONYX_COLLECTOR_ASSET_CRITICALITY", "0.5")),
            wazuh_api_url=_env("WAZUH_API_URL").rstrip("/"),
            wazuh_api_user=_env("WAZUH_API_USER"),
            wazuh_api_password=os.environ.get("WAZUH_API_PASSWORD", ""),
            wazuh_api_ca_file=_env("WAZUH_API_CA_FILE"),
            wazuh_api_insecure=_env_bool("WAZUH_API_INSECURE", False),
            ca_file=_env("SHIPPER_CA_FILE"),
            heartbeat_seconds=float(_env("SHIPPER_HEARTBEAT_SECONDS", "300")),
            flush_seconds=float(_env("SHIPPER_FLUSH_SECONDS", "5")),
            start_at_end=_env("SHIPPER_START_AT", "end").lower() != "beginning",
            gateway_batch=int(_env("SHIPPER_GATEWAY_BATCH", "100")),
            gateway_max_bytes=int(_env("SHIPPER_GATEWAY_MAX_BYTES", "900000")),
            wazuh_rotated_glob=_env("SHIPPER_WAZUH_ROTATED_GLOB", "/var/ossec/logs/alerts/*/*/ossec-alerts-*.json"),
            suricata_rotated_glob=_env("SHIPPER_SURICATA_ROTATED_GLOB"),
            osquery_rotated_glob=_env("SHIPPER_OSQUERY_ROTATED_GLOB"),
            sensor_stale_seconds=float(_env("SHIPPER_SENSOR_STALE_SECONDS", "600")),
        )
        config.validate()
        return config

    @property
    def suricata_rotated(self) -> str:
        return self.suricata_rotated_glob or f"{self.suricata_eve_file}.[0-9]*"

    @property
    def osquery_rotated(self) -> str:
        return self.osquery_rotated_glob or f"{self.osquery_results_file}.[0-9]*"

    def validate(self) -> None:
        missing = [
            name for name, value in (
                ("BLACK_ONYX_COLLECTOR_TENANT_ID", self.tenant_id),
                ("BLACK_ONYX_COLLECTOR_GATEWAY_URL", self.gateway_url),
                ("BLACK_ONYX_COLLECTOR_INGEST_KEY", self.ingest_key),
            ) if not value
        ]
        if "wazuh" in self.sources and self.wazuh_push:
            missing += [
                name for name, value in (
                    ("BLACK_ONYX_URL", self.tip_url),
                    ("BLACK_ONYX_CONNECTOR_ID", self.connector_id),
                    ("BLACK_ONYX_CONNECTOR_TOKEN", self.connector_token),
                ) if not value
            ]
        if "suricata" in self.sources and not self.sensor_asset_id:
            missing.append("BLACK_ONYX_COLLECTOR_ASSET_ID")
        if "osquery" in self.sources and not self.sensor_asset_id:
            missing.append("BLACK_ONYX_COLLECTOR_ASSET_ID")
        if self.wazuh_api_url and not (self.wazuh_api_user and self.wazuh_api_password):
            missing.append("WAZUH_API_USER/WAZUH_API_PASSWORD")
        if missing:
            raise ValueError(f"Missing required settings: {', '.join(missing)}")
        if self.heartbeat_seconds <= 0 or self.flush_seconds <= 0 or self.sensor_stale_seconds <= 0:
            raise ValueError(
                "SHIPPER_HEARTBEAT_SECONDS, SHIPPER_FLUSH_SECONDS and SHIPPER_SENSOR_STALE_SECONDS must be positive"
            )
        if self.gateway_batch < 1 or self.gateway_max_bytes < 4096:
            raise ValueError("SHIPPER_GATEWAY_BATCH must be >= 1 and SHIPPER_GATEWAY_MAX_BYTES >= 4096")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError("BLACK_ONYX_COLLECTOR_ASSET_CRITICALITY must be between 0 and 1")


# -------------------------------------------------------------------- http


class DeliveryError(RuntimeError):
    """Raised when a destination did not accept a batch; the batch is retried."""


def ssl_context(ca_file: str = "", insecure: bool = False) -> ssl.SSLContext:
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=ca_file or None)


def http_json(
    method: str, url: str, *, body: Any = None, headers: dict[str, str] | None = None,
    context: ssl.SSLContext | None = None, timeout: float = 15.0,
) -> tuple[int, Any]:
    data = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DeliveryError(f"{method} {url} failed: {exc}") from exc
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = raw.decode("utf-8", "replace")
    return status, parsed


def chunk_by_limits(items: list[dict[str, Any]], max_count: int, max_bytes: int) -> list[list[dict[str, Any]]]:
    """Split items into batches that respect both an item count and a JSON byte budget."""
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    size = 0
    for item in items:
        item_size = len(json.dumps(item, separators=(",", ":")).encode("utf-8")) + 1
        if current and (len(current) >= max_count or size + item_size > max_bytes):
            batches.append(current)
            current, size = [], 0
        current.append(item)
        size += item_size
    if current:
        batches.append(current)
    return batches


def _too_large(status: int, body: Any) -> bool:
    text = json.dumps(body) if isinstance(body, (dict, list)) else str(body or "")
    return status == 413 or (status == 400 and ("exceeds max size" in text or "too large" in text))


class Sender:
    def __init__(self, config: ShipperConfig) -> None:
        self.config = config
        self._context = ssl_context(config.ca_file)

    def _gateway(self, route: str, envelopes: list[dict[str, Any]]) -> None:
        for batch in chunk_by_limits(envelopes, self.config.gateway_batch, self.config.gateway_max_bytes):
            self._gateway_batch(route, batch)

    def _gateway_batch(self, route: str, batch: list[dict[str, Any]]) -> None:
        status, body = http_json(
            "POST", f"{self.config.gateway_url}{route}", body={"events": batch},
            headers={"X-API-Key": self.config.ingest_key, "X-Tenant-Id": self.config.tenant_id},
            context=self._context,
        )
        if status == 200:
            return
        if _too_large(status, body):
            if len(batch) > 1:
                middle = len(batch) // 2
                self._gateway_batch(route, batch[:middle])
                self._gateway_batch(route, batch[middle:])
                return
            logger.error("gateway %s refused a single event as too large (%s); dropping it", route, status)
            return
        if status in (207, 422):
            # Per-event outcomes: validation rejects are already in the gateway DLQ,
            # but a publish failure means Kafka was unavailable and must be retried.
            results = body.get("results") if isinstance(body, dict) else None
            errors = [r.get("error", "") for r in results or [] if isinstance(r, dict) and r.get("status") == "rejected"]
            if any(str(error).startswith("publish failed") for error in errors):
                raise DeliveryError(f"gateway {route} could not publish events: {errors[:3]}")
            logger.warning("gateway %s rejected %d event(s) to its DLQ: %s", route, len(errors), errors[:3])
            return
        raise DeliveryError(f"gateway {route} returned {status}: {body}")

    def host_state(self, envelopes: list[dict[str, Any]]) -> None:
        if envelopes:
            self._gateway("/api/v1/ingest/host-state", envelopes)

    def suricata(self, envelopes: list[dict[str, Any]]) -> None:
        if envelopes:
            self._gateway("/api/v1/ingest/suricata", envelopes)

    def connector_push(self, alerts: list[dict[str, Any]]) -> None:
        for batch in chunk_by_limits(alerts, CONNECTOR_PUSH_MAX, CONNECTOR_PUSH_MAX_BYTES):
            self._connector_batch(batch)

    def _connector_batch(self, batch: list[dict[str, Any]]) -> None:
        url = f"{self.config.tip_url}/api/v1/connectors/{urllib.parse.quote(self.config.connector_id)}/push"
        status, body = http_json(
            "POST", url, body={"detections": batch},
            headers={"X-Connector-Token": self.config.connector_token}, context=self._context,
        )
        if _too_large(status, body):
            if len(batch) > 1:
                middle = len(batch) // 2
                self._connector_batch(batch[:middle])
                self._connector_batch(batch[middle:])
                return
            logger.error("connector push refused a single alert as too large (%s); dropping it", status)
            return
        if status >= 400:
            raise DeliveryError(f"connector push returned {status}: {body}")
        if isinstance(body, dict) and body.get("error"):
            raise DeliveryError(f"connector push failed: {body['error']}")
        if isinstance(body, dict) and body.get("errors"):
            logger.warning("connector push: %s of %s detections failed to ingest", body["errors"], len(batch))


# ------------------------------------------------------------------ assets


class AssetEnroller:
    """Create assets in asset-registry once; never overwrite analyst edits."""

    RETRY_SECONDS = 300.0

    def __init__(self, config: ShipperConfig) -> None:
        self.config = config
        self._context = ssl_context(config.ca_file)
        self._known: set[str] = set()
        self._retry_at: dict[str, float] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue(maxsize=10_000)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.config.asset_registry_url and self.config.asset_registry_key)

    def submit(
        self, asset_id: str, *, name: str, asset_type: str, ip_address: str | None, tags: dict[str, str],
    ) -> None:
        """Queue an enrollment without blocking the tailing loop."""
        if not self.enabled or not asset_id:
            return
        with self._lock:
            if asset_id in self._known or asset_id in self._pending:
                return
            if time.monotonic() < self._retry_at.get(asset_id, 0.0):
                return
            self._pending.add(asset_id)
        details = {"name": name, "asset_type": asset_type, "ip_address": ip_address, "tags": tags}
        try:
            self._queue.put_nowait((asset_id, details))
        except queue.Full:
            with self._lock:
                self._pending.discard(asset_id)

    def start(self) -> None:
        if self.enabled and self._thread is None:
            self._thread = threading.Thread(target=self._work, name="asset-enroller", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def drain(self) -> None:
        """Process every queued enrollment on the calling thread."""
        while True:
            try:
                asset_id, details = self._queue.get_nowait()
            except queue.Empty:
                return
            self._process(asset_id, details)

    def _work(self) -> None:
        while not self._stop.is_set():
            try:
                asset_id, details = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            self._process(asset_id, details)

    def _process(self, asset_id: str, details: dict[str, Any]) -> None:
        try:
            self.ensure(asset_id, **details)
        finally:
            with self._lock:
                self._pending.discard(asset_id)

    def ensure(
        self, asset_id: str, *, name: str, asset_type: str, ip_address: str | None, tags: dict[str, str],
    ) -> None:
        if not self.enabled or not asset_id or asset_id in self._known:
            return
        with self._lock:
            if time.monotonic() < self._retry_at.get(asset_id, 0.0):
                return
            self._retry_at[asset_id] = time.monotonic() + self.RETRY_SECONDS
        url = f"{self.config.asset_registry_url}/api/v1/assets/{urllib.parse.quote(asset_id, safe='')}"
        headers = {"X-Tenant-Id": self.config.tenant_id, "X-Service-Key": self.config.asset_registry_key}
        try:
            status, _ = http_json("GET", url, headers=headers, context=self._context, timeout=5.0)
            if status == 200:
                with self._lock:
                    self._known.add(asset_id)
                return
            if status != 404:
                logger.warning("asset-registry lookup for %s returned %s", asset_id, status)
                return
            body: dict[str, Any] = {
                "asset_type": asset_type,
                "name": (name or asset_id)[:256],
                "environment": self.config.environment,
                "criticality": self.config.criticality,
                "tags": {"managed_by": "black-onyx-shipper", **tags},
                "active": True,
            }
            if ip_address:
                body["ip_address"] = ip_address[:64]
            status, response = http_json("PUT", url, body=body, headers=headers, context=self._context, timeout=5.0)
        except DeliveryError as exc:
            logger.warning("asset-registry enrollment for %s failed: %s", asset_id, exc)
            return
        if status in (200, 201):
            with self._lock:
                self._known.add(asset_id)
        else:
            logger.warning("asset-registry enrollment for %s returned %s: %s", asset_id, status, response)


# -------------------------------------------------------------- wazuh api


def fetch_active_agents(config: ShipperConfig) -> list[dict[str, Any]]:
    """List active agents from the Wazuh server API (JWT auth)."""
    context = ssl_context(config.wazuh_api_ca_file, config.wazuh_api_insecure)
    credentials = base64.b64encode(f"{config.wazuh_api_user}:{config.wazuh_api_password}".encode()).decode()
    status, body = http_json(
        "POST", f"{config.wazuh_api_url}/security/user/authenticate",
        headers={"Authorization": f"Basic {credentials}"}, context=context,
    )
    token = _dict(_dict(body).get("data")).get("token")
    if status != 200 or not token:
        raise DeliveryError(f"Wazuh API authentication returned {status}")
    agents: list[dict[str, Any]] = []
    offset = 0
    while True:
        query = urllib.parse.urlencode({
            "status": "active", "limit": 500, "offset": offset, "select": "id,name,ip,os.platform",
        })
        status, body = http_json(
            "GET", f"{config.wazuh_api_url}/agents?{query}",
            headers={"Authorization": f"Bearer {token}"}, context=context,
        )
        if status != 200:
            raise DeliveryError(f"Wazuh API agents returned {status}")
        data = _dict(_dict(body).get("data"))
        items = [item for item in data.get("affected_items") or [] if isinstance(item, dict)]
        agents.extend(items)
        offset += len(items)
        if not items or offset >= int(data.get("total_affected_items") or 0):
            return agents


# ------------------------------------------------------------------ tailing


def fingerprint_handle(handle: IO[bytes]) -> str:
    """Hash of the first complete line (bounded), stable once that line is written."""
    handle.seek(0)
    head = handle.read(FINGERPRINT_BYTES)
    end = head.find(b"\n")
    if end < 0:
        return hashlib.sha256(head).hexdigest()[:16] if len(head) >= FINGERPRINT_BYTES else ""
    return hashlib.sha256(head[: end + 1]).hexdigest()[:16]


@dataclass
class TailRead:
    lines: list[tuple[int, str]]
    offset: int
    inode: int | None
    fingerprint: str


@dataclass
class FileTail:
    """Byte-offset tailer that drains rotated files before following the new one.

    A file is identified by inode plus a fingerprint of its first line, so a new
    file that reuses the old inode is not mistaken for the old one. Handles stay
    open across rotation so data is still readable after a rename or unlink.
    """

    path: Path
    offset: int = 0
    inode: int | None = None
    fingerprint: str = ""
    rotated_glob: str = ""
    _handles: dict[int, IO[bytes]] = field(default_factory=dict, repr=False)
    _skip_partial: bool = field(default=False, repr=False)

    def close(self) -> None:
        for handle in self._handles.values():
            handle.close()
        self._handles.clear()

    def _open(self, path: Path | str, inode: int) -> IO[bytes] | None:
        handle = self._handles.get(inode)
        if handle is not None:
            return handle
        try:
            handle = open(path, "rb")  # noqa: SIM115 - kept open to survive rotation
        except OSError:
            return None
        if os.fstat(handle.fileno()).st_ino != inode:
            handle.close()
            return None
        self._handles[inode] = handle
        return handle

    def _forget_except(self, keep: set[int]) -> None:
        for inode in list(self._handles):
            if inode not in keep:
                self._handles.pop(inode).close()

    def _locate_previous(self) -> IO[bytes] | None:
        """Find the file the saved state points at after it was rotated away."""
        if self.inode is None:
            return None
        handle = self._handles.get(self.inode)
        if handle is not None:
            return handle
        for candidate in sorted(glob.glob(self.rotated_glob)) if self.rotated_glob else []:
            try:
                if os.stat(candidate).st_ino != self.inode:
                    continue
            except OSError:
                continue
            handle = self._open(candidate, self.inode)
            if handle is not None and (not self.fingerprint or fingerprint_handle(handle) == self.fingerprint):
                return handle
        return None

    def _read_from(self, handle: IO[bytes], offset: int, inode: int, fingerprint: str) -> TailRead:
        handle.seek(offset)
        chunk = handle.read(MAX_READ_BYTES)
        if self._skip_partial:
            newline = chunk.find(b"\n")
            if newline < 0:
                return TailRead([], offset + len(chunk), inode, fingerprint)
            self._skip_partial = False
            offset += newline + 1
            chunk = chunk[newline + 1:]
        end = chunk.rfind(b"\n")
        if end < 0:
            if len(chunk) >= MAX_READ_BYTES:
                logger.warning("%s: skipping a line longer than %d bytes", self.path, MAX_READ_BYTES)
                self._skip_partial = True
                return TailRead([], offset + len(chunk), inode, fingerprint)
            return TailRead([], offset, inode, fingerprint)
        lines: list[tuple[int, str]] = []
        position = offset
        for raw in chunk[: end + 1].split(b"\n")[:-1]:
            lines.append((position, raw.decode("utf-8", "replace")))
            position += len(raw) + 1
        return TailRead(lines, offset + end + 1, inode, fingerprint)

    def read(self, start_at_end: bool) -> TailRead:
        """Return complete lines with their byte offsets plus the position to commit."""
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            stat = None
        current = self._open(self.path, stat.st_ino) if stat is not None else None
        current_fp = fingerprint_handle(current) if current is not None else ""

        if self.inode is None:
            if current is None or stat is None:
                return TailRead([], self.offset, None, "")
            offset = stat.st_size if start_at_end and self.offset == 0 else self.offset
            self._forget_except({stat.st_ino})
            return self._read_from(current, offset, stat.st_ino, current_fp)

        same_file = (
            stat is not None and stat.st_ino == self.inode
            and (not self.fingerprint or not current_fp or current_fp == self.fingerprint)
        )
        if same_file and current is not None and stat is not None:
            offset = 0 if stat.st_size < self.offset else self.offset
            self._forget_except({stat.st_ino})
            return self._read_from(current, offset, stat.st_ino, self.fingerprint or current_fp)

        # Same inode with a different first line is copy-truncate: nothing old left to drain.
        reused_inode = stat is not None and stat.st_ino == self.inode
        previous = None if reused_inode else self._locate_previous()
        if previous is not None:
            if os.fstat(previous.fileno()).st_size > self.offset:
                return self._read_from(previous, self.offset, self.inode, self.fingerprint)
        elif not reused_inode:
            logger.warning(
                "%s: rotated file (inode %s) is no longer readable; unread data after offset %d is lost",
                self.path, self.inode, self.offset,
            )
        if current is None or stat is None:
            return TailRead([], self.offset, self.inode, self.fingerprint)
        self._skip_partial = False
        self._forget_except({stat.st_ino})
        return self._read_from(current, 0, stat.st_ino, current_fp)


def load_state(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except ValueError:
        logger.warning("state file %s is corrupt; starting fresh", path)
        return {}
    return data if isinstance(data, dict) else {}


def save_state(path: Path, state: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    os.replace(tmp, path)


# ------------------------------------------------------------------ shipper


@dataclass
class Batch:
    pushes: list[dict[str, Any]] = field(default_factory=list)
    host_state: list[dict[str, Any]] = field(default_factory=list)
    suricata: list[dict[str, Any]] = field(default_factory=list)


class Shipper:
    def __init__(self, config: ShipperConfig, sender: Sender | None = None, enroller: AssetEnroller | None = None):
        self.config = config
        self.sender = sender or Sender(config)
        self.enroller = enroller or AssetEnroller(config)
        self.tails: dict[str, FileTail] = {}
        state = load_state(config.state_file)
        sources = (
            ("wazuh", config.wazuh_alerts_file, config.wazuh_rotated_glob),
            ("suricata", config.suricata_eve_file, config.suricata_rotated),
            ("osquery", config.osquery_results_file, config.osquery_rotated),
        )
        for source, path, rotated_glob in sources:
            if source in config.sources:
                saved = state.get(source) or {}
                self.tails[source] = FileTail(
                    path=path, offset=int(saved.get("offset") or 0),
                    inode=saved.get("inode") if saved.get("inode") is not None else None,
                    fingerprint=str(saved.get("fingerprint") or ""),
                    rotated_glob=rotated_glob,
                )
        self.agents_seen: dict[str, dict[str, Any]] = {}
        self._last_heartbeat = 0.0
        self._stop = threading.Event()

    def stop(self, *_: Any) -> None:
        self._stop.set()
        self.enroller.stop()

    def _state(self) -> dict[str, dict[str, Any]]:
        state: dict[str, dict[str, Any]] = {}
        for source, tail in self.tails.items():
            entry: dict[str, Any] = {"offset": tail.offset}
            if tail.inode is not None:
                entry["inode"] = tail.inode
            if tail.fingerprint:
                entry["fingerprint"] = tail.fingerprint
            state[source] = entry
        return state

    def route_wazuh_line(self, line: str, position: int, batch: Batch) -> None:
        try:
            alert = json.loads(line)
        except ValueError:
            logger.warning("skipping non-JSON Wazuh alert line at offset %d", position)
            return
        if not isinstance(alert, dict):
            return
        routing = classify_wazuh_alert(alert, tenant_id=self.config.tenant_id, min_level=self.config.min_level)
        if routing.agent:
            agent_id = str(routing.agent.get("id"))
            if not self.config.wazuh_api_url:
                self.agents_seen[agent_id] = routing.agent
            self.enroller.submit(
                wazuh_asset_id(agent_id), name=str(routing.agent.get("name") or agent_id), asset_type="host",
                ip_address=routing.agent.get("ip"), tags={"wazuh_agent_id": agent_id},
            )
        if routing.push and self.config.wazuh_push:
            batch.pushes.append(alert)
        if routing.host_state:
            seed = f"wazuh:{self.tails['wazuh'].inode}:{position}:{line}"
            batch.host_state.append(host_state_envelope(
                routing.host_state, collector_id=self.config.collector_id, seed=seed,
            ))

    def route_suricata_line(self, line: str, position: int, batch: Batch) -> None:
        try:
            raw = json.loads(line)
        except ValueError:
            logger.warning("skipping non-JSON EVE line at offset %d", position)
            return
        if not isinstance(raw, dict):
            return
        envelope = suricata_envelope(
            raw, tenant_id=self.config.tenant_id, collector_id=self.config.collector_id,
            sensor_id=self.config.sensor_id, asset_id=self.config.sensor_asset_id,
            seed=f"suricata:{self.tails['suricata'].inode}:{position}:{line}",
        )
        if envelope:
            batch.suricata.append(envelope)

    def route_osquery_line(self, line: str, position: int, batch: Batch) -> None:
        try:
            raw = json.loads(line)
        except ValueError:
            logger.warning("skipping non-JSON osquery result line at offset %d", position)
            return
        envelope = osquery_envelope(
            raw,
            tenant_id=self.config.tenant_id,
            asset_id=self.config.sensor_asset_id,
            collector_id=self.config.collector_id,
            hostname=self.config.hostname or self.config.sensor_asset_id,
            os_family=self.config.os_family or "linux",
            seed=f"osquery:{self.tails['osquery'].inode}:{position}:{line}",
        )
        if envelope:
            batch.host_state.append(envelope)

    def deliver(self, batch: Batch) -> None:
        if batch.pushes:
            self.sender.connector_push(batch.pushes)
        self.sender.host_state(batch.host_state)
        self.sender.suricata(batch.suricata)

    def poll_once(self) -> bool:
        """Read, route, and deliver one chunk per source. Returns True if lines were read."""
        did_work = False
        for source, tail in self.tails.items():
            previous = (tail.offset, tail.inode, tail.fingerprint)
            result = tail.read(self.config.start_at_end)
            # Route with the inode being read so retry seeds (and event ids) stay stable.
            tail.inode, tail.fingerprint = result.inode, result.fingerprint
            batch = Batch()
            if source == "wazuh":
                router = self.route_wazuh_line
            elif source == "suricata":
                router = self.route_suricata_line
            elif source == "osquery":
                router = self.route_osquery_line
            else:
                raise RuntimeError(f"unsupported shipper source: {source}")
            for position, line in result.lines:
                if line.strip():
                    router(line, position, batch)
            try:
                self.deliver(batch)
            except DeliveryError:
                tail.offset, tail.inode, tail.fingerprint = previous
                raise
            tail.offset = result.offset
            if (tail.offset, tail.inode, tail.fingerprint) != previous:
                save_state(self.config.state_file, self._state())
            did_work = did_work or bool(result.lines)
        return did_work

    def _wazuh_heartbeats(self) -> tuple[list[dict[str, Any]], list[str]]:
        if self.config.wazuh_api_url:
            agents = fetch_active_agents(self.config)
            seen_snapshot: list[str] = []
        else:
            agents = list(self.agents_seen.values())
            seen_snapshot = list(self.agents_seen)
        envelopes: list[dict[str, Any]] = []
        for agent in agents:
            agent_id = str(agent.get("id") or "").strip()
            if not agent_id:
                continue
            asset_id = wazuh_asset_id(agent_id)
            name = str(agent.get("name") or agent_id)
            self.enroller.submit(
                asset_id, name=name, asset_type="host", ip_address=agent.get("ip"),
                tags={"wazuh_agent_id": agent_id},
            )
            envelopes.append(agent_status_envelope(
                tenant_id=self.config.tenant_id, asset_id=asset_id, hostname=name,
                os_family=os_family_from_platform(_dict(agent.get("os")).get("platform")),
                collector_id=self.config.collector_id, source_type="wazuh",
            ))
        return envelopes, seen_snapshot

    def _sensor_is_fresh(self) -> bool:
        """Suricata writes stats to eve.json on a timer, so a stale file means a stalled sensor."""
        try:
            modified = self.config.suricata_eve_file.stat().st_mtime
        except OSError:
            return False
        return time.time() - modified <= self.config.sensor_stale_seconds

    def heartbeat(self) -> None:
        envelopes: list[dict[str, Any]] = []
        seen_snapshot: list[str] = []
        failure: DeliveryError | None = None
        if "wazuh" in self.config.sources:
            try:
                wazuh_envelopes, seen_snapshot = self._wazuh_heartbeats()
                envelopes.extend(wazuh_envelopes)
            except DeliveryError as exc:
                failure = exc
        if "suricata" in self.config.sources:
            if self._sensor_is_fresh():
                self.enroller.submit(
                    self.config.sensor_asset_id, name=self.config.sensor_id or self.config.sensor_asset_id,
                    asset_type="network_sensor", ip_address=None, tags={"role": "suricata-sensor"},
                )
                envelopes.append(agent_status_envelope(
                    tenant_id=self.config.tenant_id, asset_id=self.config.sensor_asset_id,
                    hostname=self.config.sensor_id, os_family="linux",
                    collector_id=self.config.collector_id, source_type="suricata",
                ))
            else:
                logger.warning(
                    "%s has not been written for over %.0fs; withholding the sensor heartbeat",
                    self.config.suricata_eve_file, self.config.sensor_stale_seconds,
                )
        if "osquery" in self.config.sources:
            self.enroller.submit(
                self.config.sensor_asset_id,
                name=self.config.hostname or self.config.sensor_asset_id,
                asset_type="host",
                ip_address=None,
                tags={"role": "osquery-host", "os_family": self.config.os_family or "linux"},
            )
            envelopes.append(agent_status_envelope(
                tenant_id=self.config.tenant_id,
                asset_id=self.config.sensor_asset_id,
                hostname=self.config.hostname or self.config.sensor_asset_id,
                os_family=self.config.os_family or "linux",
                collector_id=self.config.collector_id,
                source_type="osquery",
            ))
        self.sender.host_state(envelopes)
        for agent_id in seen_snapshot:
            self.agents_seen.pop(agent_id, None)
        if failure is not None:
            raise failure

    def run(self) -> None:
        self.enroller.start()
        backoff = self.config.flush_seconds
        try:
            while not self._stop.is_set():
                if time.monotonic() - self._last_heartbeat >= self.config.heartbeat_seconds:
                    try:
                        self.heartbeat()
                    except DeliveryError as exc:
                        logger.warning("heartbeat incomplete, retrying next interval: %s", exc)
                    self._last_heartbeat = time.monotonic()
                try:
                    did_work = self.poll_once()
                    backoff = self.config.flush_seconds
                    if not did_work:
                        self._stop.wait(self.config.flush_seconds)
                except DeliveryError as exc:
                    logger.warning("delivery failed, retrying in %.0fs: %s", backoff, exc)
                    self._stop.wait(backoff)
                    backoff = min(backoff * 2, 300.0)
        finally:
            for tail in self.tails.values():
                tail.close()


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("SHIPPER_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        config = ShipperConfig.from_env()
    except ValueError as exc:
        logger.error("%s", exc)
        return 2
    shipper = Shipper(config)
    signal.signal(signal.SIGTERM, shipper.stop)
    signal.signal(signal.SIGINT, shipper.stop)
    logger.info("shipping sources=%s tenant=%s", ",".join(sorted(config.sources)), config.tenant_id)
    shipper.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
