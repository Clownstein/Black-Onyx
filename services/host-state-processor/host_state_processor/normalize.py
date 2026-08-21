from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_PROCESS_EVENT_TYPES = {
    "host_state.process_event",
    "host_state.process_snapshot",
    "process_event",
    "process_snapshot",
    "process",
}
_SOCKET_EVENT_TYPES = {
    "host_state.socket_snapshot",
    "socket_snapshot",
    "socket",
    "listening_ports",
}
_AUTORUN_EVENT_TYPES = {
    "host_state.autorun_snapshot",
    "autorun_snapshot",
    "autorun",
}
_SESSION_EVENT_TYPES = {
    "host_state.user_session",
    "user_session",
    "session",
}

_OSQUERY_NAME_TO_EVENT = {
    "processes": "host_state.process_snapshot",
    "process_events": "host_state.process_event",
    "listening_ports": "host_state.socket_snapshot",
    "process_open_sockets": "host_state.socket_snapshot",
    "startup_items": "host_state.autorun_snapshot",
    "services": "host_state.autorun_snapshot",
    "scheduled_tasks": "host_state.autorun_snapshot",
    "logged_in_users": "host_state.user_session",
}


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit():
            return _parse_ts(int(text))
        text = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    return None


def _basename(path: str | None) -> str:
    if not path:
        return ""
    cleaned = path.replace("\\", "/").rstrip("/")
    if not cleaned:
        return ""
    return cleaned.rsplit("/", 1)[-1]


def _lower_name(value: Any) -> str:
    return str(value or "").strip().lower()


def _infer_os_family(payload: dict[str, Any], path: str | None) -> str | None:
    explicit = payload.get("os_family") or payload.get("os") or payload.get("platform")
    if explicit:
        text = str(explicit).strip().lower()
        if text in {"linux", "windows", "darwin", "unknown"}:
            return text
        if "win" in text:
            return "windows"
        if text in {"macos", "mac", "osx"}:
            return "darwin"
    if path:
        if path.startswith("/") and not path.lower().startswith("c:"):
            return "linux"
        if "\\" in path or path.lower().startswith("c:"):
            return "windows"
    return None


def _detect_event_type(payload: dict[str, Any], event: dict[str, Any]) -> str:
    raw_type = str(
        payload.get("event_type")
        or event.get("event_type")
        or payload.get("name")
        or ""
    ).strip()
    lowered = raw_type.lower()
    if lowered in _OSQUERY_NAME_TO_EVENT:
        return _OSQUERY_NAME_TO_EVENT[lowered]
    if lowered.startswith("host_state."):
        return lowered
    if lowered in _PROCESS_EVENT_TYPES:
        return (
            "host_state.process_event"
            if "event" in lowered
            else "host_state.process_snapshot"
        )
    if lowered in _SOCKET_EVENT_TYPES:
        return "host_state.socket_snapshot"
    if lowered in _AUTORUN_EVENT_TYPES:
        return "host_state.autorun_snapshot"
    if lowered in _SESSION_EVENT_TYPES:
        return "host_state.user_session"

    # Sysmon EID heuristics — EID 3 NetworkConnect maps to socket_snapshot for
    # thin host↔network join on asset_id + remote address/port (no PCAP required).
    eid = payload.get("EventID") or payload.get("event_id") or payload.get("eid")
    try:
        eid_int = int(eid) if eid is not None else None
    except (TypeError, ValueError):
        eid_int = None
    if eid_int == 1 or payload.get("Image") or payload.get("ParentImage"):
        return "host_state.process_event"
    if eid_int == 3 or payload.get("SourcePort") or payload.get("DestinationPort") or payload.get("DestinationIp"):
        return "host_state.socket_snapshot"
    if payload.get("local_port") is not None or payload.get("port") is not None:
        return "host_state.socket_snapshot"
    if payload.get("logon_type") is not None or payload.get("LogonType") is not None:
        return "host_state.user_session"
    if payload.get("pid") is not None or payload.get("process_name") or payload.get("name"):
        return "host_state.process_event"
    return "host_state.process_event"


def _extract_hashes(payload: dict[str, Any]) -> dict[str, str]:
    hashes = payload.get("hashes") or payload.get("Hashes")
    if isinstance(hashes, dict):
        return {str(k).lower(): str(v) for k, v in hashes.items() if v}
    if isinstance(hashes, str):
        out: dict[str, str] = {}
        for part in hashes.split(","):
            if "=" in part:
                key, value = part.split("=", 1)
                out[key.strip().lower()] = value.strip()
        return out
    out = {}
    for key in ("sha256", "sha1", "md5", "SHA256", "SHA1", "MD5"):
        if payload.get(key):
            out[key.lower()] = str(payload[key])
    return out


def _normalize_process(payload: dict[str, Any]) -> dict[str, Any]:
    nested = payload.get("process") if isinstance(payload.get("process"), dict) else {}
    path = (
        nested.get("path")
        or payload.get("path")
        or payload.get("Image")
        or payload.get("exe")
        or payload.get("executable")
    )
    name = (
        nested.get("name")
        or payload.get("name")
        or payload.get("process_name")
        or payload.get("OriginalFileName")
        or _basename(str(path) if path else None)
    )
    parent_path = (
        nested.get("parent_path")
        or payload.get("parent_path")
        or payload.get("ParentImage")
        or payload.get("parent")
    )
    parent_name = (
        nested.get("parent_name")
        or payload.get("parent_name")
        or payload.get("ParentProcessName")
        or _basename(str(parent_path) if parent_path else None)
    )
    cmdline = (
        nested.get("cmdline")
        or payload.get("cmdline")
        or payload.get("cmdline_args")
        or payload.get("CommandLine")
        or payload.get("command_line")
    )
    pid_raw = nested.get("pid") or payload.get("pid") or payload.get("ProcessId") or payload.get("process_id")
    ppid_raw = (
        nested.get("ppid")
        or payload.get("ppid")
        or payload.get("ParentProcessId")
        or payload.get("parent_pid")
    )
    user = nested.get("user") or payload.get("user") or payload.get("User") or payload.get("username")
    action = nested.get("action") or payload.get("action") or payload.get("EventType")
    if action:
        action = str(action).strip().lower()
        if action in {"created", "processcreate", "start"}:
            action = "create"
        elif action in {"terminated", "processterminate", "stop", "exit"}:
            action = "terminate"
        elif action not in {"create", "terminate", "open"}:
            action = "create"
    else:
        action = "create"

    process: dict[str, Any] = {
        "name": str(name) if name else "",
        "path": str(path) if path else None,
        "cmdline": str(cmdline) if cmdline else None,
        "user": str(user) if user else None,
        "action": action,
        "parent_name": str(parent_name) if parent_name else None,
        "parent_path": str(parent_path) if parent_path else None,
    }
    try:
        if pid_raw is not None:
            process["pid"] = int(pid_raw)
    except (TypeError, ValueError):
        pass
    try:
        if ppid_raw is not None:
            process["ppid"] = int(ppid_raw)
    except (TypeError, ValueError):
        process["ppid"] = None

    hashes = _extract_hashes({**payload, **nested})
    if hashes:
        process["hashes"] = hashes
    return process


def _normalize_socket(payload: dict[str, Any]) -> dict[str, Any]:
    nested = payload.get("socket") if isinstance(payload.get("socket"), dict) else {}
    local_port = (
        nested.get("local_port")
        or payload.get("local_port")
        or payload.get("port")
        or payload.get("SourcePort")
        or payload.get("DestinationPort")
    )
    remote_port = nested.get("remote_port") or payload.get("remote_port") or payload.get("DestinationPort")
    state = nested.get("state") or payload.get("state") or payload.get("protocol_state")
    if state:
        state = str(state).lower()
    elif payload.get("listening") or str(payload.get("name") or "").lower() == "listening_ports":
        state = "listen"
    protocol = nested.get("protocol") or payload.get("protocol") or payload.get("Protocol") or "tcp"
    pid_raw = nested.get("pid") or payload.get("pid") or payload.get("ProcessId")
    process_name = (
        nested.get("process_name")
        or payload.get("process_name")
        or payload.get("name")
        or payload.get("Image")
        or _basename(str(payload.get("path") or ""))
    )
    socket: dict[str, Any] = {
        "protocol": str(protocol).lower() if protocol else "tcp",
        "local_address": nested.get("local_address")
        or payload.get("local_address")
        or payload.get("address")
        or payload.get("SourceIp")
        or "0.0.0.0",
        "remote_address": nested.get("remote_address")
        or payload.get("remote_address")
        or payload.get("DestinationIp"),
        "state": state or "listen",
        "process_name": str(process_name) if process_name else None,
        "path": payload.get("path") or payload.get("Image"),
    }
    try:
        if local_port is not None:
            socket["local_port"] = int(local_port)
    except (TypeError, ValueError):
        pass
    try:
        if remote_port is not None:
            socket["remote_port"] = int(remote_port)
    except (TypeError, ValueError):
        pass
    try:
        if pid_raw is not None:
            socket["pid"] = int(pid_raw)
    except (TypeError, ValueError):
        pass
    return socket


def _normalize_autorun(payload: dict[str, Any]) -> dict[str, Any]:
    nested = payload.get("autorun") if isinstance(payload.get("autorun"), dict) else {}
    return {
        "name": str(nested.get("name") or payload.get("name") or payload.get("service_name") or "unknown"),
        "path": nested.get("path") or payload.get("path") or payload.get("program"),
        "source": nested.get("source") or payload.get("source") or payload.get("type"),
        "enabled": nested.get("enabled") if nested.get("enabled") is not None else payload.get("enabled"),
    }


def _normalize_session(payload: dict[str, Any]) -> dict[str, Any]:
    nested = payload.get("session") if isinstance(payload.get("session"), dict) else {}
    action = nested.get("action") or payload.get("action") or payload.get("EventType")
    if action:
        action = str(action).strip().lower()
        if action in {"login", "logon_success"}:
            action = "logon"
        elif action in {"logout"}:
            action = "logoff"
        elif action in {"failed", "logon_failed"}:
            action = "failed_logon"
    return {
        "user": str(nested.get("user") or payload.get("user") or payload.get("User") or "unknown"),
        "logon_type": nested.get("logon_type") or payload.get("logon_type") or payload.get("LogonType"),
        "source_ip": nested.get("source_ip") or payload.get("source_ip") or payload.get("IpAddress"),
        "action": action,
    }


def normalize_host_state_event(event: dict[str, Any]) -> dict[str, Any]:
    """Map osquery / Sysmon-ish envelopes into HostStateEvent-shaped dicts."""
    payload = event.get("payload") or event.get("extensions") or event
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    # Already-normalized HostStateEvent may arrive as the root or payload.
    if str(payload.get("event_type") or "").startswith("host_state.") and payload.get("asset_id"):
        source = payload
    elif str(event.get("event_type") or "").startswith("host_state.") and event.get("asset_id"):
        source = event
    else:
        source = payload

    occurred = _parse_ts(
        event.get("occurred_at")
        or source.get("occurred_at")
        or source.get("timestamp")
        or source.get("UtcTime")
        or source.get("time")
        or source.get("unixTime")
    )
    if occurred is None:
        raise ValueError("occurred_at/timestamp required")

    asset = event.get("asset") if isinstance(event.get("asset"), dict) else {}
    asset_id = str(
        source.get("asset_id")
        or asset.get("asset_id")
        or event.get("asset_id")
        or payload.get("hostIdentifier")
        or payload.get("hostname")
        or "unknown"
    )
    tenant_id = str(event.get("tenant_id") or source.get("tenant_id") or "default")
    event_type = _detect_event_type(source, event)
    path_hint = str(
        (source.get("process") or {}).get("path")
        if isinstance(source.get("process"), dict)
        else source.get("path") or source.get("Image") or ""
    )
    os_family = _infer_os_family(source, path_hint or None) or "unknown"

    normalized: dict[str, Any] = {
        "event_type": event_type,
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "service_id": source.get("service_id") or event.get("service_id") or asset.get("service_id"),
        "occurred_at": occurred.isoformat().replace("+00:00", "Z"),
        "hostname": source.get("hostname") or payload.get("hostname") or asset.get("hostname"),
        "os_family": os_family,
        "raw": source,
    }

    if event_type in {"host_state.process_event", "host_state.process_snapshot"}:
        process = _normalize_process(source)
        if not process.get("name") and not process.get("path"):
            raise ValueError("process name or path required")
        normalized["process"] = process
    elif event_type == "host_state.socket_snapshot":
        socket = _normalize_socket(source)
        if socket.get("local_port") is None:
            raise ValueError("local_port required for socket events")
        normalized["socket"] = socket
    elif event_type == "host_state.autorun_snapshot":
        normalized["autorun"] = _normalize_autorun(source)
    elif event_type == "host_state.user_session":
        normalized["session"] = _normalize_session(source)

    return normalized


def process_basename(name_or_path: str | None) -> str:
    """Return lowercased process basename without extension for comparisons."""
    base = _basename(name_or_path)
    lowered = _lower_name(base)
    if lowered.endswith(".exe"):
        return lowered[:-4]
    return lowered
