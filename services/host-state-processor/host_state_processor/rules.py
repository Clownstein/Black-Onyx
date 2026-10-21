from __future__ import annotations

import re
from typing import Any

from host_state_processor.normalize import process_basename

OFFICE_PARENTS = frozenset({"winword", "excel", "outlook", "powerpnt", "msaccess"})
SUSPICIOUS_CHILDREN = frozenset(
    {"powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "cmd.exe"}
)
COMMON_LISTENERS = frozenset(
    {
        "svchost",
        "system",
        "lsass",
        "services",
        "nginx",
        "httpd",
        "apache2",
        "sshd",
        "ssh",
        "mysqld",
        "postgres",
        "sqlservr",
        "node",
        "python",
        "python3",
        "java",
        "dockerd",
        "containerd",
        "systemd",
        "rpcss",
        "spoolsv",
        "dns",
        "named",
        "redis-server",
        "mongod",
        "beam.smp",
        "grafana-server",
        "kubelet",
    }
)

_RARE_PATH_MARKERS = (
    r"\\temp\\",
    r"/temp/",
    r"\\tmp\\",
    r"/tmp/",
    r"\\appdata\\",
    r"/appdata/",
    r"\\downloads\\",
    r"/downloads/",
    r"\\users\\[^\\]+\\appdata\\local\\temp\\",
    r"/users/[^/]+/appdata/local/temp/",
)
_RARE_PATH_RE = re.compile("|".join(_RARE_PATH_MARKERS), re.IGNORECASE)


def _severity_for_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def detect_suspicious_parent_child(event: dict[str, Any]) -> dict[str, Any] | None:
    """Office parent spawning scripting interpreters (T1059.001)."""
    process = event.get("process") or {}
    if not process:
        return None
    child = process_basename(process.get("name") or process.get("path"))
    parent = process_basename(process.get("parent_name") or process.get("parent_path"))
    if not child or not parent:
        return None
    if parent not in OFFICE_PARENTS:
        return None
    if child not in SUSPICIOUS_CHILDREN and child.rstrip(".exe") not in SUSPICIOUS_CHILDREN:
        return None
    score = 0.92
    return {
        "detector": "suspicious_parent_child",
        "severity": _severity_for_score(score),
        "score": score,
        "evidence": {
            "parent_name": process.get("parent_name") or parent,
            "parent_path": process.get("parent_path"),
            "child_name": process.get("name") or child,
            "child_path": process.get("path"),
            "cmdline": process.get("cmdline"),
            "pid": process.get("pid"),
            "ppid": process.get("ppid"),
        },
        "mitre_techniques": ["T1059.001"],
    }


def detect_rare_binary_path(event: dict[str, Any]) -> dict[str, Any] | None:
    """Process path under Temp/AppData/Downloads or unsigned-looking /tmp (T1547)."""
    process = event.get("process") or {}
    path = str(process.get("path") or "")
    if not path:
        return None
    normalized = path.replace("\\", "/").lower()
    rare = bool(_RARE_PATH_RE.search(path.replace("/", "\\"))) or bool(
        _RARE_PATH_RE.search(path)
    )
    # Unsigned-looking /tmp binaries (no system package path markers).
    unsigned_tmp = normalized.startswith("/tmp/") and not any(
        marker in normalized for marker in ("/usr/", "/opt/", "/bin/", "/sbin/")
    )
    if not rare and not unsigned_tmp:
        return None
    score = 0.78 if unsigned_tmp or "temp" in normalized or "tmp" in normalized else 0.72
    if "downloads" in normalized:
        score = max(score, 0.8)
    return {
        "detector": "rare_binary_path",
        "severity": _severity_for_score(score),
        "score": score,
        "evidence": {
            "path": path,
            "name": process.get("name"),
            "cmdline": process.get("cmdline"),
            "user": process.get("user"),
            "unsigned_tmp": unsigned_tmp,
        },
        "mitre_techniques": ["T1547"],
    }


def detect_new_listening_port(
    event: dict[str, Any],
    known_ports: set[int] | None = None,
) -> dict[str, Any] | None:
    """New high listening port from an uncommon process name (T1049)."""
    socket = event.get("socket") or {}
    if not socket:
        return None
    state = str(socket.get("state") or "").lower()
    if state and state not in {"listen", "listening", "listenq"}:
        return None
    try:
        port = int(socket.get("local_port"))
    except (TypeError, ValueError):
        return None
    if port <= 1024:
        return None
    known = known_ports or set()
    if port in known:
        return None
    process_name = process_basename(socket.get("process_name") or socket.get("path"))
    if process_name in COMMON_LISTENERS:
        return None
    score = 0.7 if process_name else 0.65
    if process_name in {"powershell", "cmd", "python", "wscript", "cscript", "mshta"}:
        score = 0.88
    return {
        "detector": "new_listening_port",
        "severity": _severity_for_score(score),
        "score": score,
        "evidence": {
            "local_port": port,
            "protocol": socket.get("protocol"),
            "local_address": socket.get("local_address"),
            "process_name": socket.get("process_name") or process_name,
            "pid": socket.get("pid"),
            "state": state or "listen",
        },
        "mitre_techniques": ["T1049"],
    }


def run_rules(
    event: dict[str, Any],
    *,
    known_listening_ports: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Run all deterministic host-state detections against one normalized event."""
    detections: list[dict[str, Any]] = []
    for hit in (
        detect_suspicious_parent_child(event),
        detect_rare_binary_path(event),
        detect_new_listening_port(event, known_listening_ports),
    ):
        if hit is not None:
            detections.append(hit)
    return detections
