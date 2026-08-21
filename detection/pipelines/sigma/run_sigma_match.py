#!/usr/bin/env python3
"""Offline Sigma-like matcher for curated YAML rules + JSON/JSONL events."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


def _parse_yaml_subset(text: str) -> dict[str, Any]:
    """Indentation-based YAML subset sufficient for curated Sigma rules."""
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))

    def parse_scalar(value: str) -> Any:
        if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
            return value[1:-1]
        lower = value.lower()
        if lower in {"true", "false"}:
            return lower == "true"
        if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
            return int(value)
        try:
            return float(value)
        except ValueError:
            return value

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        mapping: dict[str, Any] = {}
        sequence: list[Any] | None = None
        i = index
        while i < len(lines):
            cur_indent, content = lines[i]
            if cur_indent < indent:
                break
            if cur_indent > indent:
                raise ValueError(f"unexpected indent at: {content}")
            if content.startswith("- "):
                if sequence is None:
                    sequence = []
                item_text = content[2:].strip()
                if item_text and ":" in item_text and not item_text.startswith("{"):
                    # list of single-key maps not used by our rules; treat as scalar
                    sequence.append(parse_scalar(item_text))
                    i += 1
                    continue
                if item_text:
                    sequence.append(parse_scalar(item_text))
                    i += 1
                    continue
                child, i = parse_block(i + 1, cur_indent + 2)
                sequence.append(child)
                continue
            if ":" not in content:
                raise ValueError(f"expected key: value at {content}")
            key, _, rest = content.partition(":")
            key = key.strip()
            rest = rest.strip()
            i += 1
            if rest:
                mapping[key] = parse_scalar(rest)
                continue
            if i < len(lines) and lines[i][0] > cur_indent:
                child, i = parse_block(i, lines[i][0])
                mapping[key] = child
            else:
                mapping[key] = None
        if sequence is not None and not mapping:
            return sequence, i
        return mapping, i

    root, _ = parse_block(0, lines[0][0] if lines else 0)
    if not isinstance(root, dict):
        raise ValueError("rule root must be a mapping")
    return root


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("{"):
        data = json.loads(stripped)
        if not isinstance(data, dict):
            raise ValueError("rule root must be a mapping")
        return data
    if yaml is not None:
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("rule root must be a mapping")
        return data
    return _parse_yaml_subset(text)


def load_rules(rules_dir: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml")):
        data = _parse_simple_yaml(path.read_text(encoding="utf-8"))
        data["_path"] = str(path)
        rules.append(data)
    return rules


def load_events(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    if path.suffix.lower() == ".jsonl" or "\n{" in text or text.startswith("{"):
        # Try JSON array / object first, then JSONL.
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass
        events: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip().lstrip("\ufeff")
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
        return events
    data = json.loads(text)
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)]
    if isinstance(data, dict):
        return [data]
    raise ValueError("events file must be object, array, or JSONL")


def _event_id(event: dict[str, Any]) -> int | None:
    for key in ("EventID", "event_id", "eventId"):
        if key in event and event[key] is not None:
            try:
                return int(event[key])
            except (TypeError, ValueError):
                continue
    return None


def _field(event: dict[str, Any], name: str) -> Any:
    if name in event:
        return event[name]
    # Common aliases
    aliases = {
        "Image": ["image", "process_path", "NewProcessName"],
        "CommandLine": ["command_line", "cmdline", "ProcessCommandLine"],
        "TargetUserName": ["target_user", "user", "TargetUser"],
        "Message": ["message", "msg"],
    }
    for alt in aliases.get(name, []):
        if alt in event:
            return event[alt]
    return None


def _endswith_match(value: Any, suffixes: list[str]) -> bool:
    text = str(value or "")
    lower = text.lower()
    return any(lower.endswith(s.lower()) for s in suffixes)


def _selection_match(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    for key, expected in selection.items():
        if key.endswith("|endswith"):
            field = key.split("|", 1)[0]
            value = _field(event, field)
            suffixes = expected if isinstance(expected, list) else [expected]
            if not _endswith_match(value, [str(s) for s in suffixes]):
                return False
            continue
        if key.endswith("|contains"):
            field = key.split("|", 1)[0]
            value = str(_field(event, field) or "").lower()
            needles = expected if isinstance(expected, list) else [expected]
            if not any(str(n).lower() in value for n in needles):
                return False
            continue
        value = _field(event, key)
        if key in {"EventID", "event_id"}:
            eid = _event_id(event)
            options = expected if isinstance(expected, list) else [expected]
            want = {int(x) for x in options}
            if eid not in want:
                return False
            continue
        options = expected if isinstance(expected, list) else [expected]
        if value not in options and str(value) not in {str(x) for x in options}:
            return False
    return True


def _keywords_match(event: dict[str, Any], keywords: list[str]) -> bool:
    blob = " ".join(
        str(_field(event, k) or "")
        for k in ("CommandLine", "Message", "Image", "ParentCommandLine")
    ).lower()
    return any(str(k).lower() in blob for k in keywords)


def _parse_ts(event: dict[str, Any]) -> datetime:
    raw = event.get("occurred_at") or event.get("timestamp") or event.get("@timestamp")
    if isinstance(raw, (int, float)):
        ts = float(raw)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(raw, str) and raw.strip():
        text = raw.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(tz=timezone.utc)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return datetime.now(tz=timezone.utc)


def match_event(event: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any] | None:
    detection = rule.get("detection") or {}
    selection = detection.get("selection") or {}
    if selection and not _selection_match(event, selection):
        return None
    keywords = detection.get("keywords") or []
    if keywords and not _keywords_match(event, list(keywords)):
        return None
    # Burst rules are handled separately.
    if detection.get("burst"):
        return None
    return _finding(event, rule)


def _finding(event: dict[str, Any], rule: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    occurred = _parse_ts(event)
    level = str(rule.get("level") or "medium").lower()
    score = {"critical": 0.95, "high": 0.85, "medium": 0.6, "low": 0.35}.get(level, 0.6)
    payload = {
        "finding_type": "sigma_rule",
        "rule_id": rule.get("id"),
        "title": rule.get("title"),
        "severity": level,
        "score": score,
        "mitre_techniques": list(rule.get("mitre_techniques") or []),
        "tenant_id": event.get("tenant_id") or "default",
        "asset_id": event.get("asset_id") or event.get("Computer") or "unknown",
        "occurred_at": occurred.isoformat().replace("+00:00", "Z"),
        "evidence": {
            "event_id": _event_id(event),
            "image": _field(event, "Image"),
            "command_line": _field(event, "CommandLine"),
            "target_user": _field(event, "TargetUserName"),
            "rule_path": rule.get("_path"),
        },
    }
    if extra:
        payload["evidence"] = {**payload["evidence"], **extra}
    return payload


def match_bursts(events: list[dict[str, Any]], rule: dict[str, Any]) -> list[dict[str, Any]]:
    detection = rule.get("detection") or {}
    burst = detection.get("burst")
    if not burst:
        return []
    selection = detection.get("selection") or {}
    field = str(burst.get("field") or "TargetUserName")
    count = int(burst.get("count") or 5)
    window_seconds = int(burst.get("window_seconds") or 120)

    candidates: list[tuple[datetime, dict[str, Any]]] = []
    for event in events:
        if selection and not _selection_match(event, selection):
            continue
        candidates.append((_parse_ts(event), event))
    candidates.sort(key=lambda item: item[0])

    findings: list[dict[str, Any]] = []
    buckets: dict[str, list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
    for ts, event in candidates:
        key = str(_field(event, field) or event.get("asset_id") or "unknown")
        bucket = buckets[key]
        bucket.append((ts, event))
        # Drop events outside window relative to newest.
        cutoff = ts.timestamp() - window_seconds
        buckets[key] = [(t, e) for t, e in bucket if t.timestamp() >= cutoff]
        if len(buckets[key]) >= count:
            last_event = buckets[key][-1][1]
            findings.append(
                _finding(
                    last_event,
                    rule,
                    extra={
                        "burst_field": field,
                        "burst_key": key,
                        "burst_count": len(buckets[key]),
                        "window_seconds": window_seconds,
                    },
                )
            )
            buckets[key] = []
    return findings


def run_match(events: list[dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule in rules:
        detection = rule.get("detection") or {}
        if detection.get("burst"):
            findings.extend(match_bursts(events, rule))
            continue
        for event in events:
            hit = match_event(event, rule)
            if hit is not None:
                findings.append(hit)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path, help="JSON / JSONL events file")
    parser.add_argument(
        "--rules",
        type=Path,
        default=Path(__file__).resolve().parent / "rules",
        help="Directory of Sigma-like YAML rules",
    )
    args = parser.parse_args(argv)
    rules = load_rules(args.rules)
    events = load_events(args.events)
    findings = run_match(events, rules)
    json.dump(findings, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
