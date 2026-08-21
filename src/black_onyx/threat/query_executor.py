"""KQL/SPL-inspired query subset over local SQLite operational metadata.

Supported subset (documented for API consumers):

  source alerts|cases|assets|detections|evidence|webhooks
  | where field == value
  | where field != value
  | where field contains value
  | where field in (a, b, c)
  | where field ago Nd|Nh|Nm   (time window relative to now on a timestamp field)
  | project field1, field2
  | sort field [asc|desc]
  | summarize count() by field
  | limit N

Pipeline stages are pipe-separated. The first token selects the source table.
Equality and contains are case-insensitive for string fields.
The ``evidence`` source scrolls Qdrant collection payloads (flattened rows).
The ``webhooks`` source lists persisted inbound webhook events.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Callable

logger = logging.getLogger(__name__)

_AGO_RE = re.compile(r"^(\d+)\s*([dhm])$", re.IGNORECASE)
_EQ_RE = re.compile(r"^(\w+)\s*==\s*(.+)$")
_NEQ_RE = re.compile(r"^(\w+)\s*!=\s*(.+)$")
_CONTAINS_RE = re.compile(r"^(\w+)\s+contains\s+(.+)$", re.IGNORECASE)
_IN_RE = re.compile(r"^(\w+)\s+in\s*\((.+)\)$", re.IGNORECASE)
_AGO_CLAUSE_RE = re.compile(r"^(\w+)\s+ago\s+(\d+[dhm])$", re.IGNORECASE)
_SORT_RE = re.compile(r"^sort\s+(\w+)(?:\s+(asc|desc))?$", re.IGNORECASE)
_SUMMARIZE_RE = re.compile(
    r"^summarize\s+count\s*\(\s*\)\s+by\s+(\w+)$", re.IGNORECASE,
)


def _parse_ago(token: str) -> timedelta:
    match = _AGO_RE.match(token.strip())
    if not match:
        raise ValueError(f"Invalid ago duration '{token}' (use Nd, Nh, or Nm)")
    amount = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "d":
        return timedelta(days=amount)
    if unit == "h":
        return timedelta(hours=amount)
    return timedelta(minutes=amount)


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00").replace("+00:00", ""))
    except ValueError:
        return None


class QueryExecutor:
    """Execute the documented query subset against in-memory row sources."""

    def __init__(
        self,
        *,
        alerts_loader: Callable[[], list[dict[str, Any]]],
        cases_loader: Callable[[], list[dict[str, Any]]],
        assets_loader: Callable[[], list[dict[str, Any]]],
        detections_loader: Callable[[], list[dict[str, Any]]],
        evidence_loader: Callable[[], list[dict[str, Any]]] | None = None,
        webhooks_loader: Callable[[], list[dict[str, Any]]] | None = None,
    ) -> None:
        self._loaders = {
            "alerts": alerts_loader,
            "cases": cases_loader,
            "assets": assets_loader,
            "detections": detections_loader,
            "evidence": evidence_loader or (lambda: []),
            "webhooks": webhooks_loader or (lambda: []),
        }

    def execute(self, query: str, default_limit: int = 100) -> dict[str, Any]:
        if not query or not query.strip():
            raise ValueError("Query is empty")

        stages = [s.strip() for s in query.strip().split("|")]
        if not stages:
            raise ValueError("Query is empty")

        source = stages[0].split()[0].lower()
        if source not in self._loaders:
            raise ValueError(
                f"Unknown source '{source}'. "
                f"Supported: {', '.join(sorted(self._loaders))}"
            )

        # Allow "source alerts" or just "alerts"
        first_tokens = stages[0].split()
        if first_tokens[0].lower() == "source" and len(first_tokens) >= 2:
            source = first_tokens[1].lower()
            if source not in self._loaders:
                raise ValueError(f"Unknown source '{source}'")
        elif first_tokens[0].lower() != source:
            raise ValueError("First stage must be a source name or 'source <name>'")

        rows = [dict(r) for r in self._loaders[source]()]
        projected: list[str] | None = None
        limit = default_limit

        for stage in stages[1:]:
            if not stage:
                continue
            lower = stage.lower()
            if lower.startswith("where "):
                rows = self._apply_where(rows, stage[6:].strip())
            elif lower.startswith("project "):
                fields = [f.strip() for f in stage[8:].split(",") if f.strip()]
                projected = fields
                rows = [{f: r.get(f) for f in fields} for r in rows]
            elif lower.startswith("sort "):
                sort = _SORT_RE.match(stage.strip())
                if not sort:
                    raise ValueError(f"Invalid sort stage: {stage}")
                field, direction = sort.group(1), (sort.group(2) or "asc").lower()
                reverse = direction == "desc"

                def _sort_key(row: dict[str, Any], f: str = field) -> Any:
                    value = row.get(f)
                    if value is None:
                        return ""
                    return str(value).lower()

                rows = sorted(rows, key=_sort_key, reverse=reverse)
            elif lower.startswith("summarize "):
                summarize = _SUMMARIZE_RE.match(stage.strip())
                if not summarize:
                    raise ValueError(
                        f"Invalid summarize stage '{stage}'. "
                        "Use summarize count() by field"
                    )
                field = summarize.group(1)
                counts = Counter(str(r.get(field) or "") for r in rows)
                rows = [{field: key, "count": value} for key, value in counts.most_common()]
                projected = [field, "count"]
            elif lower.startswith("limit "):
                try:
                    limit = max(1, min(int(stage[6:].strip()), 5_000))
                except ValueError as exc:
                    raise ValueError(f"Invalid limit: {stage}") from exc
            else:
                raise ValueError(
                    f"Unsupported stage '{stage}'. "
                    "Use where / project / sort / summarize / limit."
                )

        rows = rows[:limit]
        columns = projected or (sorted({k for r in rows for k in r.keys()}) if rows else [])
        return {
            "source": source,
            "columns": columns,
            "rows": rows,
            "n": len(rows),
            "query": query,
        }

    def _apply_where(self, rows: list[dict[str, Any]], expr: str) -> list[dict[str, Any]]:
        eq = _EQ_RE.match(expr)
        if eq:
            field, raw = eq.group(1), _strip_quotes(eq.group(2))
            needle = raw.lower()
            return [
                r for r in rows
                if str(r.get(field, "")).lower() == needle
            ]

        neq = _NEQ_RE.match(expr)
        if neq:
            field, raw = neq.group(1), _strip_quotes(neq.group(2))
            needle = raw.lower()
            return [
                r for r in rows
                if str(r.get(field, "")).lower() != needle
            ]

        contains = _CONTAINS_RE.match(expr)
        if contains:
            field, raw = contains.group(1), _strip_quotes(contains.group(2))
            needle = raw.lower()
            return [
                r for r in rows
                if needle in str(r.get(field, "")).lower()
            ]

        in_match = _IN_RE.match(expr)
        if in_match:
            field, raw_list = in_match.group(1), in_match.group(2)
            needles = {
                _strip_quotes(part).lower()
                for part in raw_list.split(",")
                if part.strip()
            }
            return [
                r for r in rows
                if str(r.get(field, "")).lower() in needles
            ]

        ago = _AGO_CLAUSE_RE.match(expr)
        if ago:
            field, duration = ago.group(1), ago.group(2)
            cutoff = datetime.now() - _parse_ago(duration)
            filtered: list[dict[str, Any]] = []
            for r in rows:
                ts = _parse_ts(r.get(field))
                if ts is not None and ts >= cutoff:
                    filtered.append(r)
            return filtered

        raise ValueError(
            f"Unsupported where expression '{expr}'. "
            "Use field==value, field!=value, field contains value, "
            "field in (a,b), or field ago Nd|Nh|Nm."
        )
