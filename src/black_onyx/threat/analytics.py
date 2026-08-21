"""Operations analytics — KPIs and aggregates over alerts, cases, detections, CTI."""

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Naive UTC wall clock — stored timestamps are compared after tz stripping."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

_RANGE_RE = re.compile(r"^(\d+)\s*([dhm])$", re.IGNORECASE)

# Rough prevalence weights for common techniques (not a vanity 100% score).
_TECHNIQUE_RISK_WEIGHT: dict[str, float] = {
    "T1059": 1.4,
    "T1059.001": 1.5,
    "T1003": 1.6,
    "T1003.001": 1.7,
    "T1021": 1.3,
    "T1078": 1.4,
    "T1190": 1.5,
    "T1566": 1.3,
    "T1486": 1.8,
    "T1048": 1.2,
}


def parse_range(range_str: str) -> timedelta:
    match = _RANGE_RE.match((range_str or "7d").strip())
    if not match:
        raise ValueError(f"Invalid range '{range_str}' (use Nd, Nh, or Nm)")
    amount = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "d":
        return timedelta(days=amount)
    if unit == "h":
        return timedelta(hours=amount)
    return timedelta(minutes=amount)


def range_start(range_str: str) -> datetime:
    return _utcnow() - parse_range(range_str)


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _seconds_between(start: Any, end: Any) -> float | None:
    a, b = _parse_ts(start), _parse_ts(end)
    if not a or not b:
        return None
    delta = (b - a).total_seconds()
    return delta if delta >= 0 else None


def _bucket_key(ts: datetime, group_by: str) -> str:
    if group_by == "hour":
        return ts.strftime("%Y-%m-%dT%H:00")
    if group_by == "week":
        iso = ts.isocalendar()
        return f"{iso.year}-W{iso.week:02d}"
    return ts.strftime("%Y-%m-%d")


class AnalyticsEngine:
    """Compute overview / timeseries / distributions / KPIs from live managers."""

    def __init__(
        self,
        *,
        watchlist_manager: Any,
        case_manager: Any,
        connector_manager: Any | None = None,
        decay_manager: Any | None = None,
        feed_manager: Any | None = None,
        qdrant_store: Any | None = None,
        detection_rules_manager: Any | None = None,
        attack_mapper: Any | None = None,
        playbook_manager: Any | None = None,
        enrichment_manager: Any | None = None,
        webhook_manager: Any | None = None,
        taxii_manager: Any | None = None,
        asset_manager: Any | None = None,
    ) -> None:
        self.watchlists = watchlist_manager
        self.cases = case_manager
        self.connectors = connector_manager
        self.decay = decay_manager
        self.feeds = feed_manager
        self.qdrant = qdrant_store
        self.rules = detection_rules_manager
        self.attack = attack_mapper
        self.playbooks = playbook_manager
        self.enrichment = enrichment_manager
        self.webhooks = webhook_manager
        self.taxii = taxii_manager
        self.assets = asset_manager

    @staticmethod
    def _sparkline_from_rows(
        rows: list[Any],
        field: str,
        start: datetime,
        *,
        days: int = 7,
    ) -> list[int]:
        """Build a dense day sparkline from already-loaded rows (no re-query)."""
        buckets: dict[str, int] = defaultdict(int)
        for row in rows:
            value = row.get(field) if isinstance(row, dict) else getattr(row, field, None)
            ts = _parse_ts(value)
            if ts and ts >= start:
                buckets[_bucket_key(ts, "day")] += 1
        keys = [(_utcnow() - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d") for i in range(days)]
        return [buckets.get(k, 0) for k in keys]

    def overview(self, range_str: str = "7d") -> dict[str, Any]:
        start = range_start(range_str)
        start_iso = start.isoformat()
        alerts = self.watchlists.alerts_since(start_iso)
        cases = self.cases.cases_since(start_iso)
        dispositions = Counter(a.get("disposition") or "open" for a in alerts)
        case_status = Counter(c.status for c in cases)
        detections: list[dict[str, Any]] = []
        if self.connectors and self.qdrant:
            try:
                detections = self.connectors.list_recent_detections(self.qdrant, limit=500)
            except Exception:
                logger.debug("overview detections count failed", exc_info=True)
        cutoff_24h = _utcnow() - timedelta(hours=24)
        detections_n = 0
        for det in detections:
            ts = _parse_ts(det.get("indexed_at") or det.get("event_time"))
            if ts and ts >= cutoff_24h:
                detections_n += 1
        # Reuse the loaded alert/case window — do not re-query via kpis/timeseries.
        kpis = self.kpis(
            ["mtta", "mttr", "fpr", "alert_volume", "case_volume", "fresh_ioc_ratio"],
            range_str,
            alerts=alerts,
            cases=cases,
        )
        open_alerts = [a for a in self.watchlists.get_alerts(limit=5_000) if not a.get("acknowledged")]
        open_cases = [c for c in self.cases.list_cases(limit=5_000) if c.status in ("open", "investigating")]
        spark_start = _utcnow() - timedelta(days=6)
        alert_spark = self._sparkline_from_rows(alerts, "triggered_at", spark_start, days=7)
        det_spark = self._sparkline_from_rows(detections, "indexed_at", spark_start, days=7)
        fresh_metric = (kpis.get("metrics") or {}).get("fresh_ioc_ratio") or {}
        fresh_pct = None
        if isinstance(fresh_metric.get("value"), (int, float)):
            fresh_pct = round(float(fresh_metric["value"]) * 100)
        asset_count = 0
        assets_by_criticality: dict[str, int] = {}
        if self.assets and hasattr(self.assets, "list_assets"):
            try:
                asset_rows = self.assets.list_assets(limit=5_000)
                asset_count = len(asset_rows)
                assets_by_criticality = dict(
                    Counter(str(a.get("criticality") or "unknown") for a in asset_rows)
                )
            except Exception:
                logger.debug("overview asset count failed", exc_info=True)
        playbook_stats: dict[str, Any] = {}
        if self.playbooks and hasattr(self.playbooks, "analytics"):
            try:
                playbook_stats = self.playbooks.analytics(since_iso=start_iso) or {}
            except Exception:
                logger.debug("overview playbook analytics failed", exc_info=True)
        return {
            "range": range_str,
            "alerts": {"n": len(alerts), "by_disposition": dict(dispositions)},
            "cases": {"n": len(cases), "by_status": dict(case_status)},
            "detections_sample_n": detections_n,
            "detections_24h": detections_n,
            "open_alerts": len(open_alerts),
            "open_alerts_n": len(open_alerts),
            "open_cases": len(open_cases),
            "fresh_ioc_pct": fresh_pct,
            "asset_count": asset_count,
            "assets_by_criticality": assets_by_criticality,
            "playbook_success_rate": playbook_stats.get("success_rate"),
            "playbook_n": playbook_stats.get("n", 0),
            "playbook_avg_duration_seconds": playbook_stats.get("avg_duration_seconds"),
            "playbook_avg_approval_wait_seconds": playbook_stats.get("avg_approval_wait_seconds"),
            "playbooks": playbook_stats,
            "sparklines": {
                "alerts": alert_spark,
                "alerts_7d": alert_spark,
                "detections": det_spark,
                "detections_24h": det_spark,
                "fresh_ioc": [fresh_pct or 0],
                "cases": [case_status.get(k, 0) for k in ("open", "investigating", "resolved", "closed")],
            },
            "kpis": kpis.get("metrics", {}),
            "n": len(alerts) + len(cases),
        }

    def playbook_analytics(self, range_str: str = "30d") -> dict[str, Any]:
        start_iso = range_start(range_str).isoformat()
        if not self.playbooks or not hasattr(self.playbooks, "analytics"):
            return {"range": range_str, "n": 0, "success_rate": None}
        data = self.playbooks.analytics(since_iso=start_iso)
        return {"range": range_str, **data}

    def timeseries(
        self,
        metric: str = "alerts",
        group_by: str = "day",
        range_str: str = "7d",
    ) -> dict[str, Any]:
        start = range_start(range_str)
        start_iso = start.isoformat()
        buckets: dict[str, int] = defaultdict(int)
        series_meta = {"metric": metric, "group_by": group_by, "range": range_str}

        if metric == "alerts":
            for alert in self.watchlists.alerts_since(start_iso):
                ts = _parse_ts(alert.get("triggered_at"))
                if ts and ts >= start:
                    buckets[_bucket_key(ts, group_by)] += 1
        elif metric == "cases":
            for case in self.cases.cases_since(start_iso):
                ts = _parse_ts(case.detected_at or case.created_at)
                if ts and ts >= start:
                    buckets[_bucket_key(ts, group_by)] += 1
        elif metric == "detections":
            if self.connectors and self.qdrant:
                try:
                    for det in self.connectors.list_recent_detections(self.qdrant, limit=1000):
                        ts = _parse_ts(det.get("indexed_at"))
                        if ts and ts >= start:
                            buckets[_bucket_key(ts, group_by)] += 1
                except Exception:
                    logger.debug("timeseries detections failed", exc_info=True)
        elif metric == "dispositions":
            for alert in self.watchlists.alerts_since(start_iso):
                if not alert.get("disposition"):
                    continue
                ts = _parse_ts(alert.get("acknowledged_at") or alert.get("triggered_at"))
                if ts and ts >= start:
                    buckets[_bucket_key(ts, group_by)] += 1
        elif metric in ("webhooks", "webhook_events"):
            if self.webhooks and hasattr(self.webhooks, "list_events"):
                try:
                    for event in self.webhooks.list_events(limit=2_000):
                        ts = _parse_ts(event.get("created_at"))
                        if ts and ts >= start:
                            buckets[_bucket_key(ts, group_by)] += 1
                except Exception:
                    logger.debug("timeseries webhooks failed", exc_info=True)
        elif metric in ("taxii", "taxii_publish"):
            if self.taxii and hasattr(self.taxii, "_conn"):
                try:
                    rows = self.taxii._conn.execute(  # noqa: SLF001 — analytics read of publish audit
                        "SELECT at FROM audit WHERE action LIKE 'publish%' OR action LIKE '%.add' "
                        "ORDER BY at DESC LIMIT 2000"
                    ).fetchall()
                    for row in rows:
                        ts = _parse_ts(row["at"] if hasattr(row, "keys") else row[0])
                        if ts and ts >= start:
                            buckets[_bucket_key(ts, group_by)] += 1
                except Exception:
                    logger.debug("timeseries taxii failed", exc_info=True)
        elif metric in ("fresh_iocs", "stale_iocs"):
            if self.decay and hasattr(self.decay, "get_all_tracked"):
                try:
                    for ioc in self.decay.get_all_tracked(limit=5_000):
                        ts = _parse_ts(ioc.get("last_seen") or ioc.get("last_updated"))
                        if not ts or ts < start:
                            continue
                        score = float(ioc.get("decay_score") or 0)
                        is_fresh = score >= 0.5
                        if metric == "fresh_iocs" and is_fresh:
                            buckets[_bucket_key(ts, group_by)] += 1
                        elif metric == "stale_iocs" and not is_fresh:
                            buckets[_bucket_key(ts, group_by)] += 1
                except Exception:
                    logger.debug("timeseries ioc freshness failed", exc_info=True)
        elif metric in ("mtta", "mtti", "mttr", "ingest_latency", "mttd", "mttd_proxy", "fpr"):
            return self._latency_timeseries(metric, group_by, range_str, start)
        else:
            raise ValueError(
                f"Unsupported metric '{metric}'. "
                "Use alerts, cases, detections, dispositions, webhooks, taxii, "
                "fresh_iocs, stale_iocs, mtta, mtti, mttr, ingest_latency, or fpr."
            )

        points = [
            {"bucket": k, "label": k, "value": buckets[k], "count": buckets[k]}
            for k in sorted(buckets)
        ]
        return {**series_meta, "points": points, "series": points, "n": sum(buckets.values())}

    def _latency_timeseries(
        self,
        metric: str,
        group_by: str,
        range_str: str,
        start: datetime,
    ) -> dict[str, Any]:
        """Bucketed mean latency (seconds) or FPR rate for response/quality trends."""
        start_iso = start.isoformat()
        samples: dict[str, list[float]] = defaultdict(list)
        unit = "seconds"
        alerts = self.watchlists.alerts_since(start_iso)
        cases = self.cases.cases_since(start_iso)

        if metric == "mtta":
            for alert in alerts:
                delta = _seconds_between(alert.get("triggered_at"), alert.get("acknowledged_at"))
                ts = _parse_ts(alert.get("acknowledged_at"))
                if delta is not None and ts and ts >= start:
                    samples[_bucket_key(ts, group_by)].append(delta)
        elif metric == "mtti":
            case_created = {c.case_id: c.created_at for c in cases}
            for alert in alerts:
                case_id = alert.get("promoted_case_id")
                if not case_id:
                    continue
                delta = _seconds_between(alert.get("triggered_at"), case_created.get(case_id))
                ts = _parse_ts(case_created.get(case_id))
                if delta is not None and ts and ts >= start:
                    samples[_bucket_key(ts, group_by)].append(delta)
            if not samples:
                for case in cases:
                    delta = _seconds_between(case.detected_at, case.created_at)
                    ts = _parse_ts(case.created_at)
                    if delta is not None and delta > 0 and ts and ts >= start:
                        samples[_bucket_key(ts, group_by)].append(delta)
        elif metric == "mttr":
            for case in cases:
                end = case.closed_at or case.contained_at
                delta = _seconds_between(case.detected_at or case.created_at, end)
                ts = _parse_ts(end)
                if delta is not None and ts and ts >= start:
                    samples[_bucket_key(ts, group_by)].append(delta)
        elif metric in ("ingest_latency", "mttd", "mttd_proxy"):
            if self.connectors and self.qdrant:
                try:
                    for det in self.connectors.list_recent_detections(self.qdrant, limit=1_000):
                        delta = _seconds_between(
                            det.get("event_time") or det.get("capture_time"),
                            det.get("indexed_at"),
                        )
                        ts = _parse_ts(det.get("indexed_at"))
                        if delta is not None and delta >= 0 and ts and ts >= start:
                            samples[_bucket_key(ts, group_by)].append(delta)
                except Exception:
                    logger.debug("latency timeseries ingest failed", exc_info=True)
        elif metric == "fpr":
            unit = "ratio"
            disposed_by: dict[str, list[str]] = defaultdict(list)
            for alert in alerts:
                if not alert.get("disposition"):
                    continue
                ts = _parse_ts(alert.get("acknowledged_at") or alert.get("triggered_at"))
                if not ts or ts < start:
                    continue
                disposed_by[_bucket_key(ts, group_by)].append(str(alert.get("disposition")))
            for bucket, dispositions in disposed_by.items():
                classified = [d for d in dispositions if d in ("true_positive", "false_positive")]
                if not classified:
                    continue
                fps = sum(1 for d in classified if d == "false_positive")
                samples[bucket].append(fps / len(classified))

        points = []
        total_n = 0
        for key in sorted(samples):
            values = samples[key]
            if not values:
                continue
            avg = sum(values) / len(values)
            n = len(values)
            total_n += n
            points.append({
                "bucket": key,
                "label": key,
                "value": round(avg, 4),
                "count": round(avg, 4),
                "n": n,
                "unit": unit,
            })
        return {
            "metric": metric,
            "group_by": group_by,
            "range": range_str,
            "unit": unit,
            "points": points,
            "series": points,
            "n": total_n,
        }

    def distributions(self, metric: str = "ioc_type", range_str: str = "7d") -> dict[str, Any]:
        start_iso = range_start(range_str).isoformat()
        counts: Counter[str] = Counter()

        if metric == "ioc_type":
            for alert in self.watchlists.alerts_since(start_iso):
                counts[alert.get("ioc_type") or "unknown"] += 1
        elif metric == "disposition":
            for alert in self.watchlists.alerts_since(start_iso):
                counts[alert.get("disposition") or "open"] += 1
        elif metric == "case_priority" or metric == "severity":
            for case in self.cases.cases_since(start_iso):
                key = case.severity if metric == "severity" else case.priority
                counts[key or "unknown"] += 1
        elif metric == "case_status":
            for case in self.cases.cases_since(start_iso):
                counts[case.status or "unknown"] += 1
        elif metric == "alert_source":
            for alert in self.watchlists.alerts_since(start_iso):
                counts[alert.get("watchlist_name") or "watchlist"] += 1
        elif metric == "hour_weekday":
            cells: dict[tuple[int, int], int] = defaultdict(int)
            for alert in self.watchlists.alerts_since(start_iso):
                ts = _parse_ts(alert.get("triggered_at"))
                if not ts:
                    continue
                # Python weekday: Mon=0; UI CalendarHeatmap uses Sun=0.
                ui_weekday = (ts.weekday() + 1) % 7
                cells[(ui_weekday, ts.hour)] += 1
            cell_rows = [
                {"weekday": dow, "hour": hour, "value": value, "count": value}
                for (dow, hour), value in sorted(cells.items())
            ]
            return {
                "metric": metric,
                "range": range_str,
                "cells": cell_rows,
                "items": [
                    {
                        "key": f"{c['weekday']}-{c['hour']}",
                        "label": f"{c['weekday']}-{c['hour']}",
                        "value": c["value"],
                        "count": c["value"],
                    }
                    for c in cell_rows
                ],
                "buckets": [],
                "n": sum(c["value"] for c in cell_rows),
            }
        elif metric in ("noisy_ioc", "noisy_iocs"):
            for alert in self.watchlists.alerts_since(start_iso):
                key = f"{alert.get('ioc_type') or '?'}:{alert.get('ioc_value') or '—'}"
                counts[key] += 1
            items = [
                {"key": k, "label": k, "count": v, "value": v}
                for k, v in counts.most_common(25)
            ]
            return {"metric": metric, "range": range_str, "items": items, "buckets": items, "n": sum(counts.values())}
        elif metric in ("enrichment_verdict", "enrichment_verdicts"):
            if self.enrichment and hasattr(self.enrichment, "list_cached_results"):
                try:
                    for row in self.enrichment.list_cached_results(limit=1_000):
                        tags = [str(t).lower() for t in (row.get("tags") or [])]
                        raw = row.get("raw_data") or {}
                        verdict = "unknown"
                        for candidate in ("malicious", "suspicious", "harmless", "clean", "benign"):
                            if any(candidate in t for t in tags) or str(raw.get("verdict") or "").lower() == candidate:
                                verdict = candidate
                                break
                        if verdict == "unknown" and isinstance(raw.get("malicious"), (int, float)):
                            verdict = "malicious" if raw["malicious"] else "clean"
                        counts[verdict] += 1
                except Exception:
                    logger.debug("enrichment_verdict distribution failed", exc_info=True)
        elif metric in ("assignee", "assignee_workload"):
            for case in self.cases.cases_since(start_iso):
                if case.status in ("resolved", "closed"):
                    continue
                counts[case.assignee or "Unassigned"] += 1
        elif metric in ("sla_aging", "sla_age"):
            now = datetime.now()
            for case in self.cases.list_cases(limit=5_000):
                if case.status in ("resolved", "closed") or not case.sla_due_at:
                    continue
                due = _parse_ts(case.sla_due_at)
                if not due:
                    continue
                hours_left = (due - now).total_seconds() / 3600.0
                if hours_left < 0:
                    bucket = "breached"
                elif hours_left < 24:
                    bucket = "<24h"
                elif hours_left < 72:
                    bucket = "1–3d"
                else:
                    bucket = ">3d"
                counts[bucket] += 1
        elif metric in ("webhook_volume", "webhook_source"):
            if self.webhooks and hasattr(self.webhooks, "list_events"):
                try:
                    for event in self.webhooks.list_events(limit=2_000):
                        ts = _parse_ts(event.get("created_at"))
                        if ts and ts.isoformat() >= start_iso:
                            counts[event.get("webhook_name") or "webhook"] += 1
                except Exception:
                    logger.debug("webhook_volume distribution failed", exc_info=True)
        elif metric == "dedup_savings":
            skipped = 0
            if self.connectors and hasattr(self.connectors, "_conn"):
                try:
                    row = self.connectors._conn.execute(  # noqa: SLF001
                        "SELECT COUNT(*) AS n FROM seen_detections"
                    ).fetchone()
                    skipped = int(row["n"] if hasattr(row, "keys") else row[0])
                except Exception:
                    logger.debug("dedup_savings failed", exc_info=True)
            items = [
                {"key": "skipped_duplicates", "label": "Skipped duplicates", "count": skipped, "value": skipped},
            ]
            return {"metric": metric, "range": range_str, "items": items, "buckets": items, "n": skipped}
        elif metric in ("asset_criticality", "criticality"):
            if self.assets and hasattr(self.assets, "list_assets"):
                try:
                    for asset in self.assets.list_assets(limit=5_000):
                        counts[str(asset.get("criticality") or "unknown")] += 1
                except Exception:
                    logger.debug("asset_criticality distribution failed", exc_info=True)
        elif metric in ("intel_age_at_match", "intel_age"):
            age_buckets: Counter[str] = Counter()
            for alert in self.watchlists.alerts_since(start_iso):
                triggered = _parse_ts(alert.get("triggered_at"))
                added = _parse_ts(alert.get("item_added_at") or alert.get("added_at"))
                if not triggered or not added:
                    age_buckets["unknown"] += 1
                    continue
                hours = max(0.0, (triggered - added).total_seconds() / 3600.0)
                if hours < 24:
                    age_buckets["<24h"] += 1
                elif hours < 168:
                    age_buckets["1–7d"] += 1
                elif hours < 720:
                    age_buckets["7–30d"] += 1
                else:
                    age_buckets[">30d"] += 1
            order = ["<24h", "1–7d", "7–30d", ">30d", "unknown"]
            items = [
                {"key": k, "label": k, "count": age_buckets[k], "value": age_buckets[k]}
                for k in order if age_buckets.get(k)
            ]
            return {
                "metric": metric, "range": range_str, "items": items, "buckets": items,
                "n": sum(age_buckets.values()),
                "hint": "hours between watchlist item added_at and alert triggered_at",
            }
        elif metric in ("enrichment_coverage", "enrich_coverage"):
            enriched = failed = cached = 0
            seen: set[str] = set()
            if self.enrichment and hasattr(self.enrichment, "list_cached_results"):
                try:
                    for row in self.enrichment.list_cached_results(limit=2_000):
                        key = f"{row.get('ioc_type')}:{row.get('ioc_value')}"
                        seen.add(key)
                        tags = [str(t).lower() for t in (row.get("tags") or [])]
                        raw = row.get("raw_data") or {}
                        if any("error" in t or "fail" in t for t in tags) or raw.get("error"):
                            failed += 1
                        else:
                            enriched += 1
                            cached += 1
                except Exception:
                    logger.debug("enrichment_coverage failed", exc_info=True)
            alert_iocs = {
                f"{a.get('ioc_type')}:{a.get('ioc_value')}"
                for a in self.watchlists.alerts_since(start_iso)
                if a.get("ioc_value")
            }
            untracked = sum(1 for key in alert_iocs if key not in seen)
            items = [
                {"key": "enriched", "label": "Enriched", "count": enriched, "value": enriched},
                {"key": "cached", "label": "Cached", "count": cached, "value": cached},
                {"key": "failed", "label": "Failed", "count": failed, "value": failed},
                {"key": "untracked", "label": "Alert IOCs not enriched", "count": untracked, "value": untracked},
            ]
            return {
                "metric": metric, "range": range_str, "items": items, "buckets": items,
                "n": enriched + failed + untracked,
                "hint": "enrichment cache outcomes vs alert IOC coverage",
            }
        elif metric in ("detections_by_connector", "detection_source"):
            if self.connectors and self.qdrant:
                try:
                    for det in self.connectors.list_recent_detections(self.qdrant, limit=1_000):
                        ts = _parse_ts(det.get("indexed_at") or det.get("event_time"))
                        if ts and ts.isoformat() >= start_iso:
                            counts[str(det.get("connector") or "unknown")] += 1
                except Exception:
                    logger.debug("detections_by_connector failed", exc_info=True)
        elif metric in ("time_in_status", "case_dwell", "status_dwell"):
            # Mean hours spent in each status from status_change timeline events.
            dwell_hours: dict[str, list[float]] = defaultdict(list)
            now = datetime.now()
            for case in self.cases.list_cases(limit=5_000):
                created = _parse_ts(case.created_at)
                if not created or created.isoformat() < start_iso:
                    # Still include open long-lived cases for dwell, but prefer
                    # those created/updated in-range via created_at gate above.
                    pass
                events = []
                try:
                    for event in self.cases.get_timeline(case.case_id):
                        if event.get("event_type") != "status_change":
                            continue
                        desc = str(event.get("description") or "")
                        status = desc.split(":", 1)[1].strip() if ":" in desc else desc.strip()
                        ts = _parse_ts(event.get("timestamp"))
                        if status and ts:
                            events.append((ts, status))
                except Exception:
                    logger.debug("time_in_status timeline failed", exc_info=True)
                    continue
                if not events:
                    # Fallback: single open→now/closed segment when no history.
                    end = _parse_ts(case.closed_at) or now
                    start_ts = created or _parse_ts(case.detected_at)
                    if start_ts:
                        hours = max(0.0, (end - start_ts).total_seconds() / 3600.0)
                        dwell_hours[case.status or "open"].append(hours)
                    continue
                events.sort(key=lambda item: item[0])
                for idx, (ts, status) in enumerate(events):
                    end = events[idx + 1][0] if idx + 1 < len(events) else (
                        _parse_ts(case.closed_at) or now
                    )
                    hours = max(0.0, (end - ts).total_seconds() / 3600.0)
                    dwell_hours[status or "unknown"].append(hours)
            items = [
                {
                    "key": status,
                    "label": status,
                    "value": round(sum(hours) / len(hours), 2),
                    "count": round(sum(hours) / len(hours), 2),
                    "n": len(hours),
                    "unit": "hours",
                }
                for status, hours in sorted(dwell_hours.items())
                if hours
            ]
            return {
                "metric": metric,
                "range": range_str,
                "items": items,
                "buckets": items,
                "n": sum(i["n"] for i in items),
                "unit": "hours",
                "hint": "mean hours spent in each case status",
            }
        else:
            raise ValueError(
                f"Unsupported distribution metric '{metric}'. "
                "Use ioc_type, disposition, case_priority, severity, case_status, alert_source, "
                "hour_weekday, noisy_ioc, enrichment_verdict, assignee, sla_aging, webhook_volume, "
                "dedup_savings, asset_criticality, intel_age_at_match, enrichment_coverage, "
                "detections_by_connector, or time_in_status."
            )

        items = [
            {"key": k, "label": k, "count": v, "value": v}
            for k, v in counts.most_common()
        ]
        return {
            "metric": metric,
            "range": range_str,
            "items": items,
            "buckets": items,
            "n": sum(counts.values()),
        }

    def kpis(
        self,
        metrics: list[str],
        range_str: str = "7d",
        *,
        alerts: list[dict[str, Any]] | None = None,
        cases: list[Any] | None = None,
    ) -> dict[str, Any]:
        start = range_start(range_str)
        start_iso = start.isoformat()
        if alerts is None:
            alerts = self.watchlists.alerts_since(start_iso)
        if cases is None:
            cases = self.cases.cases_since(start_iso)
        result: dict[str, Any] = {}

        for name in metrics:
            key = name.strip().lower()
            if key == "mtta":
                samples = [
                    _seconds_between(a.get("triggered_at"), a.get("acknowledged_at"))
                    for a in alerts
                    if a.get("acknowledged_at")
                ]
                samples = [s for s in samples if s is not None]
                avg = (sum(samples) / len(samples)) if samples else None
                result["mtta"] = {
                    "seconds": avg,
                    "value": avg,
                    "n": len(samples),
                    "unit": "seconds",
                    "hint": "mean time to acknowledge",
                }
            elif key == "mttr":
                samples = [
                    _seconds_between(c.detected_at or c.created_at, c.closed_at or c.contained_at)
                    for c in cases
                    if c.closed_at or c.contained_at
                ]
                samples = [s for s in samples if s is not None]
                avg = (sum(samples) / len(samples)) if samples else None
                result["mttr"] = {
                    "seconds": avg,
                    "value": avg,
                    "n": len(samples),
                    "unit": "seconds",
                    "hint": "mean time to remediate/contain",
                }
            elif key == "mtti":
                # Mean time to investigate: alert trigger → case creation for promoted alerts
                case_created = {c.case_id: c.created_at for c in cases}
                samples = []
                for alert in alerts:
                    case_id = alert.get("promoted_case_id")
                    if not case_id:
                        continue
                    delta = _seconds_between(alert.get("triggered_at"), case_created.get(case_id))
                    if delta is not None:
                        samples.append(delta)
                # Also include cases without alert link using detected→created when distinct
                if not samples:
                    for c in cases:
                        delta = _seconds_between(c.detected_at, c.created_at)
                        if delta is not None and delta > 0:
                            samples.append(delta)
                avg = (sum(samples) / len(samples)) if samples else None
                result["mtti"] = {
                    "seconds": avg,
                    "value": avg,
                    "n": len(samples),
                    "unit": "seconds",
                    "hint": "mean time to investigate (alert→case)",
                }
            elif key in ("ingest_latency", "mttd", "mttd_proxy"):
                samples = []
                if self.connectors and self.qdrant:
                    try:
                        for det in self.connectors.list_recent_detections(self.qdrant, limit=500):
                            delta = _seconds_between(
                                det.get("event_time") or det.get("capture_time"),
                                det.get("indexed_at"),
                            )
                            if delta is not None and delta >= 0:
                                samples.append(delta)
                    except Exception:
                        logger.debug("ingest_latency samples failed", exc_info=True)
                avg = (sum(samples) / len(samples)) if samples else None
                result["ingest_latency"] = {
                    "seconds": avg,
                    "value": avg,
                    "n": len(samples),
                    "unit": "seconds",
                    "hint": "mean indexed_at − event_time (MTTD proxy)",
                }
                result["mttd"] = result["ingest_latency"]
            elif key in ("intel_hit_rate", "watchlist_hit_rate"):
                item_n = 0
                try:
                    for wl in self.watchlists.list_watchlists():
                        item_n += int(wl.get("item_count") or 0)
                except Exception:
                    logger.debug("intel_hit_rate watchlist count failed", exc_info=True)
                rate = (len(alerts) / item_n) if item_n else None
                result["intel_hit_rate"] = {
                    "rate": rate,
                    "value": rate,
                    "ratio": rate,
                    "n": item_n,
                    "alerts": len(alerts),
                    "hint": "watchlist alerts / active watchlist items",
                }
            elif key in ("automation_success", "playbook_success"):
                stats: dict[str, Any] = {}
                if self.playbooks and hasattr(self.playbooks, "analytics"):
                    try:
                        stats = self.playbooks.analytics(since_iso=start_iso) or {}
                    except Exception:
                        logger.debug("automation_success failed", exc_info=True)
                rate = stats.get("success_rate")
                result["automation_success"] = {
                    "rate": rate,
                    "value": rate,
                    "ratio": rate,
                    "n": int(stats.get("n") or 0),
                    "completed": stats.get("completed"),
                    "failed": stats.get("failed"),
                    "hint": "successful playbook runs / total runs",
                }
            elif key == "fpr":
                # Spec: FP / (TP + FP). Other dispositions (informational, duplicate, …)
                # must not dilute the quality rate.
                classified = [
                    a for a in alerts
                    if a.get("disposition") in ("true_positive", "false_positive")
                ]
                fps = [a for a in classified if a.get("disposition") == "false_positive"]
                rate = (len(fps) / len(classified)) if classified else None
                result["fpr"] = {
                    "rate": rate,
                    "value": rate,
                    "ratio": rate,
                    "n": len(classified),
                    "false_positives": len(fps),
                    "true_positives": len(classified) - len(fps),
                    "hint": "false positives / (true positives + false positives)",
                }
            elif key == "tpr":
                classified = [
                    a for a in alerts
                    if a.get("disposition") in ("true_positive", "false_positive")
                ]
                tps = [a for a in classified if a.get("disposition") == "true_positive"]
                result["tpr"] = {
                    "rate": (len(tps) / len(classified)) if classified else None,
                    "n": len(classified),
                    "true_positives": len(tps),
                    "hint": "true positives / (true positives + false positives)",
                }
            elif key == "alert_volume":
                result["alert_volume"] = {"count": len(alerts), "value": len(alerts), "n": len(alerts)}
            elif key == "case_volume":
                result["case_volume"] = {"count": len(cases), "value": len(cases), "n": len(cases)}
            elif key in ("alert_case_ratio", "alert_to_case_ratio"):
                promoted = [a for a in alerts if a.get("promoted_case_id")]
                ratio = (len(promoted) / len(alerts)) if alerts else None
                result["alert_case_ratio"] = {
                    "rate": ratio,
                    "value": ratio,
                    "ratio": ratio,
                    "n": len(alerts),
                    "promoted": len(promoted),
                    "hint": "alerts promoted to cases / alerts",
                }
            elif key == "fresh_ioc_ratio":
                ratio = None
                n = 0
                if self.decay:
                    try:
                        summary = None
                        if hasattr(self.decay, "get_summary"):
                            summary = self.decay.get_summary()
                        elif hasattr(self.decay, "summary"):
                            summary = self.decay.summary()
                        if isinstance(summary, dict) and summary.get("tracked_count"):
                            n = int(summary["tracked_count"])
                            ratio = float(summary.get("fresh_count", 0)) / n if n else None
                    except Exception:
                        logger.debug("fresh_ioc_ratio failed", exc_info=True)
                result["fresh_ioc_ratio"] = {
                    "rate": ratio,
                    "value": ratio,
                    "ratio": ratio,
                    "n": n,
                    "hint": "fresh IOCs / tracked IOCs",
                }
            elif key == "escalation_rate":
                escalated = [
                    a for a in alerts
                    if a.get("disposition") == "escalated" or a.get("promoted_case_id")
                ]
                rate = (len(escalated) / len(alerts)) if alerts else None
                result["escalation_rate"] = {
                    "rate": rate,
                    "value": rate,
                    "n": len(alerts),
                    "escalated": len(escalated),
                }
            elif key == "reopen_rate":
                reopened = 0
                evaluated = 0
                closed_like = {"resolved", "closed"}
                open_like = {"open", "investigating"}
                for case in cases:
                    statuses: list[str] = []
                    try:
                        for event in self.cases.get_timeline(case.case_id):
                            if event.get("event_type") != "status_change":
                                continue
                            desc = str(event.get("description") or "")
                            status = desc.split(":", 1)[1].strip() if ":" in desc else desc.strip()
                            if status:
                                statuses.append(status)
                    except Exception:
                        continue
                    if len(statuses) < 2:
                        continue
                    evaluated += 1
                    for idx in range(1, len(statuses)):
                        if statuses[idx - 1] in closed_like and statuses[idx] in open_like:
                            reopened += 1
                            break
                rate = (reopened / evaluated) if evaluated else None
                result["reopen_rate"] = {
                    "rate": rate,
                    "value": rate,
                    "n": evaluated,
                    "reopened": reopened,
                    "hint": "cases with closed/resolved → open/investigating transition",
                }
            elif key == "closure_rate":
                closed = [c for c in cases if c.status in ("resolved", "closed")]
                rate = (len(closed) / len(cases)) if cases else None
                result["closure_rate"] = {
                    "rate": rate,
                    "value": rate,
                    "n": len(cases),
                    "closed": len(closed),
                }
            elif key == "sla_breach_rate":
                evaluated = [c for c in cases if c.sla_due_at]
                breached = []
                for c in evaluated:
                    due = _parse_ts(c.sla_due_at)
                    closed = _parse_ts(c.closed_at) or datetime.now()
                    if due and closed > due and c.status not in ("resolved", "closed"):
                        breached.append(c)
                    elif due and c.closed_at and _parse_ts(c.closed_at) and _parse_ts(c.closed_at) > due:
                        breached.append(c)
                rate = (len(breached) / len(evaluated)) if evaluated else None
                result["sla_breach_rate"] = {
                    "rate": rate,
                    "value": rate,
                    "n": len(evaluated),
                    "breached": len(breached),
                }
            else:
                result[key] = {"error": f"Unknown metric '{key}'", "n": 0}

        return {"range": range_str, "metrics": result, "n": len(alerts) + len(cases)}

    def attack_coverage(self, range_str: str = "30d") -> dict[str, Any]:
        """Risk-weighted coverage from sightings — never invents a 100% score."""
        start = range_start(range_str)
        sightings: Counter[str] = Counter()
        claimed: set[str] = set()

        # Case tags / timeline descriptions may carry technique IDs
        tech_re = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
        for case in self.cases.cases_since(start.isoformat()):
            for tag in case.tags or []:
                for match in tech_re.findall(str(tag)):
                    sightings[match] += 1
            for event in self.cases.get_timeline(case.case_id):
                for match in tech_re.findall(str(event.get("description") or "")):
                    sightings[match] += 1

        if self.connectors and self.qdrant:
            try:
                for det in self.connectors.list_recent_detections(self.qdrant, limit=500):
                    blob = " ".join(
                        str(det.get(k) or "") for k in ("title", "source_file", "ioc_status")
                    )
                    for match in tech_re.findall(blob):
                        sightings[match] += 1
                    for tid in det.get("technique_ids") or []:
                        for match in tech_re.findall(str(tid)):
                            sightings[match] += 1
            except Exception:
                logger.debug("attack coverage detections scan failed", exc_info=True)

        # Claimed coverage from stored Sigma/YARA technique tags (not live detection).
        if self.rules and hasattr(self.rules, "list_rules"):
            try:
                for rule in self.rules.list_rules(limit=5_000):
                    tags = rule.get("tags") or []
                    if isinstance(tags, str):
                        try:
                            tags = json.loads(tags)
                        except Exception:
                            tags = [tags]
                    for tag in tags:
                        for match in tech_re.findall(str(tag)):
                            claimed.add(match)
            except Exception:
                logger.debug("attack coverage rules scan failed", exc_info=True)

        def _weight(tid: str) -> float:
            if tid in _TECHNIQUE_RISK_WEIGHT:
                return _TECHNIQUE_RISK_WEIGHT[tid]
            return _TECHNIQUE_RISK_WEIGHT.get(tid.split(".")[0], 1.0)

        def _name(tid: str) -> str:
            if self.attack:
                try:
                    info = self.attack.get_technique(tid) or {}
                    return info.get("name") or tid
                except Exception:
                    pass
            return tid

        techniques = []
        weighted_sum = 0.0
        for tid, count in sightings.most_common(200):
            weight = _weight(tid)
            covered = tid in claimed or tid.split(".")[0] in claimed
            techniques.append({
                "technique_id": tid,
                "name": _name(tid),
                "sightings": count,
                "risk_weight": weight,
                "weighted_score": round(count * weight, 3),
                "covered": covered,
                "gap": not covered,
            })
            weighted_sum += count * weight

        # Rules claiming coverage with zero org sightings — gap analysis, not vanity.
        for tid in sorted(claimed):
            if tid in sightings:
                continue
            techniques.append({
                "technique_id": tid,
                "name": _name(tid),
                "sightings": 0,
                "risk_weight": _weight(tid),
                "weighted_score": 0.0,
                "covered": True,
                "gap": True,
            })

        unique = len(sightings)
        catalog_size = 0
        if self.attack is not None:
            techniques_map = getattr(self.attack, "_techniques", None) or getattr(
                self.attack, "techniques", None
            )
            if isinstance(techniques_map, dict):
                catalog_size = len(techniques_map)
        if not catalog_size:
            catalog_size = max(unique, 60)
        raw_ratio = unique / catalog_size
        coverage_index = round(min(0.95, raw_ratio * 0.65 + min(0.3, weighted_sum / 100.0)), 4)

        navigator_techniques = []
        for tid in sorted(set(sightings) | claimed):
            score = float(sightings.get(tid, 0))
            if tid in claimed and score == 0:
                score = 0.5  # claimed-only marker for Navigator tint
            navigator_techniques.append({
                "techniqueID": tid,
                "score": score,
                "color": "#4bd4bd" if tid in claimed else "#f2bd68",
                "comment": "claimed+sighted" if tid in claimed and tid in sightings
                else ("claimed" if tid in claimed else "sighted"),
            })
        navigator = {
            "name": "Black Onyx ATT&CK sightings vs claimed rules",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": (
                "Risk-weighted org sightings overlaid with Sigma/YARA claimed techniques. "
                "Not a 100% coverage score."
            ),
            "techniques": navigator_techniques,
            "gradient": {
                "colors": ["#ffffff", "#f2bd68", "#4bd4bd"],
                "minValue": 0,
                "maxValue": max([float(s) for s in sightings.values()] + [1.0]),
            },
        }

        return {
            "range": range_str,
            "techniques": techniques,
            "leaderboard": techniques,
            "claimed_techniques": sorted(claimed),
            "unique_techniques": unique,
            "catalog_size": catalog_size,
            "coverage_index": coverage_index,
            "coverage_basis": "risk_weighted_sightings_vs_claimed_rules",
            "navigator": navigator,
            "n": sum(sightings.values()),
            "note": (
                "coverage_index is risk-weighted from observed sightings; "
                "claimed techniques come from stored rule tags — not a chase for 100% ATT&CK coverage."
            ),
        }

    def cti_impact(self, range_str: str = "30d") -> dict[str, Any]:
        start_iso = range_start(range_str).isoformat()
        alerts = self.watchlists.alerts_since(start_iso)
        promoted = [a for a in alerts if a.get("promoted_case_id")]
        fps = [a for a in alerts if a.get("disposition") == "false_positive"]
        tps = [a for a in alerts if a.get("disposition") == "true_positive"]

        feed_yield: list[dict[str, Any]] = []
        if self.feeds:
            try:
                for feed in self.feeds.list_feeds():
                    feed_yield.append({
                        "name": feed.get("name"),
                        "last_status": feed.get("last_status"),
                        "last_items": feed.get("last_items") or 0,
                        "last_attempt": feed.get("last_attempt"),
                    })
            except Exception:
                logger.debug("cti impact feeds failed", exc_info=True)

        fresh_iocs = 0
        stale_iocs = 0
        if self.decay:
            try:
                if hasattr(self.decay, "get_summary"):
                    stats = self.decay.get_summary()
                    fresh_iocs = int(stats.get("fresh_count") or 0)
                    stale_iocs = int(stats.get("stale_count") or 0)
                elif hasattr(self.decay, "get_all_tracked"):
                    for ioc in self.decay.get_all_tracked(limit=500):
                        score = float(ioc.get("decay_score") or 0)
                        if score >= 0.5:
                            fresh_iocs += 1
                        else:
                            stale_iocs += 1
            except Exception:
                logger.debug("cti impact decay failed", exc_info=True)

        geo_counts: Counter[str] = Counter()
        cve_rows: dict[str, dict[str, Any]] = {}
        if self.enrichment and hasattr(self.enrichment, "list_cached_results"):
            try:
                for row in self.enrichment.list_cached_results(limit=1_000):
                    provider = str(row.get("provider") or "")
                    ioc_type = str(row.get("ioc_type") or "").lower()
                    ioc_value = str(row.get("ioc_value") or "")
                    tags = row.get("tags") or []
                    raw = row.get("raw_data") or {}
                    if not isinstance(raw, dict):
                        raw = {}
                    for tag in tags:
                        text = str(tag)
                        if text.lower().startswith("country:"):
                            code = text.split(":", 1)[1].strip().upper()
                            if len(code) == 2:
                                geo_counts[code] += 1
                    country = raw.get("countryCode") or raw.get("country_code") or raw.get("country")
                    if isinstance(country, str) and len(country) == 2:
                        geo_counts[country.upper()] += 1
                    if ioc_type == "cve" and ioc_value:
                        entry = cve_rows.setdefault(ioc_value.upper(), {
                            "cve_id": ioc_value.upper(),
                            "epss": 0.0,
                            "kev": False,
                            "score": 0.0,
                        })
                        if provider == "epss":
                            epss = raw.get("epss")
                            if epss is None and tags:
                                for tag in tags:
                                    if str(tag).startswith("epss:"):
                                        try:
                                            epss = float(str(tag).split(":", 1)[1])
                                        except ValueError:
                                            epss = None
                            if isinstance(epss, (int, float)):
                                entry["epss"] = float(epss)
                                entry["score"] = max(entry["score"], float(epss))
                        if provider == "kev":
                            in_kev = bool(raw.get("in_kev")) or any("in_kev" in str(t) for t in tags)
                            entry["kev"] = in_kev
                            if in_kev:
                                entry["score"] = max(entry["score"], entry["epss"] + 0.5)
                        if provider == "nvd":
                            entry["score"] = max(entry["score"], float(raw.get("cvss") or entry["epss"] or 0))
            except Exception:
                logger.debug("cti impact enrichment scan failed", exc_info=True)

        geo = [{"country": code, "code": code, "value": count, "count": count} for code, count in geo_counts.most_common(64)]
        cves = sorted(cve_rows.values(), key=lambda r: (-float(r.get("score") or 0), r["cve_id"]))[:40]

        return {
            "range": range_str,
            "funnel": {
                "watchlist_alerts": len(alerts),
                "true_positives": len(tps),
                "false_positives": len(fps),
                "promoted_to_case": len(promoted),
            },
            "feeds": [{"label": f.get("name"), "name": f.get("name"), "value": f.get("last_items") or 0, "hits": f.get("last_items") or 0} for f in feed_yield],
            "feed_yield": feed_yield,
            "geo": geo,
            "countries": geo,
            "cves": cves,
            "ioc_freshness": {"fresh": fresh_iocs, "stale": stale_iocs, "n": fresh_iocs + stale_iocs},
            "n": len(alerts),
        }

    def connectors_health(self) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        if not self.connectors:
            return {"connectors": items, "n": 0}
        for row in self.connectors.list_connectors():
            items.append({
                "id": row.get("id"),
                "name": row.get("name"),
                "enabled": row.get("enabled"),
                "last_poll_at": row.get("last_poll_at"),
                "last_success_at": row.get("last_success_at"),
                "last_poll_status": row.get("last_poll_status"),
                "last_poll_error": row.get("last_poll_error"),
                "collection": row.get("collection"),
            })
        return {"connectors": items, "n": len(items)}
