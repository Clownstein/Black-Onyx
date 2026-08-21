from __future__ import annotations

WEB_SERVICE_V1_METRICS = [
    "cpu.utilization",
    "memory.working_set",
    "http.request_rate",
    "http.error_rate",
    "http.duration.p95",
    "queue.depth",
    "db.pool.utilization",
]

HEAVY_TAILED = {
    "http.request_rate",
    "http.duration.p95",
    "queue.depth",
}


def profile_metric_names(profile: str) -> list[str]:
    if profile == "web_service_v1":
        return list(WEB_SERVICE_V1_METRICS)
    raise ValueError(f"unsupported metrics profile: {profile}")
