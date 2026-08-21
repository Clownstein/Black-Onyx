"""Pass-through calibrated scorer for host-state detections already present."""

from __future__ import annotations

from typing import Any


class HostStateScorer:
    """Score host-state feature items by trusting upstream rule/detection scores.

    When an item already carries calibrated_score / risk_score / score, clamp to [0,1]
    and return it. Otherwise derive a mild score from rule_hits / severity hints.
    """

    model_name = "host-state-model"
    model_version = "0.1.0"

    def health(self) -> dict[str, Any]:
        return {
            "status": "ready",
            "backend": "passthrough",
            "model_name": self.model_name,
            "model_version": self.model_version,
        }

    def predict(self, body: dict[str, Any]) -> dict[str, Any]:
        items = body.get("items") or []
        results: list[dict[str, Any]] = []
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                item = {}
            raw = self._extract_score(item)
            calibrated = max(0.0, min(1.0, float(raw)))
            item_id = str(
                item.get("sequence_id")
                or item.get("feature_id")
                or item.get("event_id")
                or f"item-{idx}"
            )
            results.append(
                {
                    "sequence_id": item_id,
                    "raw_score": calibrated,
                    "calibrated_score": calibrated,
                    "top_contributors": self._contributors(item),
                    "model_version": self.model_version,
                    "backend": "passthrough",
                }
            )
        return {
            "request_id": body.get("request_id"),
            "tenant_id": body.get("tenant_id"),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_version": body.get("feature_version") or "host-state.features.v1",
            "results": results,
        }

    @staticmethod
    def _extract_score(item: dict[str, Any]) -> float:
        for key in ("calibrated_score", "risk_score", "score", "anomaly_score"):
            if key in item and item[key] is not None:
                try:
                    return float(item[key])
                except (TypeError, ValueError):
                    pass
        hits = item.get("rule_hits") or item.get("detections") or []
        if isinstance(hits, list) and hits:
            return min(0.99, 0.4 + 0.1 * len(hits))
        severity = str(item.get("severity") or "").lower()
        return {"critical": 0.95, "high": 0.85, "medium": 0.6, "low": 0.3}.get(severity, 0.2)

    @staticmethod
    def _contributors(item: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for hit in item.get("rule_hits") or []:
            if isinstance(hit, dict):
                out.append(
                    {
                        "rule_id": hit.get("rule_id") or hit.get("id"),
                        "detail": hit.get("detail") or hit.get("title") or str(hit),
                    }
                )
            else:
                out.append({"detail": str(hit)})
        return out[:10]
