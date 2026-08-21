"""Shared anomaly model protocol used by modality services (Phase 1+)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AnomalyModel(Protocol):
    model_name: str
    model_version: str
    feature_version: str

    def validate_input(self, batch: dict[str, Any]) -> None:
        """Raise if the batch cannot be scored."""

    def predict(self, batch: dict[str, Any]) -> dict[str, Any]:
        """Return scores and evidence for a validated batch."""

    def health(self) -> dict[str, Any]:
        """Return readiness details for the loaded model artifact."""
