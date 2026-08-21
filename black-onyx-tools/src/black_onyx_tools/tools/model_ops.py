"""Model gateway and training orchestrator readiness (read-only)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from black_onyx_tools.client import PlatformClient


async def model_ops(
    client: PlatformClient,
    *,
    job_id: str | None = None,
) -> dict[str, Any]:
    """Read-only readiness for model-gateway + training-orchestrator.

    model-gateway exposes model URLs on ``/health/ready`` (no ``/api/v1/models``).
    training-orchestrator has no job list; optional ``job_id`` fetches one job.
    """
    models_ready = await client.detection_get("models", "/health/ready")
    training_ready = await client.detection_get("training", "/health/ready")
    ops_models: Any = None
    try:
        ops_models = await client.detection_get("incident", "/api/v1/ops/models")
    except Exception as exc:  # noqa: BLE001 — soft-fail optional probe
        ops_models = {"error": str(exc)}

    training_job: Any = None
    if job_id:
        training_job = await client.detection_get(
            "training",
            f"/api/v1/training-jobs/{job_id}",
        )

    return {
        "models_ready": models_ready,
        "training_ready": training_ready,
        "ops_models": ops_models,
        "training_job": training_job,
        "read_only": True,
        "note": (
            "Read-only. Pass job_id to fetch a training job; "
            "there is no training-jobs list endpoint."
        ),
    }


def register_model_ops(mcp: FastMCP, client: PlatformClient) -> None:
    @mcp.tool(name="black_onyx_model_ops")
    async def model_ops_tool(job_id: str = "") -> dict[str, Any]:
        """Report model-gateway and training-orchestrator readiness (read-only)."""
        return await model_ops(client, job_id=job_id.strip() or None)
