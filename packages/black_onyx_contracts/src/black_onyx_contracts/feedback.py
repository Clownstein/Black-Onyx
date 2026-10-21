"""Analyst calibration feedback (contracts/feedback/analyst_feedback.schema.json)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AnalystFeedbackLabel = Literal[
    "true_positive",
    "false_positive",
    "benign",
    "needs_review",
    "missed_detection",
]


class AnalystFeedback(BaseModel):
    """Tenant-scoped calibration feedback retained without immediate retraining."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern=r"^[0-9]+\.[0-9]+$")
    feedback_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    incident_id: str = Field(min_length=1, max_length=128)
    finding_id: str | None = Field(default=None, max_length=128)
    label: AnalystFeedbackLabel
    note: str | None = Field(default=None, max_length=8000)
    actor: str = Field(min_length=1, max_length=256)
    created_at: datetime
