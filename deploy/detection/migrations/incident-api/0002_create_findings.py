"""create findings table

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-26

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("finding_type", sa.String(length=128), nullable=False),
        sa.Column("asset_id", sa.String(length=256), nullable=False),
        sa.Column("service_id", sa.String(length=256), nullable=True),
        sa.Column("model_name", sa.String(length=128), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("raw_score", sa.Float(), nullable=False),
        sa.Column("calibrated_score", sa.Float(), nullable=False),
        sa.Column("severity_hint", sa.String(length=64), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "finding_id", name="uq_findings_tenant_finding"),
    )
    op.create_index("ix_findings_tenant_id", "findings", ["tenant_id"])
    op.create_index("ix_findings_finding_type", "findings", ["finding_type"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_service_id", "findings", ["service_id"])
    op.create_index("ix_findings_calibrated_score", "findings", ["calibrated_score"])
    op.create_index("ix_findings_window_start", "findings", ["window_start"])
    op.create_index("ix_findings_window_end", "findings", ["window_end"])


def downgrade() -> None:
    op.drop_index("ix_findings_window_end", table_name="findings")
    op.drop_index("ix_findings_window_start", table_name="findings")
    op.drop_index("ix_findings_calibrated_score", table_name="findings")
    op.drop_index("ix_findings_service_id", table_name="findings")
    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_index("ix_findings_finding_type", table_name="findings")
    op.drop_index("ix_findings_tenant_id", table_name="findings")
    op.drop_table("findings")
