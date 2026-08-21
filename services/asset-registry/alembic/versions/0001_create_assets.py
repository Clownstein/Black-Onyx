"""create assets table

Revision ID: 0001
Revises:
Create Date: 2026-07-26

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("asset_id", sa.String(length=256), nullable=False),
        sa.Column("asset_type", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("service_id", sa.String(length=256), nullable=True),
        sa.Column("environment", sa.String(length=128), nullable=True),
        sa.Column("criticality", sa.Float(), nullable=False),
        sa.Column("owner_team", sa.String(length=128), nullable=True),
        sa.Column("network_zone", sa.String(length=128), nullable=True),
        sa.Column("expected_peers", sa.JSON(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "asset_id", name="uq_assets_tenant_asset"),
    )
    op.create_index("ix_assets_tenant_id", "assets", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_assets_tenant_id", table_name="assets")
    op.drop_table("assets")
