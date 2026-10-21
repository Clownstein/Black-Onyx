"""add last-seen time for idempotent connector sightings

Revision ID: 0003
Revises: 0002_asset_details
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002_asset_details"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "last_seen_at")
