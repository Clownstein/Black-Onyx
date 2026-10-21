"""Add TIP asset detail fields to the registry SoR.

Revision ID: 0002_asset_details
Revises: 0001_create_assets
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_asset_details"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("ip_address", sa.String(length=64), nullable=True))
    op.add_column("assets", sa.Column("notes", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "notes")
    op.drop_column("assets", "ip_address")
