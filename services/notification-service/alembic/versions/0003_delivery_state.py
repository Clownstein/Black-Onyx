"""add notification delivery mode and retry state

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("email_outbox") as batch:
        batch.add_column(
            sa.Column("delivery_mode", sa.String(length=32), nullable=False, server_default="queued")
        )
        batch.add_column(
            sa.Column("retryable", sa.Boolean(), nullable=False, server_default=sa.false())
        )


def downgrade() -> None:
    with op.batch_alter_table("email_outbox") as batch:
        batch.drop_column("retryable")
        batch.drop_column("delivery_mode")

