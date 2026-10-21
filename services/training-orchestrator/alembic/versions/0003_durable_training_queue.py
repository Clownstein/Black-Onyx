"""add durable training queue metadata

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
    with op.batch_alter_table("training_jobs") as batch:
        batch.add_column(sa.Column("request_json", sa.JSON(), nullable=False, server_default="{}"))
        batch.add_column(sa.Column("synthetic_data", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"))
        batch.add_column(sa.Column("claimed_by", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("failure_reason", sa.Text(), nullable=True))
    op.create_index("ix_training_jobs_queue", "training_jobs", ["status", "lease_expires_at"])


def downgrade() -> None:
    op.drop_index("ix_training_jobs_queue", table_name="training_jobs")
    with op.batch_alter_table("training_jobs") as batch:
        for name in (
            "failure_reason", "finished_at", "started_at", "heartbeat_at",
            "lease_expires_at", "claimed_by", "max_attempts", "attempt_count",
            "synthetic_data", "request_json",
        ):
            batch.drop_column(name)
