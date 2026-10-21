"""Security gateway approvals, agent runs, and challenge solves."""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "platform_cutover",
        sa.Column("domain", sa.String(length=64), primary_key=True),
        sa.Column(
            "migrated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("sqlite_counts", sa.JSON(), nullable=False),
        sa.Column("postgres_counts", sa.JSON(), nullable=False),
    )
    op.create_table(
        "schema_migrations",
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("applied_at", sa.Integer(), nullable=False),
    )
    op.create_table(
        "approvals",
        sa.Column("approval_id", sa.Text(), primary_key=True),
        sa.Column("principal", sa.Text(), nullable=False),
        sa.Column("tool", sa.Text(), nullable=False),
        sa.Column("request_digest", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("approved_by", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("used_at", sa.Integer(), nullable=True),
    )
    op.create_index("ix_approvals_expires", "approvals", ["expires_at"])
    op.create_table(
        "agent_runs",
        sa.Column("run_id", sa.Text(), primary_key=True),
        sa.Column("principal", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("pending_tool", sa.Text(), nullable=True),
        sa.Column("pending_digest", sa.Text(), nullable=True),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_agent_runs_principal", "agent_runs", ["principal", "status"])
    op.create_table(
        "challenge_solves",
        sa.Column("actor_id", sa.Text(), nullable=False),
        sa.Column("challenge_id", sa.Text(), nullable=False),
        sa.Column(
            "solved_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("actor_id", "challenge_id"),
    )


def downgrade() -> None:
    op.drop_table("challenge_solves")
    op.drop_index("ix_agent_runs_principal", table_name="agent_runs")
    op.drop_table("agent_runs")
    op.drop_index("ix_approvals_expires", table_name="approvals")
    op.drop_table("approvals")
    op.drop_table("schema_migrations")
    op.drop_table("platform_cutover")
