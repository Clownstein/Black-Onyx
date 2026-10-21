"""create incidents tables

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
        "incidents",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=64), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("category", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assets", sa.JSON(), nullable=False),
        sa.Column("services", sa.JSON(), nullable=False),
        sa.Column("deployment_id", sa.String(length=256), nullable=True),
        sa.Column("commit", sa.String(length=128), nullable=True),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("disposition", sa.String(length=64), nullable=True),
        sa.Column("assigned_to", sa.String(length=256), nullable=True),
        sa.Column("fingerprint", sa.String(length=256), nullable=True),
        sa.Column("context", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "incident_id", name="uq_incidents_tenant_incident"),
    )
    op.create_index("ix_incidents_tenant_id", "incidents", ["tenant_id"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_fingerprint", "incidents", ["fingerprint"])

    op.create_table(
        "incident_comments",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("comment_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("author", sa.String(length=256), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("comment_id", name="uq_comments_comment_id_legacy"),
    )
    op.create_index("ix_incident_comments_incident_id", "incident_comments", ["incident_id"])
    op.create_index("ix_incident_comments_tenant_id", "incident_comments", ["tenant_id"])

    op.create_table(
        "incident_timeline",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entry_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("actor", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entry_id"),
    )
    op.create_index("ix_incident_timeline_incident_id", "incident_timeline", ["incident_id"])
    op.create_index("ix_incident_timeline_tenant_id", "incident_timeline", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_incident_timeline_tenant_id", table_name="incident_timeline")
    op.drop_index("ix_incident_timeline_incident_id", table_name="incident_timeline")
    op.drop_table("incident_timeline")
    op.drop_index("ix_incident_comments_tenant_id", table_name="incident_comments")
    op.drop_index("ix_incident_comments_incident_id", table_name="incident_comments")
    op.drop_table("incident_comments")
    op.drop_index("ix_incidents_fingerprint", table_name="incidents")
    op.drop_index("ix_incidents_severity", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_index("ix_incidents_tenant_id", table_name="incidents")
    op.drop_table("incidents")
