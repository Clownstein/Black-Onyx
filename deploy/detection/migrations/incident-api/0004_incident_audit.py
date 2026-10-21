"""create incident_audit table matching ORM

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-26

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incident_audit",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incident_audit_tenant_id", "incident_audit", ["tenant_id"])
    op.create_index("ix_incident_audit_incident_id", "incident_audit", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_incident_audit_incident_id", table_name="incident_audit")
    op.drop_index("ix_incident_audit_tenant_id", table_name="incident_audit")
    op.drop_table("incident_audit")
