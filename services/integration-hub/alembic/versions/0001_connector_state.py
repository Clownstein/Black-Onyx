"""create integration connector execution state"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "thehive_dry_runs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=False),
        sa.Column("operation", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_thehive_dry_runs_tenant_incident",
        "thehive_dry_runs",
        ["tenant_id", "incident_id"],
    )
    op.create_table(
        "dfir_collect_requests",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=True),
        sa.Column("asset_id", sa.String(length=256), nullable=False),
        sa.Column("artifact", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "request_id",
            name="uq_dfir_requests_tenant_request",
        ),
    )
    op.create_index(
        "ix_dfir_requests_tenant_asset",
        "dfir_collect_requests",
        ["tenant_id", "asset_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_dfir_requests_tenant_asset", table_name="dfir_collect_requests")
    op.drop_table("dfir_collect_requests")
    op.drop_index(
        "ix_thehive_dry_runs_tenant_incident",
        table_name="thehive_dry_runs",
    )
    op.drop_table("thehive_dry_runs")
