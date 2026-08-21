"""create threat intelligence indicators, health, and checkpoints"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "indicators",
        sa.Column("indicator_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=True),
        sa.Column("observable_type", sa.String(length=64), nullable=False),
        sa.Column("observable_value", sa.String(length=2048), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("tlp", sa.String(length=32), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("campaigns", sa.JSON(), nullable=False),
        sa.Column("mitre_techniques", sa.JSON(), nullable=False),
        sa.Column("raw_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("indicator_id"),
        sa.UniqueConstraint(
            "observable_type",
            "observable_value",
            "source",
            name="uq_indicators_type_value_source",
        ),
    )
    op.create_index(
        "ix_indicators_tenant_observable",
        "indicators",
        ["tenant_id", "observable_type", "observable_value"],
    )
    op.create_table(
        "feed_health",
        sa.Column("feed_name", sa.String(length=128), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=32), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("indicator_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("feed_name"),
    )
    op.create_table(
        "feed_checkpoints",
        sa.Column("feed_name", sa.String(length=128), nullable=False),
        sa.Column("cursor", sa.Text(), nullable=True),
        sa.Column("etag", sa.String(length=512), nullable=True),
        sa.Column("last_modified", sa.String(length=128), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("feed_name"),
    )


def downgrade() -> None:
    op.drop_table("feed_checkpoints")
    op.drop_table("feed_health")
    op.drop_index("ix_indicators_tenant_observable", table_name="indicators")
    op.drop_table("indicators")
