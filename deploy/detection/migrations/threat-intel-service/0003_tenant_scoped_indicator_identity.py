"""scope indicator identity by tenant"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("indicators") as batch:
        batch.drop_constraint("uq_indicators_type_value_source", type_="unique")
        batch.create_unique_constraint(
            "uq_indicators_type_value_source_tenant",
            ["observable_type", "observable_value", "source", "tenant_id"],
        )
    op.create_index(
        "uq_indicators_global_type_value_source",
        "indicators",
        ["observable_type", "observable_value", "source"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
        sqlite_where=sa.text("tenant_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_indicators_global_type_value_source", table_name="indicators")
    with op.batch_alter_table("indicators") as batch:
        batch.drop_constraint("uq_indicators_type_value_source_tenant", type_="unique")
        batch.create_unique_constraint(
            "uq_indicators_type_value_source",
            ["observable_type", "observable_value", "source"],
        )
