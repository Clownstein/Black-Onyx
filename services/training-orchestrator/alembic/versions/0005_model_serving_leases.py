"""serialize serving transitions with durable alias leases"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_serving_leases",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("model_name", sa.String(length=128), nullable=False),
        sa.Column("alias", sa.String(length=64), nullable=False),
        sa.Column("lease_token", sa.String(length=36), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "model_name", "alias", name="uq_model_serving_lease"),
    )
    op.create_index("ix_model_serving_leases_tenant_id", "model_serving_leases", ["tenant_id"])
    op.create_index("ix_model_serving_leases_model_name", "model_serving_leases", ["model_name"])


def downgrade() -> None:
    op.drop_index("ix_model_serving_leases_model_name", table_name="model_serving_leases")
    op.drop_index("ix_model_serving_leases_tenant_id", table_name="model_serving_leases")
    op.drop_table("model_serving_leases")
