"""add model serving desired state and replica reports

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_serving_desired",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("model_name", sa.String(length=128), nullable=False),
        sa.Column("alias", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("package_signature", sa.String(length=128), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "model_name", "alias", name="uq_model_serving_desired"),
    )
    op.create_index("ix_model_serving_desired_tenant_id", "model_serving_desired", ["tenant_id"])
    op.create_index("ix_model_serving_desired_model_name", "model_serving_desired", ["model_name"])
    op.create_table(
        "model_serving_instances",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("model_name", sa.String(length=128), nullable=False),
        sa.Column("instance_id", sa.String(length=128), nullable=False),
        sa.Column("alias", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("package_signature", sa.String(length=128), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "model_name", "instance_id", "alias", name="uq_model_serving_instance",
        ),
    )
    op.create_index("ix_model_serving_instances_tenant_id", "model_serving_instances", ["tenant_id"])
    op.create_index("ix_model_serving_instances_model_name", "model_serving_instances", ["model_name"])


def downgrade() -> None:
    op.drop_index("ix_model_serving_instances_model_name", table_name="model_serving_instances")
    op.drop_index("ix_model_serving_instances_tenant_id", table_name="model_serving_instances")
    op.drop_table("model_serving_instances")
    op.drop_index("ix_model_serving_desired_model_name", table_name="model_serving_desired")
    op.drop_index("ix_model_serving_desired_tenant_id", table_name="model_serving_desired")
    op.drop_table("model_serving_desired")
