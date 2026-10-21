"""fence replica confirmations and retain alias removal tombstones"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("model_serving_desired") as batch:
        batch.alter_column(
            "version", existing_type=sa.String(length=64), nullable=True,
        )
        batch.alter_column(
            "package_signature", existing_type=sa.String(length=128), nullable=True,
        )
        batch.alter_column(
            "updated_at", existing_type=sa.DateTime(timezone=True), nullable=False,
        )
    with op.batch_alter_table("model_serving_instances") as batch:
        batch.add_column(
            sa.Column("generation", sa.Integer(), nullable=False, server_default="0")
        )
        batch.alter_column("generation", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("model_serving_instances") as batch:
        batch.drop_column("generation")
    op.execute(
        "DELETE FROM model_serving_desired WHERE version IS NULL OR package_signature IS NULL"
    )
    with op.batch_alter_table("model_serving_desired") as batch:
        batch.alter_column(
            "package_signature", existing_type=sa.String(length=128), nullable=False,
        )
        batch.alter_column(
            "version", existing_type=sa.String(length=64), nullable=False,
        )
        batch.alter_column(
            "updated_at", existing_type=sa.DateTime(timezone=True), nullable=True,
        )
