"""align nullability and indexes with ORM metadata"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("indicators") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
    with op.batch_alter_table("feed_checkpoints") as batch:
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)
    for column in ("observable_type", "observable_value", "source", "tenant_id"):
        op.create_index(f"ix_indicators_{column}", "indicators", [column])


def downgrade() -> None:
    for column in ("tenant_id", "source", "observable_value", "observable_type"):
        op.drop_index(f"ix_indicators_{column}", table_name="indicators")
    with op.batch_alter_table("feed_checkpoints") as batch:
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=True)
    with op.batch_alter_table("indicators") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=True)
