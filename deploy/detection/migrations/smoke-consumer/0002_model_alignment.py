"""align nullability and indexes with ORM metadata"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ingested_events") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
    op.create_index("ix_ingested_events_tenant_id", "ingested_events", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_ingested_events_tenant_id", table_name="ingested_events")
    with op.batch_alter_table("ingested_events") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=True)
