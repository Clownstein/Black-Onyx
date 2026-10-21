"""align nullability and indexes with ORM metadata"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("email_outbox") as batch:
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)
    op.create_index("ix_email_outbox_tenant_id", "email_outbox", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_email_outbox_tenant_id", table_name="email_outbox")
    with op.batch_alter_table("email_outbox") as batch:
        batch.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=True)
        batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=True)
