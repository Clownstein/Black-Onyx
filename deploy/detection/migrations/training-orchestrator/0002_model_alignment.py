"""align nullability and indexes with ORM metadata"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TIMESTAMPS = {
    "training_jobs": ("created_at", "updated_at"),
    "model_aliases": ("updated_at",),
    "model_version_history": ("created_at",),
    "drift_observations": ("observed_at",),
}


def upgrade() -> None:
    for table, columns in TIMESTAMPS.items():
        with op.batch_alter_table(table) as batch:
            for column in columns:
                batch.alter_column(column, existing_type=sa.DateTime(timezone=True), nullable=False)
    for table in TIMESTAMPS:
        for column in ("tenant_id", "model_name"):
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade() -> None:
    for table in reversed(list(TIMESTAMPS)):
        for column in ("model_name", "tenant_id"):
            op.drop_index(f"ix_{table}_{column}", table_name=table)
    for table, columns in reversed(list(TIMESTAMPS.items())):
        with op.batch_alter_table(table) as batch:
            for column in reversed(columns):
                batch.alter_column(column, existing_type=sa.DateTime(timezone=True), nullable=True)
