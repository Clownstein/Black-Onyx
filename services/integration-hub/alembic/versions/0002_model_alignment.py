"""align nullability and indexes with ORM metadata"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("thehive_dry_runs", "dfir_collect_requests"):
        with op.batch_alter_table(table) as batch:
            batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=False)
    for table, columns in {
        "thehive_dry_runs": ("tenant_id", "incident_id"),
        "dfir_collect_requests": ("tenant_id", "request_id"),
    }.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade() -> None:
    for table, columns in {
        "dfir_collect_requests": ("request_id", "tenant_id"),
        "thehive_dry_runs": ("incident_id", "tenant_id"),
    }.items():
        for column in columns:
            op.drop_index(f"ix_{table}_{column}", table_name=table)
    for table in ("dfir_collect_requests", "thehive_dry_runs"):
        with op.batch_alter_table(table) as batch:
            batch.alter_column("created_at", existing_type=sa.DateTime(timezone=True), nullable=True)
