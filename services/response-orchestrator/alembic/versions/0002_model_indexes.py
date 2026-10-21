"""align indexes with ORM metadata"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

INDEXES = {
    "response_requests": ("incident_id", "request_id", "tenant_id"),
    "response_audit": ("request_id", "tenant_id"),
}


def upgrade() -> None:
    for table, columns in INDEXES.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade() -> None:
    for table, columns in reversed(list(INDEXES.items())):
        for column in reversed(columns):
            op.drop_index(f"ix_{table}_{column}", table_name=table)
