"""align operational indexes with ORM metadata"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

INDEXES = {
    "analyst_feedback": ("incident_id", "tenant_id"),
    "deployment_events": ("environment", "service_id", "tenant_id"),
    "incident_timeline": ("incident_id", "tenant_id"),
    "notification_settings": ("tenant_id",),
    "operational_audit": ("resource_id", "resource_type", "tenant_id"),
    "saved_hunts": ("tenant_id",),
}


def upgrade() -> None:
    for table, columns in INDEXES.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade() -> None:
    for table, columns in reversed(list(INDEXES.items())):
        for column in reversed(columns):
            op.drop_index(f"ix_{table}_{column}", table_name=table)
