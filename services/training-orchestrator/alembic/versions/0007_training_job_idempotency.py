"""deduplicate retried training-job submissions"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("training_jobs") as batch:
        batch.add_column(sa.Column("idempotency_key", sa.String(length=128), nullable=True))
        batch.create_unique_constraint(
            "uq_training_jobs_tenant_idempotency", ["tenant_id", "idempotency_key"],
        )


def downgrade() -> None:
    with op.batch_alter_table("training_jobs") as batch:
        batch.drop_constraint("uq_training_jobs_tenant_idempotency", type_="unique")
        batch.drop_column("idempotency_key")
