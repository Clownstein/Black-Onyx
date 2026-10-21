"""Create auth/tip schemas and cutover marker table."""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS auth")
    op.execute("CREATE SCHEMA IF NOT EXISTS tip")
    op.create_table(
        "platform_cutover",
        sa.Column("domain", sa.String(length=64), primary_key=True),
        sa.Column("migrated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("sqlite_counts", sa.JSON(), nullable=False),
        sa.Column("postgres_counts", sa.JSON(), nullable=False),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("platform_cutover", schema="public")
    op.execute("DROP SCHEMA IF EXISTS tip CASCADE")
    op.execute("DROP SCHEMA IF EXISTS auth CASCADE")
