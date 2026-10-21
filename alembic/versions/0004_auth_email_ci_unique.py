"""Case-insensitive unique email for auth.users."""

from typing import Sequence, Union

from alembic import op
from sqlalchemy import text

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("SET search_path TO auth")
    # Normalize stored emails to lowercase so UNIQUE(email) and LOWER(email)
    # agree with the app's strip().casefold() writes for ASCII addresses.
    op.execute("UPDATE users SET email = LOWER(email) WHERE email IS DISTINCT FROM LOWER(email)")
    # Collapse any remaining case-variant duplicates (keep the earliest user_id).
    bind = op.get_bind()
    duplicates = bind.execute(
        text(
            "SELECT LOWER(email) AS email_key, MIN(user_id) AS keep_id, COUNT(*) AS n "
            "FROM users GROUP BY LOWER(email) HAVING COUNT(*) > 1"
        )
    ).fetchall()
    for row in duplicates:
        email_key = row[0]
        keep_id = row[1]
        bind.execute(
            text(
                "DELETE FROM users WHERE LOWER(email) = :email_key AND user_id <> :keep_id"
            ),
            {"email_key": email_key, "keep_id": keep_id},
        )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower ON users (LOWER(email))"
    )


def downgrade() -> None:
    op.execute("SET search_path TO auth")
    op.execute("DROP INDEX IF EXISTS ux_users_email_lower")
