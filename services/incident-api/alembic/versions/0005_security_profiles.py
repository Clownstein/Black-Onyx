"""create security profile tables

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-27

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_profiles",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("profile_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("selected_packs", sa.JSON(), nullable=False),
        sa.Column("asset_scope", sa.JSON(), nullable=False),
        sa.Column("enabled_surfaces", sa.JSON(), nullable=False),
        sa.Column("schedule", sa.String(length=64), nullable=False),
        sa.Column("strictness", sa.String(length=64), nullable=False),
        sa.Column("merge_policy", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "profile_id", name="uq_security_profiles_tenant_profile"),
    )
    op.create_index("ix_security_profiles_tenant_id", "security_profiles", ["tenant_id"])

    op.create_table(
        "profile_check_state",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("profile_id", sa.String(length=128), nullable=False),
        sa.Column("check_id", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=True),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "profile_id",
            "check_id",
            name="uq_profile_check_state_tenant_profile_check",
        ),
    )
    op.create_index("ix_profile_check_state_tenant_id", "profile_check_state", ["tenant_id"])
    op.create_index("ix_profile_check_state_profile_id", "profile_check_state", ["profile_id"])

    op.create_table(
        "profile_attestations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("attestation_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("profile_id", sa.String(length=128), nullable=False),
        sa.Column("check_id", sa.String(length=256), nullable=False),
        sa.Column("author", sa.String(length=256), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("evidence_links", sa.JSON(), nullable=False),
        sa.Column("attested_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "attestation_id",
            name="uq_profile_attestations_attestation_id_legacy",
        ),
    )
    op.create_index("ix_profile_attestations_tenant_id", "profile_attestations", ["tenant_id"])
    op.create_index("ix_profile_attestations_profile_id", "profile_attestations", ["profile_id"])

    op.create_table(
        "profile_exceptions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("exception_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("profile_id", sa.String(length=128), nullable=False),
        sa.Column("check_id", sa.String(length=256), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(length=256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "exception_id",
            name="uq_profile_exceptions_exception_id_legacy",
        ),
    )
    op.create_index("ix_profile_exceptions_tenant_id", "profile_exceptions", ["tenant_id"])
    op.create_index("ix_profile_exceptions_profile_id", "profile_exceptions", ["profile_id"])


def downgrade() -> None:
    op.drop_index("ix_profile_exceptions_profile_id", table_name="profile_exceptions")
    op.drop_index("ix_profile_exceptions_tenant_id", table_name="profile_exceptions")
    op.drop_table("profile_exceptions")
    op.drop_index("ix_profile_attestations_profile_id", table_name="profile_attestations")
    op.drop_index("ix_profile_attestations_tenant_id", table_name="profile_attestations")
    op.drop_table("profile_attestations")
    op.drop_index("ix_profile_check_state_profile_id", table_name="profile_check_state")
    op.drop_index("ix_profile_check_state_tenant_id", table_name="profile_check_state")
    op.drop_table("profile_check_state")
    op.drop_index("ix_security_profiles_tenant_id", table_name="security_profiles")
    op.drop_table("security_profiles")
