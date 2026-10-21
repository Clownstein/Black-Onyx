"""add relational incident and operational domain tables

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Development databases may be rebuilt, but these constraints are additive
    # so an existing local database can also be upgraded safely.
    with op.batch_alter_table("incident_comments") as batch:
        batch.drop_constraint("uq_comments_comment_id_legacy", type_="unique")
        batch.create_unique_constraint(
            "uq_comments_tenant_comment",
            ["tenant_id", "comment_id"],
        )
        batch.create_foreign_key(
            "fk_comments_tenant_incident",
            "incidents",
            ["tenant_id", "incident_id"],
            ["tenant_id", "incident_id"],
            ondelete="CASCADE",
        )
    with op.batch_alter_table("incident_audit") as batch:
        batch.create_foreign_key(
            "fk_incident_audit_tenant_incident",
            "incidents",
            ["tenant_id", "incident_id"],
            ["tenant_id", "incident_id"],
            ondelete="CASCADE",
        )

    op.create_table(
        "incident_findings",
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=False),
        sa.Column("finding_id", sa.String(length=128), nullable=False),
        sa.Column(
            "linked_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_incident_findings_tenant_incident",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "finding_id"],
            ["findings.tenant_id", "findings.finding_id"],
            name="fk_incident_findings_tenant_finding",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "incident_id", "finding_id"),
    )

    # Replace the unused migration-only timeline table with the authoritative shape.
    op.drop_table("incident_timeline")
    op.create_table(
        "incident_timeline",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entry_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("actor", sa.String(length=256), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_timeline_tenant_incident",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "entry_id", name="uq_timeline_tenant_entry"),
    )
    op.create_index("ix_timeline_tenant_incident", "incident_timeline", ["tenant_id", "incident_id"])
    op.create_index("ix_timeline_occurred_at", "incident_timeline", ["occurred_at"])

    op.create_table(
        "deployment_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("deployment_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("service_id", sa.String(length=256), nullable=False),
        sa.Column("environment", sa.String(length=128), nullable=False),
        sa.Column("commit_sha", sa.String(length=128), nullable=True),
        sa.Column("version", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "deployment_id",
            name="uq_deployments_tenant_deployment",
        ),
    )
    op.create_index("ix_deployments_tenant_service", "deployment_events", ["tenant_id", "service_id"])
    op.create_index("ix_deployments_commit", "deployment_events", ["commit_sha"])

    op.create_table(
        "saved_hunts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("hunt_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("query_type", sa.String(length=64), nullable=False),
        sa.Column("filters", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "hunt_id", name="uq_saved_hunts_tenant_hunt"),
    )

    op.create_table(
        "analyst_feedback",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("feedback_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=False),
        sa.Column("finding_id", sa.String(length=128), nullable=True),
        sa.Column("label", sa.String(length=64), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("actor", sa.String(length=256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "incident_id"],
            ["incidents.tenant_id", "incidents.incident_id"],
            name="fk_feedback_tenant_incident",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "finding_id"],
            ["findings.tenant_id", "findings.finding_id"],
            name="fk_feedback_tenant_finding",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "feedback_id",
            name="uq_feedback_tenant_feedback",
        ),
    )

    op.create_table(
        "notification_settings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("setting_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("channel", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.String(length=256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "setting_id",
            name="uq_notification_settings_tenant_setting",
        ),
    )
    op.create_table(
        "operational_audit",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("actor", sa.String(length=256), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_operational_audit_tenant_resource",
        "operational_audit",
        ["tenant_id", "resource_type", "resource_id"],
    )

    for table, constraint in [
        ("profile_check_state", "fk_profile_state_tenant_profile"),
        ("profile_attestations", "fk_attestations_tenant_profile"),
        ("profile_exceptions", "fk_exceptions_tenant_profile"),
    ]:
        with op.batch_alter_table(table) as batch:
            batch.create_foreign_key(
                constraint,
                "security_profiles",
                ["tenant_id", "profile_id"],
                ["tenant_id", "profile_id"],
                ondelete="CASCADE",
            )
    with op.batch_alter_table("profile_attestations") as batch:
        batch.drop_constraint(
            "uq_profile_attestations_attestation_id_legacy",
            type_="unique",
        )
        batch.create_unique_constraint(
            "uq_attestations_tenant_attestation",
            ["tenant_id", "attestation_id"],
        )
    with op.batch_alter_table("profile_exceptions") as batch:
        batch.drop_constraint(
            "uq_profile_exceptions_exception_id_legacy",
            type_="unique",
        )
        batch.create_unique_constraint(
            "uq_exceptions_tenant_exception",
            ["tenant_id", "exception_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("profile_exceptions") as batch:
        batch.drop_constraint("uq_exceptions_tenant_exception", type_="unique")
        batch.create_unique_constraint(
            "uq_profile_exceptions_exception_id_legacy",
            ["exception_id"],
        )
    with op.batch_alter_table("profile_attestations") as batch:
        batch.drop_constraint("uq_attestations_tenant_attestation", type_="unique")
        batch.create_unique_constraint(
            "uq_profile_attestations_attestation_id_legacy",
            ["attestation_id"],
        )
    for table, constraint in [
        ("profile_exceptions", "fk_exceptions_tenant_profile"),
        ("profile_attestations", "fk_attestations_tenant_profile"),
        ("profile_check_state", "fk_profile_state_tenant_profile"),
    ]:
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(constraint, type_="foreignkey")
    op.drop_index(
        "ix_operational_audit_tenant_resource",
        table_name="operational_audit",
    )
    op.drop_table("operational_audit")
    op.drop_table("notification_settings")
    op.drop_table("analyst_feedback")
    op.drop_table("saved_hunts")
    op.drop_index("ix_deployments_commit", table_name="deployment_events")
    op.drop_index("ix_deployments_tenant_service", table_name="deployment_events")
    op.drop_table("deployment_events")
    op.drop_index("ix_timeline_occurred_at", table_name="incident_timeline")
    op.drop_index("ix_timeline_tenant_incident", table_name="incident_timeline")
    op.drop_table("incident_timeline")
    op.create_table(
        "incident_timeline",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entry_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("actor", sa.String(length=256), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entry_id"),
    )
    op.drop_table("incident_findings")
    with op.batch_alter_table("incident_audit") as batch:
        batch.drop_constraint(
            "fk_incident_audit_tenant_incident",
            type_="foreignkey",
        )
    with op.batch_alter_table("incident_comments") as batch:
        batch.drop_constraint("fk_comments_tenant_incident", type_="foreignkey")
        batch.drop_constraint("uq_comments_tenant_comment", type_="unique")
        batch.create_unique_constraint(
            "uq_comments_comment_id_legacy",
            ["comment_id"],
        )
