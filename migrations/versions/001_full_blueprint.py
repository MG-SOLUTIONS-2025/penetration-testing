"""Full schema — creates all tables, indexes, and the reports table.

Revision ID: 001_full_blueprint
Revises:
Create Date: 2026-03-17
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "001_full_blueprint"
down_revision = None
branch_labels = None
depends_on = None

_UUID = postgresql.UUID(as_uuid=True)


def _fk(table):
    return sa.ForeignKey(f"{table}.id")


def upgrade() -> None:
    # ── users ──────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("email", sa.String(255), unique=True, index=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("is_admin", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── engagements ────────────────────────────────────────────────────────
    op.create_table(
        "engagements",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("client_name", sa.String(255), nullable=False),
        sa.Column("authorized_by", sa.Text, nullable=False),
        sa.Column("auth_document_hash", sa.String(64), nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("allow_ddos_testing", sa.Boolean, server_default="false"),
        sa.Column("allow_exploitation", sa.Boolean, server_default="false"),
        sa.Column("created_by", _UUID, _fk("users"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── targets ────────────────────────────────────────────────────────────
    op.create_table(
        "targets",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("engagement_id", _UUID, _fk("engagements"), nullable=False),
        sa.Column("target_type", sa.String(20), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("is_in_scope", sa.Boolean, server_default="true"),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── audit_log ──────────────────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("user_id", _UUID, _fk("users"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", _UUID, nullable=True),
        sa.Column("detail", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── scans ──────────────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("engagement_id", _UUID, _fk("engagements"), nullable=False),
        sa.Column("target_id", _UUID, _fk("targets"), nullable=True),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("config", postgresql.JSONB, nullable=True),
        sa.Column("baseline_scan_id", _UUID, sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_by", _UUID, _fk("users"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scans_engagement_id", "scans", ["engagement_id"])

    # ── findings ───────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("scan_id", _UUID, _fk("scans"), nullable=False),
        sa.Column("engagement_id", _UUID, _fk("engagements"), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("finding_type", sa.String(100), nullable=False),
        sa.Column("target_value", sa.String(512), nullable=False),
        sa.Column("detail", postgresql.JSONB, nullable=True),
        sa.Column("raw_output", sa.Text, nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("defectdojo_finding_id", sa.Integer, nullable=True),
        sa.Column("cvss_vector", sa.String(100), nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("vpr_score", sa.Float, nullable=True),
        sa.Column("vpr_factors", postgresql.JSONB, nullable=True),
        sa.Column("cwe_id", sa.Integer, nullable=True),
        sa.Column("compliance_mappings", postgresql.JSONB, nullable=True),
        sa.Column("status", sa.String(20), server_default="new"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_findings_engagement_fingerprint", "findings",
        ["engagement_id", "fingerprint"], unique=True,
    )
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_engagement_id_2", "findings", ["engagement_id"])

    # ── refresh_tokens ─────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("user_id", _UUID, _fk("users"), nullable=False),
        sa.Column("token_hash", sa.String(64), unique=True, index=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── scan_schedules ─────────────────────────────────────────────────────
    op.create_table(
        "scan_schedules",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("engagement_id", _UUID, _fk("engagements"), nullable=False),
        sa.Column("target_id", _UUID, _fk("targets"), nullable=False),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("config", postgresql.JSONB, nullable=True),
        sa.Column("cron_expression", sa.String(100), nullable=False),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", _UUID, _fk("users"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scan_schedules_engagement_id", "scan_schedules", ["engagement_id"])

    # ── audit_log_worm ─────────────────────────────────────────────────────
    op.create_table(
        "audit_log_worm",
        sa.Column("sequence_number", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), unique=True, index=True, nullable=False),
        sa.Column("user_id", _UUID, _fk("users"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", _UUID, nullable=True),
        sa.Column("detail", postgresql.JSONB, nullable=True),
        sa.Column("client_ip", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── credential_exposures ───────────────────────────────────────────────
    op.create_table(
        "credential_exposures",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("engagement_id", _UUID, _fk("engagements"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("breach_name", sa.String(255), nullable=False),
        sa.Column("breach_date", sa.String(20), nullable=True),
        sa.Column("data_classes", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_credential_exposures_engagement_id", "credential_exposures", ["engagement_id"]
    )

    # ── exploit_attempts ───────────────────────────────────────────────────
    op.create_table(
        "exploit_attempts",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("engagement_id", _UUID, _fk("engagements"), nullable=False),
        sa.Column("finding_id", _UUID, _fk("findings"), nullable=True),
        sa.Column("module_name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("output", sa.Text, nullable=True),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("created_by", _UUID, _fk("users"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── reports ────────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("engagement_id", _UUID, _fk("engagements"), nullable=False),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column("template", sa.String(100), nullable=False),
        sa.Column("content", sa.Text, nullable=True),
        sa.Column("content_bytes", sa.LargeBinary, nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("generated_by", _UUID, _fk("users"), nullable=True),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_reports_engagement_id", "reports", ["engagement_id"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("exploit_attempts")
    op.drop_table("credential_exposures")
    op.drop_table("audit_log_worm")
    op.drop_table("scan_schedules")
    op.drop_table("refresh_tokens")
    op.drop_index("ix_findings_engagement_id_2", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_engagement_fingerprint", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scans_engagement_id", table_name="scans")
    op.drop_table("scans")
    op.drop_table("audit_log")
    op.drop_table("targets")
    op.drop_table("engagements")
    op.drop_table("users")
