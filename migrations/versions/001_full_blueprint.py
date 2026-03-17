"""Full blueprint compliance migration — adds all new tables and columns.

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
    # --- Phase 1.5: Refresh tokens ---
    op.create_table(
        "refresh_tokens",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("user_id", _UUID, _fk("users"), nullable=False),
        sa.Column("token_hash", sa.String(64), unique=True, index=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # --- Phase 2.1: Scan schedules ---
    op.create_table(
        "scan_schedules",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("engagement_id", _UUID, _fk("engagements"), nullable=False),
        sa.Column("target_id", _UUID, _fk("targets"), nullable=False),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("config", postgresql.JSONB, nullable=True),
        sa.Column("cron_expression", sa.String(100), nullable=False),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", _UUID, _fk("users"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # --- Phase 2.2: CVSS columns on findings ---
    op.add_column("findings", sa.Column("cvss_vector", sa.String(100), nullable=True))
    op.add_column("findings", sa.Column("cvss_score", sa.Float, nullable=True))

    # --- Phase 2.3: Finding status/diffing columns ---
    op.add_column("findings", sa.Column("status", sa.String(20), server_default="new"))
    op.add_column(
        "findings",
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scans",
        sa.Column("baseline_scan_id", _UUID, _fk("scans"), nullable=True),
    )

    # --- Phase 2.5: WORM audit log ---
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

    # --- Phase 4.1: Credential exposures ---
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

    # --- Phase 4.2: DDoS testing flag ---
    op.add_column(
        "engagements",
        sa.Column("allow_ddos_testing", sa.Boolean, server_default="false"),
    )
    op.add_column(
        "engagements",
        sa.Column("allow_exploitation", sa.Boolean, server_default="false"),
    )

    # --- Phase 4.3: Exploit attempts ---
    op.create_table(
        "exploit_attempts",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("engagement_id", _UUID, _fk("engagements"), nullable=False),
        sa.Column("finding_id", _UUID, _fk("findings"), nullable=True),
        sa.Column("module_name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("output", sa.Text, nullable=True),
        sa.Column("created_by", _UUID, _fk("users"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # --- Phase 5.1: Compliance fields ---
    op.add_column("findings", sa.Column("cwe_id", sa.Integer, nullable=True))
    op.add_column("findings", sa.Column("compliance_mappings", postgresql.JSONB, nullable=True))

    # --- Phase 5.2: VPR fields ---
    op.add_column("findings", sa.Column("vpr_score", sa.Float, nullable=True))
    op.add_column("findings", sa.Column("vpr_factors", postgresql.JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "vpr_factors")
    op.drop_column("findings", "vpr_score")
    op.drop_column("findings", "compliance_mappings")
    op.drop_column("findings", "cwe_id")
    op.drop_table("exploit_attempts")
    op.drop_column("engagements", "allow_exploitation")
    op.drop_column("engagements", "allow_ddos_testing")
    op.drop_table("credential_exposures")
    op.drop_table("audit_log_worm")
    op.drop_column("scans", "baseline_scan_id")
    op.drop_column("findings", "resolved_at")
    op.drop_column("findings", "first_seen_at")
    op.drop_column("findings", "status")
    op.drop_column("findings", "cvss_score")
    op.drop_column("findings", "cvss_vector")
    op.drop_table("scan_schedules")
    op.drop_table("refresh_tokens")
