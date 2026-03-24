"""Remove authentication: drop refresh_tokens, make created_by nullable,
drop hashed_password and is_admin from users.

Revision ID: 003_remove_auth
Revises: 002_indexes_softdelete_reports
Create Date: 2026-03-24
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "003_remove_auth"
down_revision = "002_indexes_softdelete_reports"
branch_labels = None
depends_on = None

_UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    # Drop refresh_tokens table
    op.drop_table("refresh_tokens")

    # Make created_by nullable on engagements, scans, scan_schedules, exploit_attempts
    op.alter_column("engagements", "created_by", existing_type=_UUID, nullable=True)
    op.alter_column("scans", "created_by", existing_type=_UUID, nullable=True)
    op.alter_column("scan_schedules", "created_by", existing_type=_UUID, nullable=True)
    op.alter_column("exploit_attempts", "created_by", existing_type=_UUID, nullable=True)

    # Drop auth columns from users
    op.drop_column("users", "hashed_password")
    op.drop_column("users", "is_admin")


def downgrade() -> None:
    # Re-add auth columns to users
    op.add_column("users", sa.Column("is_admin", sa.Boolean, server_default="false"))
    op.add_column("users", sa.Column("hashed_password", sa.String(255), nullable=False, server_default=""))

    # Make created_by NOT NULL again
    op.alter_column("exploit_attempts", "created_by", existing_type=_UUID, nullable=False)
    op.alter_column("scan_schedules", "created_by", existing_type=_UUID, nullable=False)
    op.alter_column("scans", "created_by", existing_type=_UUID, nullable=False)
    op.alter_column("engagements", "created_by", existing_type=_UUID, nullable=False)

    # Re-create refresh_tokens table
    op.create_table(
        "refresh_tokens",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("user_id", _UUID, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), unique=True, index=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
