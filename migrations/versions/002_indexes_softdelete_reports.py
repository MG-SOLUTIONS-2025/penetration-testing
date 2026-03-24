"""No-op placeholder (schema merged into 001_full_blueprint).

Revision ID: 002_indexes_softdelete_reports
Revises: 001_full_blueprint
Create Date: 2026-03-20
"""

from alembic import op  # noqa: F401

revision = "002_indexes_softdelete_reports"
down_revision = "001_full_blueprint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
