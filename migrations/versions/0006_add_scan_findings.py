"""add scan_findings

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("artifact_digest", sa.String(), nullable=False),
        sa.Column("scanner", sa.String(), nullable=False),
        sa.Column("advisory_id", sa.String(), nullable=False),
        sa.Column("package", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), server_default="", nullable=False),
        sa.Column("fix_state", sa.String(), server_default="unknown", nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(["artifact_digest"], ["artifacts.digest"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_digest", "scanner", "advisory_id", "package"),
    )
    op.create_index(
        op.f("ix_scan_findings_artifact_digest"), "scan_findings", ["artifact_digest"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_findings_artifact_digest"), table_name="scan_findings")
    op.drop_table("scan_findings")
