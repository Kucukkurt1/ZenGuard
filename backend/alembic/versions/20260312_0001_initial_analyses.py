"""initial analyses table

Revision ID: 20260312_0001
Revises:
Create Date: 2026-03-12

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260312_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("sha256", sa.CHAR(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("mime_type", sa.Text(), nullable=False),
        sa.Column("storage_path", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.SmallInteger(), nullable=True),
        sa.Column("risk_band", sa.String(length=16), nullable=True),
        sa.Column("coverage", sa.String(length=16), nullable=True),
        sa.Column("ruleset_version", sa.Text(), nullable=True),
        sa.Column("engine_versions", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("task_id", sa.Text(), nullable=True),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("report", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'rejected')",
            name="ck_analyses_status",
        ),
        sa.CheckConstraint(
            "risk_band IS NULL OR risk_band IN "
            "('clean', 'low', 'medium', 'high', 'critical')",
            name="ck_analyses_risk_band",
        ),
        sa.CheckConstraint(
            "coverage IS NULL OR coverage IN ('full', 'partial', 'none')",
            name="ck_analyses_coverage",
        ),
        sa.CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
            name="ck_analyses_risk_score_range",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analyses_sha256", "analyses", ["sha256"], unique=False)
    op.create_index("ix_analyses_status", "analyses", ["status"], unique=False)
    op.create_index(
        "ix_analyses_created_at_desc",
        "analyses",
        [sa.text("created_at DESC")],
        unique=False,
    )
    op.create_index("ix_analyses_risk_score", "analyses", ["risk_score"], unique=False)
    op.create_index(
        "ix_analyses_report_gin",
        "analyses",
        ["report"],
        unique=False,
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("ix_analyses_report_gin", table_name="analyses")
    op.drop_index("ix_analyses_risk_score", table_name="analyses")
    op.drop_index("ix_analyses_created_at_desc", table_name="analyses")
    op.drop_index("ix_analyses_status", table_name="analyses")
    op.drop_index("ix_analyses_sha256", table_name="analyses")
    op.drop_table("analyses")
