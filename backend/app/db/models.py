from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel

ANALYSIS_STATUSES = ("queued", "running", "completed", "failed", "rejected")
RISK_BANDS = ("clean", "low", "medium", "high", "critical")
COVERAGE_VALUES = ("full", "partial", "none")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Analysis(SQLModel, table=True):
    __tablename__ = "analyses"
    __table_args__ = (
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
    )

    id: UUID = Field(
        default_factory=uuid4,
        primary_key=True,
        sa_type=sa.Uuid(),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=False),
    )
    started_at: Optional[datetime] = Field(
        default=None,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=True),
    )
    finished_at: Optional[datetime] = Field(
        default=None,
        sa_column=sa.Column(sa.DateTime(timezone=True), nullable=True),
    )
    original_filename: str = Field(max_length=255)
    sha256: str = Field(max_length=64, sa_column=sa.Column(sa.CHAR(64), nullable=False))
    size_bytes: int = Field(sa_column=sa.Column(sa.BigInteger(), nullable=False))
    mime_type: str = Field(default="application/octet-stream")
    storage_path: str
    status: str = Field(default="queued", max_length=32)
    risk_score: Optional[int] = Field(
        default=None, sa_column=sa.Column(sa.SmallInteger(), nullable=True)
    )
    risk_band: Optional[str] = Field(default=None, max_length=16)
    coverage: Optional[str] = Field(default=None, max_length=16)
    ruleset_version: Optional[str] = Field(default=None)
    engine_versions: Optional[dict[str, Any]] = Field(
        default=None, sa_column=sa.Column(JSONB, nullable=True)
    )
    task_id: Optional[str] = Field(default=None)
    error_code: Optional[str] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    report: Optional[dict[str, Any]] = Field(
        default=None, sa_column=sa.Column(JSONB, nullable=True)
    )
