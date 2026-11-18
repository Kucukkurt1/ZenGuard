from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AnalysisUploadResponse(BaseModel):
    id: UUID
    sha256: str
    status: str
    original_filename: str
    size_bytes: int


class AnalysisSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime
    original_filename: str
    sha256: str
    size_bytes: int
    mime_type: str
    status: str
    risk_score: Optional[int] = None
    risk_band: Optional[str] = None
    coverage: Optional[str] = None
    progress_percent: Optional[int] = None
    progress_stage: Optional[str] = None


class AnalysisDetail(AnalysisSummary):
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    storage_path: str
    ruleset_version: Optional[str] = None
    engine_versions: Optional[dict[str, Any]] = None
    task_id: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    report: Optional[dict[str, Any]] = None


class AnalysisListResponse(BaseModel):
    items: list[AnalysisSummary]
    limit: int
    offset: int
    total: int


class HealthResponse(BaseModel):
    api: str
    db: str
    redis: str
    clamav: str

