import asyncio
from pathlib import Path
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, Response, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import get_settings
from app.db.models import Analysis, utc_now
from app.schemas.analysis import (
    AnalysisDetail,
    AnalysisListResponse,
    AnalysisSummary,
    AnalysisUploadResponse,
)
from app.engines.excerpts import excerpts_from
from app.services.progress import clear_progress, get_progress
from app.services.runner import execute_analysis
from app.services.storage import UploadTooLargeError, sanitize_filename, save_upload_streaming

router = APIRouter(prefix="/analyses", tags=["analyses"])

OPEN_STATUSES = ("queued", "running")
TERMINAL_STATUSES = ("completed", "failed", "rejected")


def _fallback_progress(row: Analysis) -> tuple[int, str]:
    if row.status == "queued":
        return 5, "Kuyrukta"
    if row.status == "running":
        return 30, "Taranıyor"
    if row.status == "failed":
        return 100, "Tarama başarısız"
    if row.status == "rejected":
        return 100, "Politika reddi"
    return 100, "Tamamlandı"


def _present_summary(row: Analysis) -> AnalysisSummary:
    item = AnalysisSummary.model_validate(row)
    live = get_progress(row.id)
    if live is not None and row.status in OPEN_STATUSES:
        item.progress_percent, item.progress_stage = live
    else:
        item.progress_percent, item.progress_stage = _fallback_progress(row)
    return item


def _matched_lines(row: Analysis) -> list[dict]:
    if row.status != "completed" or row.risk_band not in ("high", "critical"):
        return []
    root = Path(get_settings().zeng_quarantine_dir).resolve()
    target = (root / row.storage_path).resolve()
    if target == root or root not in target.parents or not target.is_file():
        return []
    try:
        if target.stat().st_size > 1_000_000:
            return []
        return excerpts_from(target.read_bytes())
    except OSError:
        return []


def _present_detail(row: Analysis) -> AnalysisDetail:
    item = AnalysisDetail.model_validate(row)
    summary = _present_summary(row)
    item.progress_percent = summary.progress_percent
    item.progress_stage = summary.progress_stage
    if isinstance(item.report, dict):
        item.report = {**item.report, "lines": _matched_lines(row)}
    return item


async def _kick(analysis_id: UUID) -> None:
    await asyncio.to_thread(execute_analysis, analysis_id)


async def _latest_by_statuses(
    session: AsyncSession, sha256: str, statuses: tuple[str, ...]
) -> Optional[Analysis]:
    stmt = (
        select(Analysis)
        .where(Analysis.sha256 == sha256)
        .where(Analysis.status.in_(statuses))
        .order_by(Analysis.created_at.desc())
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


@router.post(
    "",
    response_model=AnalysisUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_analysis(
    background: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
    file: UploadFile = File(...),
    rescan: bool = Query(False, description="Create a new row for a finished sample"),
) -> AnalysisUploadResponse:
    original_filename = sanitize_filename(file.filename)

    try:
        sha256, size_bytes, storage_path, mime_type = await save_upload_streaming(file)
    except UploadTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Upload exceeds ZENG_MAX_UPLOAD_BYTES",
        ) from exc
    finally:
        await file.close()

    if not rescan:
        open_row = await _latest_by_statuses(session, sha256, OPEN_STATUSES)
        if open_row is not None:
            return AnalysisUploadResponse(
                id=open_row.id,
                sha256=open_row.sha256,
                status=open_row.status,
                original_filename=open_row.original_filename,
                size_bytes=open_row.size_bytes,
            )

        terminal_row = await _latest_by_statuses(session, sha256, TERMINAL_STATUSES)
        if terminal_row is not None:
            return AnalysisUploadResponse(
                id=terminal_row.id,
                sha256=terminal_row.sha256,
                status=terminal_row.status,
                original_filename=terminal_row.original_filename,
                size_bytes=terminal_row.size_bytes,
            )

    now = utc_now()
    row = Analysis(
        original_filename=original_filename,
        sha256=sha256,
        size_bytes=size_bytes,
        mime_type=mime_type,
        storage_path=storage_path,
        status="queued",
        created_at=now,
        updated_at=now,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    background.add_task(_kick, row.id)

    return AnalysisUploadResponse(
        id=row.id,
        sha256=row.sha256,
        status=row.status,
        original_filename=row.original_filename,
        size_bytes=row.size_bytes,
    )


@router.post(
    "/{analysis_id}/run",
    response_model=AnalysisUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_analysis(
    analysis_id: UUID,
    background: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
) -> AnalysisUploadResponse:
    row = await session.get(Analysis, analysis_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if row.status in TERMINAL_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Bu kayıt bitmiş. Yeni tarama için dosyayı yeniden yükleyin.",
        )
    if row.status == "queued":
        background.add_task(_kick, row.id)
    return AnalysisUploadResponse(
        id=row.id,
        sha256=row.sha256,
        status=row.status,
        original_filename=row.original_filename,
        size_bytes=row.size_bytes,
    )


@router.post(
    "/{analysis_id}/rescan",
    response_model=AnalysisUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def rescan_analysis(
    analysis_id: UUID,
    background: BackgroundTasks,
    session: AsyncSession = Depends(get_db),
) -> AnalysisUploadResponse:
    row = await session.get(Analysis, analysis_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if row.status not in TERMINAL_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tarama bitmeden yeniden başlatılamaz.",
        )
    stored = Path(get_settings().zeng_quarantine_dir) / row.storage_path
    if not stored.is_file():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Karantina dosyası yok.",
        )

    now = utc_now()
    fresh = Analysis(
        original_filename=row.original_filename,
        sha256=row.sha256,
        size_bytes=row.size_bytes,
        mime_type=row.mime_type,
        storage_path=row.storage_path,
        status="queued",
        created_at=now,
        updated_at=now,
    )
    session.add(fresh)
    await session.commit()
    await session.refresh(fresh)
    background.add_task(_kick, fresh.id)
    return AnalysisUploadResponse(
        id=fresh.id,
        sha256=fresh.sha256,
        status=fresh.status,
        original_filename=fresh.original_filename,
        size_bytes=fresh.size_bytes,
    )


@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_analysis(
    analysis_id: UUID,
    session: AsyncSession = Depends(get_db),
) -> Response:
    row = await session.get(Analysis, analysis_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if row.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tarama sürüyor. Bitince silebilirsiniz.",
        )

    sha256 = row.sha256
    storage_path = row.storage_path
    others = await session.scalar(
        select(func.count())
        .select_from(Analysis)
        .where(Analysis.sha256 == sha256)
        .where(Analysis.id != row.id)
    )
    await session.delete(row)
    await session.commit()
    clear_progress(analysis_id)

    if int(others or 0) == 0:
        root = Path(get_settings().zeng_quarantine_dir).resolve()
        target = (root / storage_path).resolve()
        if target != root and root in target.parents:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{analysis_id}", response_model=AnalysisDetail)
async def get_analysis(
    analysis_id: UUID,
    session: AsyncSession = Depends(get_db),
) -> AnalysisDetail:
    row = await session.get(Analysis, analysis_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return _present_detail(row)


@router.get("", response_model=AnalysisListResponse)
async def list_analyses(
    session: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    sha256: Optional[str] = Query(None, min_length=64, max_length=64),
    status_filter: Optional[str] = Query(None, alias="status"),
) -> AnalysisListResponse:
    base = select(Analysis)
    count_stmt = select(func.count()).select_from(Analysis)

    if sha256 is not None:
        base = base.where(Analysis.sha256 == sha256.lower())
        count_stmt = count_stmt.where(Analysis.sha256 == sha256.lower())
    if status_filter is not None:
        base = base.where(Analysis.status == status_filter)
        count_stmt = count_stmt.where(Analysis.status == status_filter)

    total_result = await session.execute(count_stmt)
    total = int(total_result.scalar_one())

    stmt = (
        base.order_by(Analysis.created_at.desc()).offset(offset).limit(limit)
    )
    result = await session.execute(stmt)
    rows = result.scalars().all()

    return AnalysisListResponse(
        items=[_present_summary(r) for r in rows],
        limit=limit,
        offset=offset,
        total=total,
    )
