import threading
from pathlib import Path
from uuid import UUID

from app.core.config import get_settings
from app.db.models import Analysis, utc_now
from app.db.session import SyncSessionLocal
from app.engines.clamav import ClamavError
from app.engines.scan import scan_bytes
from app.engines.yara_scan import YaraError
from app.services.progress import clear_progress, set_progress
from app.services.scoring import POLICY_CODES, build_report

_LOCK = threading.Lock()
_INFLIGHT: set[str] = set()

_POLICY_MESSAGE = {
    "ZIP_BOMB": "Sıkıştırma oranı sınırı aşıldı.",
    "SIZE_LIMIT": "Açılmış boyut sınırı aşıldı.",
    "ARCHIVE_COUNT": "Üye sayısı sınırı aşıldı.",
    "ARCHIVE_DEPTH": "Arşiv derinliği sınırı aşıldı.",
    "PATH_TRAVERSAL": "Üye yolu dışarı kaçıyor.",
    "UNSAFE_MEMBER": "Arşivde sembolik bağ var.",
}


def execute_analysis(analysis_id: UUID) -> None:
    """Run one queued sample in this process and write the terminal row."""
    key = str(analysis_id)
    with _LOCK:
        if key in _INFLIGHT:
            return
        _INFLIGHT.add(key)
    try:
        _execute(analysis_id)
    finally:
        with _LOCK:
            _INFLIGHT.discard(key)


def _execute(analysis_id: UUID) -> None:
    filename, storage_path = _mark_running(analysis_id)
    if filename is None or storage_path is None:
        return
    set_progress(analysis_id, 12, "Dosya okunuyor")
    path = Path(get_settings().zeng_quarantine_dir) / storage_path
    try:
        payload = path.read_bytes()
    except OSError as exc:
        _fail(analysis_id, "storage_missing", f"Karantina dosyası okunamadı: {exc}"[:300])
        return

    def on_progress(percent: int, stage: str) -> None:
        set_progress(analysis_id, percent, stage)

    try:
        result = scan_bytes(payload, filename=filename, on_progress=on_progress)
    except ClamavError as exc:
        _fail(analysis_id, exc.error_code, "ClamAV taraması tamamlanamadı.")
        return
    except YaraError as exc:
        _fail(analysis_id, exc.error_code, "YARA taraması tamamlanamadı.")
        return
    except Exception as exc:
        _fail(analysis_id, "engine_error", f"Tarama tamamlanamadı: {exc}"[:300])
        return

    set_progress(analysis_id, 96, "Skor yazılıyor")
    _finish(analysis_id, result)
    if result.error_code in POLICY_CODES:
        set_progress(analysis_id, 100, "Politika reddi")
    else:
        set_progress(analysis_id, 100, "Tamamlandı")


def _mark_running(analysis_id: UUID) -> tuple[str | None, str | None]:
    with SyncSessionLocal() as session:
        row = session.get(Analysis, analysis_id)
        if row is None or row.status != "queued":
            return None, None
        row.status = "running"
        row.started_at = utc_now()
        row.updated_at = utc_now()
        row.error_code = None
        row.error_message = None
        filename = row.original_filename
        storage_path = row.storage_path
        session.commit()
        return filename, storage_path


def _finish(analysis_id: UUID, result) -> None:
    report = build_report(result)
    score = report["score"]
    with SyncSessionLocal() as session:
        row = session.get(Analysis, analysis_id)
        if row is None or row.status != "running":
            return
        row.updated_at = utc_now()
        row.finished_at = utc_now()
        row.report = report
        row.ruleset_version = result.ruleset_version
        row.coverage = report["coverage"]
        if result.error_code in POLICY_CODES:
            row.status = "rejected"
            row.risk_score = 100
            row.risk_band = "critical"
            row.coverage = "none"
            row.error_code = result.error_code
            row.error_message = _POLICY_MESSAGE.get(result.error_code, result.error_code)
        else:
            row.status = "completed"
            row.risk_score = score["value"]
            row.risk_band = score["band"]
            row.error_code = None
            row.error_message = None
        session.commit()


def _fail(analysis_id: UUID, code: str, message: str) -> None:
    clear_progress(analysis_id)
    set_progress(analysis_id, 100, "Tarama başarısız")
    with SyncSessionLocal() as session:
        row = session.get(Analysis, analysis_id)
        if row is None or row.status not in {"queued", "running"}:
            return
        row.status = "failed"
        row.risk_score = None
        row.risk_band = None
        row.coverage = "none"
        row.report = None
        row.error_code = code
        row.error_message = message
        row.finished_at = utc_now()
        row.updated_at = utc_now()
        session.commit()
