import os
import shutil
from pathlib import Path
from typing import BinaryIO, Tuple

from fastapi import UploadFile

from app.core.config import get_settings
from app.services.hashing import sha256_hex_stream


class UploadTooLargeError(Exception):
    """Raised when streamed upload exceeds configured max bytes."""


def sanitize_filename(filename: str | None) -> str:
    if not filename:
        return "upload.bin"
    base = os.path.basename(filename.replace("\\", "/"))
    return base[:255] if base else "upload.bin"


def quarantine_relative_path(sha256_hex: str) -> str:
    return f"{sha256_hex[:2]}/{sha256_hex}"


def quarantine_absolute_path(sha256_hex: str) -> Path:
    settings = get_settings()
    root = Path(settings.zeng_quarantine_dir)
    return root / quarantine_relative_path(sha256_hex)


def detect_mime_type(path: Path) -> str:
    try:
        import magic

        mime = magic.from_file(str(path), mime=True)
        if mime:
            return mime
    except Exception:
        pass
    return "application/octet-stream"


async def save_upload_streaming(
    upload: UploadFile,
) -> Tuple[str, int, str, str]:
    """
    Stream upload to quarantine while hashing.
    Returns (sha256, size_bytes, storage_path_relative, mime_type).
    Deletes partial file on size limit breach.
    """
    settings = get_settings()
    max_bytes = settings.zeng_max_upload_bytes
    root = Path(settings.zeng_quarantine_dir)
    root.mkdir(parents=True, exist_ok=True)

    temp_path = root / ".partial" / f"upload-{os.getpid()}.part"
    temp_path.parent.mkdir(parents=True, exist_ok=True)

    size = 0
    digest = __import__("hashlib").sha256()

    try:
        with temp_path.open("wb") as out:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise UploadTooLargeError()
                digest.update(chunk)
                out.write(chunk)
    except Exception:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise

    sha256 = digest.hexdigest()
    final_path = quarantine_absolute_path(sha256)
    final_path.parent.mkdir(parents=True, exist_ok=True)

    if final_path.exists():
        temp_path.unlink(missing_ok=True)
    else:
        temp_path.replace(final_path)

    mime_type = detect_mime_type(final_path)
    rel = quarantine_relative_path(sha256)
    return sha256, size, rel, mime_type


def remove_partial_at(path: Path) -> None:
    if path.exists():
        path.unlink(missing_ok=True)
        parent = path.parent
        if parent.exists() and not any(parent.iterdir()):
            shutil.rmtree(parent, ignore_errors=True)
