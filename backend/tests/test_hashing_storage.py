import io
from pathlib import Path

import pytest

from app.services.hashing import sha256_hex_stream
from app.services.storage import UploadTooLargeError, save_upload_streaming
from fastapi import UploadFile


KNOWN_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


def test_sha256_empty_stream():
    stream = io.BytesIO(b"")
    assert sha256_hex_stream(stream) == KNOWN_SHA256


def test_sha256_known_payload():
    import hashlib

    data = b"ZenGuard test payload"
    stream = io.BytesIO(data)
    expected = hashlib.sha256(data).hexdigest()
    assert sha256_hex_stream(stream) == expected


@pytest.mark.asyncio
async def test_upload_too_large_removed(tmp_path, monkeypatch):
    monkeypatch.setenv("ZENG_QUARANTINE_DIR", str(tmp_path))
    monkeypatch.setenv("ZENG_MAX_UPLOAD_BYTES", "8")
    monkeypatch.setenv("POSTGRES_USER", "u")
    monkeypatch.setenv("POSTGRES_PASSWORD", "p")
    monkeypatch.setenv("POSTGRES_DB", "d")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/d"
    )
    monkeypatch.setenv(
        "DATABASE_URL_SYNC", "postgresql+psycopg://u:p@localhost:5432/d"
    )
    monkeypatch.setenv("REDIS_URL", "redis://:x@localhost:6379/0")
    monkeypatch.setenv("CLAMAV_SOCKET", "/run/clamav/clamd.sock")
    monkeypatch.setenv("CLAMAV_TCP_ADDR", "clamav:3310")

    from app.core.config import get_settings

    get_settings.cache_clear()

    big = b"x" * 16
    upload = UploadFile(filename="big.bin", file=io.BytesIO(big))

    with pytest.raises(UploadTooLargeError):
        await save_upload_streaming(upload)

    partial_dir = tmp_path / ".partial"
    assert not list(partial_dir.glob("*.part")) if partial_dir.exists() else True

    get_settings.cache_clear()
