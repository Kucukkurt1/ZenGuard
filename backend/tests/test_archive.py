import io
import stat
import tarfile
import zipfile

import pytest

from app.core.config import get_settings
from app.engines.archive import (
    PolicyViolation,
    _Scope,
    _State,
    _stream,
    extract_archive,
    is_traversal,
)


@pytest.fixture(autouse=True)
def architecture_limits(monkeypatch):
    monkeypatch.setenv("ZENG_MAX_UNCOMPRESSED_BYTES", "104857600")
    monkeypatch.setenv("ZENG_MAX_ARCHIVE_FILES", "200")
    monkeypatch.setenv("ZENG_MAX_ARCHIVE_DEPTH", "3")
    monkeypatch.setenv("ZENG_ZIP_BOMB_RATIO", "1000")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def zip_bytes(files: dict[str, bytes], *, compressed: bool = False) -> bytes:
    buf = io.BytesIO()
    mode = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", compression=mode) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buf.getvalue()


def tar_bytes(files: dict[str, bytes], mode: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def seven_bytes(files: dict[str, bytes]) -> bytes:
    import py7zr

    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w") as archive:
        for name, data in files.items():
            archive.writestr(data, name)
    return buf.getvalue()


def member_map(result):
    return {member.path: member for member in result.members}


def test_traversal_names():
    assert is_traversal("../kacak.txt")
    assert is_traversal("foo/../../etc/passwd")
    assert is_traversal("/etc/passwd")
    assert is_traversal("\\windows\\system32\\x")
    assert is_traversal("C:/windows/x")
    assert is_traversal("C:foo")
    assert not is_traversal("dir/notes.txt")
    assert not is_traversal(".../notes.txt")


def test_formats_roundtrip(tmp_path):
    samples = {
        "zip": zip_bytes({"a.txt": b"hello-archive", "b.txt": b"second"}),
        "tar": tar_bytes({"a.txt": b"hello-archive", "b.txt": b"second"}, "w:"),
        "tar.gz": tar_bytes({"a.txt": b"hello-archive", "b.txt": b"second"}, "w:gz"),
        "tar.bz2": tar_bytes({"a.txt": b"hello-archive", "b.txt": b"second"}, "w:bz2"),
        "7z": seven_bytes({"a.txt": b"hello-archive", "b.txt": b"second"}),
    }
    for label, payload in samples.items():
        work = tmp_path / label
        result = extract_archive(payload, work)
        assert result.error_code is None, label
        assert result.coverage == "full", label
        found = member_map(result)
        assert set(found) == {"a.txt", "b.txt"}, label
        assert found["a.txt"].depth == 1
        assert found["a.txt"].disk_path.read_bytes() == b"hello-archive"
        assert found["b.txt"].disk_path.read_bytes() == b"second"


def test_depth_three_file_is_allowed(tmp_path):
    # a.zip → b.zip → c.zip → d.txt  (d.txt is depth 3)
    nested = zip_bytes({"b.zip": zip_bytes({"c.zip": zip_bytes({"d.txt": b"deep-ok"})})})
    work = tmp_path / "work"
    result = extract_archive(nested, work)
    assert result.error_code is None
    found = member_map(result)
    assert found["b.zip/c.zip/d.txt"].depth == 3
    assert found["b.zip/c.zip/d.txt"].disk_path.read_bytes() == b"deep-ok"
    assert not any(signal.signal_id == "nested_depth_max" for signal in result.signals)


def test_depth_four_is_rejected(tmp_path):
    # a.zip → b.zip → c.zip → d.zip → e.txt  (e.txt would be depth 4)
    nested = zip_bytes(
        {"b.zip": zip_bytes({"c.zip": zip_bytes({"d.zip": zip_bytes({"e.txt": b"too-deep"})})})}
    )
    work = tmp_path / "work"
    result = extract_archive(nested, work)
    assert result.error_code == "ARCHIVE_DEPTH"
    assert result.coverage == "none"
    assert result.members == []
    assert result.work_dir is None
    assert not work.exists()
    assert not (tmp_path / "e.txt").exists()


def test_empty_archive_at_depth_three_signals_nested(tmp_path):
    empty = zip_bytes({})
    nested = zip_bytes({"b.zip": zip_bytes({"c.zip": zip_bytes({"d.zip": empty})})})
    work = tmp_path / "work"
    result = extract_archive(nested, work)
    assert result.error_code is None
    assert result.coverage == "full"
    assert "b.zip/c.zip/d.zip" in member_map(result)
    assert member_map(result)["b.zip/c.zip/d.zip"].depth == 3
    assert any(signal.signal_id == "nested_depth_max" for signal in result.signals)


def test_member_201_is_rejected(tmp_path):
    payload = zip_bytes({f"f{i}.txt": b"x" for i in range(201)})
    work = tmp_path / "work"
    result = extract_archive(payload, work)
    assert result.error_code == "ARCHIVE_COUNT"
    assert result.coverage == "none"
    assert not work.exists()
    assert list(tmp_path.iterdir()) == []


def test_high_file_count_signal_below_the_cap(tmp_path):
    payload = zip_bytes({f"f{i}.txt": b"x" for i in range(101)})
    result = extract_archive(payload, tmp_path / "work")
    assert result.error_code is None
    assert len(result.members) == 101
    signal = next(item for item in result.signals if item.signal_id == "high_file_count")
    assert signal.points == 3
    assert signal.evidence["count"] == 101


@pytest.mark.parametrize(
    "name",
    ["../kacak.txt", "/etc/passwd", "C:/windows/kacak.txt", "foo/../../kacak.txt"],
)
def test_path_traversal_rejected(tmp_path, name):
    payload = zip_bytes({name: b"escape"})
    work = tmp_path / "work"
    result = extract_archive(payload, work)
    assert result.error_code == "PATH_TRAVERSAL"
    assert not work.exists()
    assert not (tmp_path / "kacak.txt").exists()
    assert not (tmp_path / "passwd").exists()


def test_zip_symlink_rejected(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = stat.S_IFLNK << 16
        archive.writestr(info, b"target")
    work = tmp_path / "work"
    result = extract_archive(buf.getvalue(), work)
    assert result.error_code == "UNSAFE_MEMBER"
    assert not work.exists()


def test_tar_symlink_rejected(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "target"
        archive.addfile(info)
    work = tmp_path / "work"
    result = extract_archive(buf.getvalue(), work)
    assert result.error_code == "UNSAFE_MEMBER"
    assert not work.exists()


def _ratio_of(payload: bytes) -> int:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        info = archive.infolist()[0]
        if info.compress_size <= 0:
            return 10**9
        return info.file_size // info.compress_size


def _compressed_zip(raw: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("pad.bin", raw)
    return buf.getvalue()


def test_zip_bomb_rejects_and_deletes_workdir(tmp_path):
    payload = None
    for size in (50_000, 100_000, 250_000, 500_000, 1_000_000):
        candidate = _compressed_zip(b"\x00" * size)
        if _ratio_of(candidate) >= 1000:
            payload = candidate
            break
    assert payload is not None
    work = tmp_path / "work"
    result = extract_archive(payload, work)
    assert result.error_code == "ZIP_BOMB"
    assert result.coverage == "none"
    assert result.members == []
    assert not work.exists()


def test_stream_stops_before_reading_the_rest(tmp_path):
    class Reader:
        def __init__(self):
            self.read_bytes = 0

        def read(self, size: int) -> bytes:
            if self.read_bytes >= 5_000_000:
                return b""
            self.read_bytes += size
            return b"\x00" * size

    reader = Reader()
    state = _State(104_857_600, 200, 3, 1000)
    scope = _Scope(compressed=100, shared=False)
    with pytest.raises(PolicyViolation) as caught:
        _stream(reader, tmp_path / "partial.bin", state, scope)
    assert caught.value.code == "ZIP_BOMB"
    assert reader.read_bytes < 1_000_000


def test_suspicious_ratio_continues(tmp_path):
    payload = None
    patterns = [b"\x00", bytes(range(32))]
    for pattern in patterns:
        for size in (2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000):
            raw = (pattern * ((size // len(pattern)) + 1))[:size]
            candidate = _compressed_zip(raw)
            ratio = _ratio_of(candidate)
            if 100 <= ratio < 1000:
                payload = candidate
                break
        if payload is not None:
            break
    assert payload is not None
    result = extract_archive(payload, tmp_path / "work")
    assert result.error_code is None
    assert result.coverage == "full"
    signal = next(item for item in result.signals if item.signal_id == "suspicious_ratio")
    assert signal.points == 6
    assert signal.member_path == "pad.bin"
    assert 100 <= signal.evidence["ratio"] < 1000
    assert result.work_dir is not None and result.work_dir.exists()


def test_size_limit_deletes_workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("ZENG_MAX_UNCOMPRESSED_BYTES", "1024")
    get_settings.cache_clear()
    payload = zip_bytes({"big.bin": b"A" * 4096})
    work = tmp_path / "work"
    result = extract_archive(payload, work)
    assert result.error_code == "SIZE_LIMIT"
    assert not work.exists()


def _flag_encrypted(payload: bytes) -> bytes:
    """Stdlib ZipFile cannot write the encryption bit; set it in both headers."""
    raw = bytearray(payload)
    assert raw[:4] == b"PK\x03\x04"
    raw[6] |= 0x1
    central = raw.find(b"PK\x01\x02")
    assert central > 0
    raw[central + 8] |= 0x1
    return bytes(raw)


def test_encrypted_zip_is_partial_and_not_extracted(tmp_path):
    payload = _flag_encrypted(zip_bytes({"secret.txt": b"top-secret-plain"}))
    work = tmp_path / "work"
    result = extract_archive(payload, work)
    assert result.error_code is None
    assert result.coverage == "partial"
    assert result.members == []
    signal = next(item for item in result.signals if item.signal_id == "encrypted_archive")
    assert signal.points == 5
    assert list(work.glob("*.bin")) == []
    assert not any(path.name == "secret.txt" for path in work.rglob("*"))


def test_extension_mismatch_on_text_named_zip(tmp_path):
    inner = zip_bytes({"inner.txt": b"inside"})
    payload = zip_bytes({"readme.txt": inner})
    result = extract_archive(payload, tmp_path / "work")
    assert result.error_code is None
    found = member_map(result)
    assert found["readme.txt/inner.txt"].depth == 2
    assert found["readme.txt/inner.txt"].disk_path.read_bytes() == b"inside"
    mismatch = [
        signal
        for signal in result.signals
        if signal.signal_id == "extension_mismatch" and signal.member_path == "readme.txt"
    ]
    assert len(mismatch) == 1
    assert mismatch[0].points == 3
    assert mismatch[0].evidence["magic"] == "zip"
