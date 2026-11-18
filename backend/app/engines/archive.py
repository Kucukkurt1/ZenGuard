import hashlib
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path

from app.core.config import get_settings
from app.engines.filetype import (
    detect_container,
    detect_container_path,
    extension_family,
    magic_family,
    mime_type,
)
from app.engines.types import ArchiveResult, Member, Signal

CHUNK = 64 * 1024
SUSPICIOUS_RATIO = 100

SIGNAL_POINTS = {
    "encrypted_archive": 5,
    "extension_mismatch": 3,
    "nested_depth_max": 4,
    "high_file_count": 3,
    "suspicious_ratio": 6,
}


class PolicyViolation(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class ArchiveReadError(Exception):
    error_code = "archive_read_error"


def is_traversal(name: str) -> bool:
    if not name:
        return False
    if name.startswith("/") or name.startswith("\\"):
        return True
    if len(name) >= 2 and name[0].isalpha() and name[1] == ":":
        return True
    parts = name.replace("\\", "/").split("/")
    return any(part == ".." for part in parts)


def _is_bomb(written: int, compressed: int, bomb_ratio: int) -> bool:
    if written <= 0:
        return False
    if compressed <= 0:
        return True
    return written >= bomb_ratio * compressed


def _is_suspicious(written: int, compressed: int, bomb_ratio: int) -> bool:
    if written <= 0 or compressed <= 0:
        return False
    if _is_bomb(written, compressed, bomb_ratio):
        return False
    return written >= SUSPICIOUS_RATIO * compressed


class _Scope:
    def __init__(self, compressed: int | None, shared: bool):
        self.compressed = compressed
        self.shared = shared
        self.written = 0


class _State:
    def __init__(self, max_bytes: int, max_files: int, max_depth: int, bomb_ratio: int):
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.max_depth = max_depth
        self.bomb_ratio = bomb_ratio
        self.total_written = 0
        self.file_count = 0
        self.index = 0
        self.partial = False
        self.members: list[Member] = []
        self.signals: list[Signal] = []
        self.encrypted_paths: list[str] = []
        self.nested_paths: list[str] = []
        self._seen: set[tuple] = set()

    def add(self, signal: Signal, key: tuple) -> None:
        if key in self._seen:
            return
        self._seen.add(key)
        self.signals.append(signal)

    def note_encrypted(self, path: str) -> None:
        self.partial = True
        if path not in self.encrypted_paths:
            self.encrypted_paths.append(path)

    def note_nested(self, path: str) -> None:
        if path not in self.nested_paths:
            self.nested_paths.append(path)

    def finish(self) -> None:
        if self.encrypted_paths:
            self.add(
                Signal(
                    "encrypted_archive",
                    SIGNAL_POINTS["encrypted_archive"],
                    self.encrypted_paths[0],
                    {"paths": list(self.encrypted_paths)},
                ),
                ("encrypted_archive",),
            )
        if self.nested_paths:
            self.add(
                Signal(
                    "nested_depth_max",
                    SIGNAL_POINTS["nested_depth_max"],
                    self.nested_paths[0],
                    {"paths": list(self.nested_paths)},
                ),
                ("nested_depth_max",),
            )
        if 100 < self.file_count <= self.max_files:
            self.add(
                Signal(
                    "high_file_count",
                    SIGNAL_POINTS["high_file_count"],
                    None,
                    {"count": self.file_count},
                ),
                ("high_file_count",),
            )


def _join(prefix: str, name: str) -> str:
    cleaned = name.replace("\\", "/").strip("/")
    if not prefix:
        return cleaned
    if not cleaned:
        return prefix
    return f"{prefix}/{cleaned}"


def _stream(src, dest: Path, state: _State, scope: _Scope) -> tuple[int, str]:
    digest = hashlib.sha256()
    written = 0
    with dest.open("wb") as out:
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            if state.total_written + len(chunk) > state.max_bytes:
                raise PolicyViolation("SIZE_LIMIT")
            projected = scope.written + len(chunk)
            if scope.compressed is not None and _is_bomb(projected, scope.compressed, state.bomb_ratio):
                raise PolicyViolation("ZIP_BOMB")
            out.write(chunk)
            digest.update(chunk)
            written += len(chunk)
            state.total_written += len(chunk)
            scope.written += len(chunk)
    return written, digest.hexdigest()


def _note_member_ratio(state: _State, scope: _Scope, path: str) -> None:
    if scope.shared or scope.compressed is None:
        return
    if _is_suspicious(scope.written, scope.compressed, state.bomb_ratio):
        state.add(
            Signal(
                "suspicious_ratio",
                SIGNAL_POINTS["suspicious_ratio"],
                path,
                {
                    "written": scope.written,
                    "compressed": scope.compressed,
                    "ratio": scope.written // scope.compressed,
                },
            ),
            ("suspicious_ratio", path),
        )


def _note_shared_ratio(state: _State, scope: _Scope, path: str) -> None:
    if not scope.shared or scope.compressed is None:
        return
    if _is_suspicious(scope.written, scope.compressed, state.bomb_ratio):
        state.add(
            Signal(
                "suspicious_ratio",
                SIGNAL_POINTS["suspicious_ratio"],
                path or ".",
                {
                    "written": scope.written,
                    "compressed": scope.compressed,
                    "ratio": scope.written // scope.compressed,
                },
            ),
            ("suspicious_ratio", path or "."),
        )


def _zip_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def _zip_encrypted(path: Path) -> bool:
    with zipfile.ZipFile(path) as archive:
        return any(info.flag_bits & 0x1 for info in archive.infolist())


def _seven_encrypted(path: Path) -> bool:
    import py7zr

    try:
        with py7zr.SevenZipFile(path, mode="r") as archive:
            return bool(archive.needs_password())
    except py7zr.PasswordRequired:
        return True


def _encrypted(path: Path, kind: str) -> bool:
    if kind == "zip":
        return _zip_encrypted(path)
    if kind == "7z":
        return _seven_encrypted(path)
    return False


def _peek(path: Path, kind: str) -> str | None:
    """Central-directory check for an archive that must not be expanded.

    Empty container → None (caller records nested_depth_max).
    Encrypted → ``encrypted``.
    Symlink, traversal, or any file that would land at depth 4 → policy code.
    """
    if kind == "zip":
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if any(info.flag_bits & 0x1 for info in infos):
                return "encrypted"
            saw_file = False
            for info in infos:
                if _zip_symlink(info):
                    return "UNSAFE_MEMBER"
                if is_traversal(info.filename):
                    return "PATH_TRAVERSAL"
                if not info.is_dir():
                    saw_file = True
            return "ARCHIVE_DEPTH" if saw_file else None
    if kind == "7z":
        import py7zr

        try:
            with py7zr.SevenZipFile(path, mode="r") as archive:
                if archive.needs_password():
                    return "encrypted"
                for item in archive.files:
                    if item.is_symlink or item.is_junction:
                        return "UNSAFE_MEMBER"
                    if is_traversal(item.filename):
                        return "PATH_TRAVERSAL"
                saw_file = any(not info.is_directory for info in archive.list())
                return "ARCHIVE_DEPTH" if saw_file else None
        except py7zr.PasswordRequired:
            return "encrypted"
    saw_file = False
    with tarfile.open(path, mode="r:*") as archive:
        for info in archive.getmembers():
            if info.issym():
                return "UNSAFE_MEMBER"
            if is_traversal(info.name):
                return "PATH_TRAVERSAL"
            if info.isfile():
                saw_file = True
    return "ARCHIVE_DEPTH" if saw_file else None


def _hold_at_max_depth(path: Path, kind: str, logical: str, state: _State) -> None:
    peeked = _peek(path, kind)
    if peeked == "encrypted":
        state.note_encrypted(logical)
        state.note_nested(logical)
        return
    if peeked is None:
        state.note_nested(logical)
        return
    raise PolicyViolation(peeked)


def _remember_member(
    state: _State,
    dest: Path,
    logical: str,
    child_depth: int,
    size: int,
    digest: str,
    head: bytes,
) -> None:
    ext_fam = extension_family(logical)
    mag = magic_family(head)
    if ext_fam and mag and ext_fam != mag:
        state.add(
            Signal(
                "extension_mismatch",
                SIGNAL_POINTS["extension_mismatch"],
                logical,
                {"extension": ext_fam, "magic": mag},
            ),
            ("extension_mismatch", logical),
        )
    state.members.append(
        Member(
            path=logical,
            sha256=digest,
            size_bytes=size,
            depth=child_depth,
            mime_type=mime_type(head),
            disk_path=dest,
        )
    )


def _take_file(
    state: _State,
    src,
    logical: str,
    child_depth: int,
    scope: _Scope,
    work_dir: Path,
) -> None:
    if child_depth > state.max_depth:
        raise PolicyViolation("ARCHIVE_DEPTH")
    if state.file_count >= state.max_files:
        raise PolicyViolation("ARCHIVE_COUNT")
    state.index += 1
    dest = work_dir / f"{state.index:05d}.bin"
    size, digest = _stream(src, dest, state, scope)
    state.file_count += 1
    with dest.open("rb") as handle:
        head = handle.read(512)
    _note_member_ratio(state, scope, logical)
    _remember_member(state, dest, logical, child_depth, size, digest, head)
    kind = detect_container_path(dest)
    if not kind:
        return
    if child_depth >= state.max_depth:
        _hold_at_max_depth(dest, kind, logical, state)
        return
    if _encrypted(dest, kind):
        state.note_encrypted(logical)
        return
    _walk_path(dest, kind, child_depth, logical, state, work_dir)


def _walk_zip(path: Path, archive_depth: int, prefix: str, state: _State, work_dir: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if any(info.flag_bits & 0x1 for info in infos):
            state.note_encrypted(prefix or ".")
            return
        for info in infos:
            if _zip_symlink(info):
                raise PolicyViolation("UNSAFE_MEMBER")
            if is_traversal(info.filename):
                raise PolicyViolation("PATH_TRAVERSAL")
            if info.is_dir():
                continue
            logical = _join(prefix, info.filename)
            child_depth = archive_depth + 1
            compressed = None if (info.flag_bits & 0x8 and info.compress_size == 0) else info.compress_size
            scope = _Scope(compressed, shared=False)
            with archive.open(info, "r") as src:
                _take_file(state, src, logical, child_depth, scope, work_dir)


def _walk_tar(path: Path, archive_depth: int, prefix: str, state: _State, work_dir: Path) -> None:
    scope = _Scope(path.stat().st_size, shared=True)
    with tarfile.open(path, mode="r:*") as archive:
        for info in archive.getmembers():
            if is_traversal(info.name):
                raise PolicyViolation("PATH_TRAVERSAL")
            if info.issym():
                raise PolicyViolation("UNSAFE_MEMBER")
            if info.isdir() or info.islnk():
                continue
            if not info.isfile():
                raise PolicyViolation("UNSAFE_MEMBER")
            logical = _join(prefix, info.name)
            child_depth = archive_depth + 1
            extracted = archive.extractfile(info)
            if extracted is None:
                continue
            with extracted:
                _take_file(state, extracted, logical, child_depth, scope, work_dir)
    _note_shared_ratio(state, scope, prefix or ".")


def _walk_7z(path: Path, archive_depth: int, prefix: str, state: _State, work_dir: Path) -> None:
    import py7zr

    shared = _Scope(path.stat().st_size, shared=True)
    try:
        archive = py7zr.SevenZipFile(path, mode="r")
    except py7zr.PasswordRequired:
        state.note_encrypted(prefix or ".")
        return
    with archive:
        if archive.needs_password():
            state.note_encrypted(prefix or ".")
            return
        for item in archive.files:
            if item.is_symlink or item.is_junction:
                raise PolicyViolation("UNSAFE_MEMBER")
            if is_traversal(item.filename):
                raise PolicyViolation("PATH_TRAVERSAL")
        for info in archive.list():
            if info.is_directory:
                continue
            if is_traversal(info.filename):
                raise PolicyViolation("PATH_TRAVERSAL")
            logical = _join(prefix, info.filename)
            child_depth = archive_depth + 1
            streams = archive.read(targets=[info.filename]) or {}
            src = streams.get(info.filename)
            if src is None:
                continue
            per_member = info.compressed if isinstance(info.compressed, int) and info.compressed > 0 else None
            scope = _Scope(per_member, shared=False) if per_member is not None else shared
            with src:
                _take_file(state, src, logical, child_depth, scope, work_dir)
            archive.reset()
    if shared.written:
        _note_shared_ratio(state, shared, prefix or ".")


def _walk_path(path: Path, kind: str, archive_depth: int, prefix: str, state: _State, work_dir: Path) -> None:
    if archive_depth >= state.max_depth:
        raise PolicyViolation("ARCHIVE_DEPTH")
    if kind == "zip":
        _walk_zip(path, archive_depth, prefix, state, work_dir)
    elif kind == "7z":
        _walk_7z(path, archive_depth, prefix, state, work_dir)
    elif kind == "tar":
        _walk_tar(path, archive_depth, prefix, state, work_dir)
    else:
        raise ArchiveReadError(f"unsupported archive: {kind}")


def extract_archive(data: bytes, work_dir: Path) -> ArchiveResult:
    """Extract zip, tar, tar.gz, tar.bz2, and 7z under the architecture limits.

    Depth 0 is this container. Members are written only up to depth 3.
    A non-empty archive at depth 3 is ``ARCHIVE_DEPTH`` (its children would be
    depth 4). An empty archive left closed at depth 3 records ``nested_depth_max``.
    Limit breaches delete ``work_dir`` and return the policy code.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    kind = detect_container(data)
    if kind is None:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise ArchiveReadError("not a supported archive")
    settings = get_settings()
    state = _State(
        settings.zeng_max_uncompressed_bytes,
        settings.zeng_max_archive_files,
        settings.zeng_max_archive_depth,
        settings.zeng_zip_bomb_ratio,
    )
    source = work_dir / ".source"
    try:
        source.write_bytes(data)
        _walk_path(source, kind, 0, "", state, work_dir)
        state.finish()
    except PolicyViolation as exc:
        shutil.rmtree(work_dir, ignore_errors=True)
        return ArchiveResult("rejected", exc.code, "none", [], [], None)
    except Exception:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise
    coverage = "partial" if state.partial else "full"
    return ArchiveResult("ok", None, coverage, state.members, state.signals, work_dir)
