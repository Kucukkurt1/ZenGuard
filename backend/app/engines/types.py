from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Signal:
    signal_id: str
    points: int
    member_path: str | None = None
    evidence: dict = field(default_factory=dict)


@dataclass
class Member:
    path: str
    sha256: str
    size_bytes: int
    depth: int
    mime_type: str
    disk_path: Path | None = None
    data: bytes | None = None

    def read_bytes(self) -> bytes:
        if self.data is not None:
            return self.data
        if self.disk_path is None:
            return b""
        return self.disk_path.read_bytes()

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "depth": self.depth,
            "mime_type": self.mime_type,
        }


@dataclass
class ArchiveResult:
    status: str
    error_code: str | None
    coverage: str
    members: list[Member]
    signals: list[Signal]
    work_dir: Path | None


@dataclass(frozen=True)
class ClamHit:
    classification: str
    signature: str | None = None
    member_path: str | None = None


@dataclass(frozen=True)
class YaraHit:
    rule: str
    severity: str
    member_path: str | None = None


@dataclass
class ScanResult:
    coverage: str
    error_code: str | None
    ruleset_version: str | None
    members: list[dict]
    engines: dict
