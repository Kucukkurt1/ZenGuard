import hashlib
import copy
import tempfile
from pathlib import Path

from app.engines import archive, clamav, static, yara_scan
from app.engines.filetype import detect_container, mime_type
from app.engines.types import ClamHit, Member, ScanResult, Signal

_SKIPPED = {
    "clamav": {"status": "skipped", "classification": None, "signature": None, "hits": []},
    "yara": {"status": "skipped", "ruleset_version": None, "matches": []},
    "static": {"status": "skipped", "signals": []},
}


def _basename(filename: str) -> str:
    base = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    return (base or "upload.bin")[:255]


def _signal_dict(signal: Signal) -> dict:
    return {
        "signal_id": signal.signal_id,
        "points": signal.points,
        "member_path": signal.member_path,
        "evidence": signal.evidence,
    }


def _aggregate_clam(hits: list[ClamHit]) -> tuple[str, str | None]:
    malware = next((hit for hit in hits if hit.classification == "malware"), None)
    if malware is not None:
        return "malware", malware.signature
    pua = next((hit for hit in hits if hit.classification == "pua"), None)
    if pua is not None:
        return "pua", pua.signature
    return "clean", None


def scan_tree(members: list[Member], on_progress=None) -> dict:
    """Run ClamAV, then YARA, then static on each member.

    A ClamAV or YARA failure aborts the scan. A static failure on one member
    records ``static_error`` (0 points) and the walk continues.
    """
    clam_hits: list[ClamHit] = []
    yara_matches: list[dict] = []
    static_signals: list[dict] = []
    static_failed = False
    version = yara_scan.ruleset_version()
    total = len(members) or 1

    for index, member in enumerate(members):
        start = 40 + int(52 * index / total)
        end = 40 + int(52 * (index + 1) / total)

        def step(offset: int, label: str) -> None:
            if on_progress is not None:
                on_progress(min(94, start + offset), label)

        step(0, f"ClamAV · {member.path}")
        payload = member.read_bytes()
        clam = clamav.scan_bytes(payload)
        clam_hits.append(
            ClamHit(clam.classification, clam.signature, member.path)
        )
        step(max(1, (end - start) // 3), f"YARA · {member.path}")
        for hit in yara_scan.scan_bytes(payload, member.path):
            yara_matches.append(
                {"rule": hit.rule, "severity": hit.severity, "member_path": member.path}
            )
        step(max(2, (end - start) * 2 // 3), f"Statik · {member.path}")
        try:
            for signal in static.analyze(payload, member.path):
                static_signals.append(_signal_dict(signal))
        except Exception as exc:
            static_failed = True
            static_signals.append(
                {
                    "signal_id": "static_error",
                    "points": 0,
                    "member_path": member.path,
                    "evidence": {"error": f"{type(exc).__name__}: {exc}"[:200]},
                }
            )

    classification, signature = _aggregate_clam(clam_hits)
    return {
        "ruleset_version": version,
        "static_failed": static_failed,
        "clamav": {
            "status": "ok",
            "classification": classification,
            "signature": signature,
            "hits": [
                {
                    "member_path": hit.member_path,
                    "classification": hit.classification,
                    "signature": hit.signature,
                }
                for hit in clam_hits
            ],
        },
        "yara": {
            "status": "ok",
            "ruleset_version": version,
            "matches": yara_matches,
        },
        "static": {
            "status": "partial" if static_failed else "ok",
            "signals": static_signals,
        },
    }


def scan_bytes(payload: bytes, *, filename: str = "upload.bin", on_progress=None) -> ScanResult:
    """Hash-free orchestration for one uploaded blob.

    Archives are extracted in this process (``ZENG_SANDBOX_MODE=inprocess`` in
    unit tests). Policy rejections skip every engine. The root object is depth 0.
    """
    if on_progress is not None:
        on_progress(15, "Dosya hazırlanıyor")
    name = _basename(filename)
    root = Member(
        path=name,
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        depth=0,
        mime_type=mime_type(payload),
        data=payload,
    )
    kind = detect_container(payload)
    if kind is None:
        if on_progress is not None:
            on_progress(35, "Tek dosya taranıyor")
        tree = scan_tree([root], on_progress=on_progress)
        return _result(root_members=[root], archive_status="skipped", archive_signals=[], archive_error=None, archive_coverage="full", tree=tree)

    with tempfile.TemporaryDirectory(prefix="zg-scan-") as parent:
        if on_progress is not None:
            on_progress(28, "Arşiv açılıyor")
        extracted = archive.extract_archive(payload, Path(parent) / "work")
        if extracted.status == "rejected":
            if on_progress is not None:
                on_progress(100, "Politika reddi")
            return ScanResult(
                coverage="none",
                error_code=extracted.error_code,
                ruleset_version=None,
                members=[],
                engines={
                    "archive": {
                        "status": "rejected",
                        "error_code": extracted.error_code,
                        "signals": [],
                    },
                    **copy.deepcopy(_SKIPPED),
                },
            )
        for member in extracted.members:
            member.data = member.read_bytes()
            member.disk_path = None
        members = [root, *extracted.members]
        if on_progress is not None:
            on_progress(40, "Üyeler taranıyor")
        tree = scan_tree(members, on_progress=on_progress)
        return _result(
            root_members=members,
            archive_status="ok",
            archive_signals=extracted.signals,
            archive_error=None,
            archive_coverage=extracted.coverage,
            tree=tree,
        )


def _result(
    root_members: list[Member],
    archive_status: str,
    archive_signals: list[Signal],
    archive_error: str | None,
    archive_coverage: str,
    tree: dict,
) -> ScanResult:
    coverage = archive_coverage
    if tree.get("static_failed"):
        coverage = "partial"
    return ScanResult(
        coverage=coverage,
        error_code=archive_error,
        ruleset_version=tree.get("ruleset_version"),
        members=[member.as_dict() for member in root_members],
        engines={
            "archive": {
                "status": archive_status,
                "error_code": archive_error,
                "signals": [_signal_dict(signal) for signal in archive_signals],
            },
            "clamav": tree["clamav"],
            "yara": tree["yara"],
            "static": tree["static"],
        },
    )
