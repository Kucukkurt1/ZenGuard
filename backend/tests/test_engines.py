import os
import struct

import pytest

from app.core.config import get_settings
from app.engines import clamav, static, yara_scan
from app.engines.clamav import ClamavError, classify_response
from app.engines.scan import scan_bytes, scan_tree
from app.engines.types import ClamHit, Member
from app.engines.yara_scan import YaraError

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
CLEAN = b"Merhaba, bu yalnizca duz bir nottur.\n"
MARKER = b"ZENG_BENIGN_STATIC_MARKER"


def test_sandbox_mode_is_inprocess():
    get_settings.cache_clear()
    assert get_settings().zeng_sandbox_mode == "inprocess"


def test_eicar_length_is_the_standard_string():
    assert len(EICAR) == 68


def test_yara_eicar_is_critical_and_clean_text_is_empty():
    hits = yara_scan.scan_bytes(EICAR, "eicar.com")
    matched = [hit for hit in hits if hit.rule == "eicar"]
    assert len(matched) == 1
    assert matched[0].severity == "critical"
    assert yara_scan.scan_bytes(CLEAN, "note.txt") == []


def test_yara_medium_marker_is_recorded_once():
    blob = MARKER + b"\n" + MARKER
    hits = yara_scan.scan_bytes(blob, "marker.txt")
    rules = [hit.rule for hit in hits]
    assert rules.count("benign_static_marker") == 1
    assert hits[0].severity == "medium"


def test_ruleset_version_is_stable_sha256():
    first = yara_scan.ruleset_version()
    second = yara_scan.ruleset_version()
    assert first == second
    assert len(first) == 64
    int(first, 16)


@pytest.mark.parametrize(
    ("raw", "kind", "signature"),
    [
        ("stream: OK", "clean", None),
        ("stream: PUA.Win.Trojan.Example FOUND", "pua", "PUA.Win.Trojan.Example"),
        ("stream: Heuristics.Encrypted.Zip FOUND", "pua", "Heuristics.Encrypted.Zip"),
        ("stream: Win.Test.EICAR_HDB-1 FOUND", "malware", "Win.Test.EICAR_HDB-1"),
    ],
)
def test_clamav_response_classes(raw, kind, signature):
    hit = classify_response(raw)
    assert hit.classification == kind
    assert hit.signature == signature


def test_clamav_error_response_raises():
    with pytest.raises(ClamavError):
        classify_response("INSTREAM size limit exceeded. ERROR")


def test_eicar_and_clean_text_scan():
    yara_hits = yara_scan.scan_bytes(EICAR, "eicar.com")
    assert any(hit.rule == "eicar" and hit.severity == "critical" for hit in yara_hits)
    assert static.analyze(CLEAN, "note.txt") == []
    assert yara_scan.scan_bytes(CLEAN, "note.txt") == []
    if not clamav.channel_available():
        pytest.skip("ClamAV socket/TCP is not reachable")
    infected = scan_bytes(EICAR, filename="eicar.com")
    assert infected.error_code is None
    assert infected.coverage == "full"
    assert infected.engines["clamav"]["classification"] == "malware"
    assert infected.engines["clamav"]["signature"]
    assert any(
        match["rule"] == "eicar" and match["severity"] == "critical"
        for match in infected.engines["yara"]["matches"]
    )
    assert infected.engines["static"]["signals"] == []
    clean = scan_bytes(CLEAN, filename="note.txt")
    assert clean.engines["clamav"]["classification"] == "clean"
    assert clean.engines["clamav"]["signature"] is None
    assert clean.engines["yara"]["matches"] == []
    assert clean.engines["static"]["signals"] == []
    assert clean.engines["archive"]["status"] == "skipped"
    assert clean.engines["archive"]["signals"] == []
    assert clean.members[0]["depth"] == 0


def test_clamav_failure_raises(monkeypatch):
    def boom(_data: bytes):
        raise ClamavError("down")

    monkeypatch.setattr(clamav, "scan_bytes", boom)
    with pytest.raises(ClamavError):
        scan_bytes(CLEAN, filename="note.txt")


def test_yara_failure_raises(monkeypatch):
    monkeypatch.setattr(clamav, "scan_bytes", lambda _data: ClamHit("clean", None))

    def boom(_data: bytes, member_path: str | None = None):
        raise YaraError("rules failed")

    monkeypatch.setattr(yara_scan, "scan_bytes", boom)
    with pytest.raises(YaraError):
        scan_bytes(CLEAN, filename="note.txt")


def test_static_error_continues_and_marks_partial(monkeypatch):
    monkeypatch.setattr(clamav, "scan_bytes", lambda _data: ClamHit("clean", None))
    real_analyze = static.analyze

    def wrapped(data: bytes, member_path: str):
        if member_path.endswith("bad.bin"):
            raise RuntimeError("parse failed")
        return real_analyze(data, member_path)

    monkeypatch.setattr(static, "analyze", wrapped)
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("ok.txt", b"hello")
        archive.writestr("bad.bin", b"xxxx")
    result = scan_bytes(buf.getvalue(), filename="bundle.zip")
    assert result.coverage == "partial"
    assert result.error_code is None
    signals = result.engines["static"]["signals"]
    assert any(
        item["signal_id"] == "static_error"
        and item["points"] == 0
        and item["member_path"] == "bad.bin"
        for item in signals
    )
    assert not any(
        item["signal_id"] == "static_error" and item["member_path"] == "ok.txt"
        for item in signals
    )
    assert any(member["path"] == "ok.txt" for member in result.members)
    assert "secret" not in {member["path"] for member in result.members}


def test_archive_rejection_does_not_call_engines(monkeypatch, tmp_path):
    called = []

    def boom(_data: bytes):
        called.append(1)
        return ClamHit("clean", None)

    monkeypatch.setattr(clamav, "scan_bytes", boom)
    payload = _bomb_zip()
    result = scan_bytes(payload, filename="bomb.zip")
    assert result.error_code == "ZIP_BOMB"
    assert result.coverage == "none"
    assert result.members == []
    assert result.engines["clamav"]["status"] == "skipped"
    assert result.engines["yara"]["status"] == "skipped"
    assert result.engines["static"]["status"] == "skipped"
    assert called == []
    assert list(tmp_path.iterdir()) == []


def test_pua_and_malware_aggregate(monkeypatch):
    monkeypatch.setattr(yara_scan, "ruleset_version", lambda: "abc")
    monkeypatch.setattr(yara_scan, "scan_bytes", lambda _data, member_path=None: [])
    monkeypatch.setattr(static, "analyze", lambda _data, _path: [])
    sequence = iter(
        [ClamHit("pua", "PUA.Example"), ClamHit("clean", None)]
    )
    monkeypatch.setattr(clamav, "scan_bytes", lambda _data: next(sequence))
    pua_only = scan_tree(
        [
            Member("a.bin", "aa", 1, 0, "application/octet-stream", data=b"a"),
            Member("b.bin", "bb", 1, 0, "application/octet-stream", data=b"b"),
        ]
    )
    assert pua_only["clamav"]["classification"] == "pua"
    assert pua_only["clamav"]["signature"] == "PUA.Example"

    sequence = iter(
        [ClamHit("pua", "PUA.Example"), ClamHit("malware", "Win.Malware.Test")]
    )
    monkeypatch.setattr(clamav, "scan_bytes", lambda _data: next(sequence))
    mixed = scan_tree(
        [
            Member("a.bin", "aa", 1, 0, "application/octet-stream", data=b"a"),
            Member("b.bin", "bb", 1, 0, "application/octet-stream", data=b"b"),
        ]
    )
    assert mixed["clamav"]["classification"] == "malware"
    assert mixed["clamav"]["signature"] == "Win.Malware.Test"


def test_static_signals_match_the_table():
    assert static.analyze(CLEAN, "note.txt") == []

    packed = _build_pe(tls=False)
    packed_ids = {signal.signal_id for signal in static.analyze(packed, "packed.exe")}
    assert "packer_section" in packed_ids
    assert "pe_rwe_section" in packed_ids
    assert "pe_no_imports" in packed_ids
    assert "pe_tls_callback" not in packed_ids

    tls_pe = _build_pe(tls=True)
    tls_ids = {signal.signal_id for signal in static.analyze(tls_pe, "tls.exe")}
    assert "pe_tls_callback" in tls_ids

    assert any(
        signal.signal_id == "double_extension"
        for signal in static.analyze(b"x", "invoice.pdf.exe")
    )
    macro = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32 + b"vbaProject.bin"
    assert any(signal.signal_id == "office_macro" for signal in static.analyze(macro, "doc.doc"))

    script = b"Invoke-Expression 'hi'\nInvoke-Expression 'again'\n"
    script_hits = static.analyze(script, "run.ps1")
    assert [signal.signal_id for signal in script_hits].count("script_exec") == 1
    assert static.analyze(script, "notes.txt") == []

    noisy = os.urandom(4096)
    assert any(signal.signal_id == "entropy_high" for signal in static.analyze(noisy, "blob.bin"))
    assert static.analyze(b"A" * 4096, "plain.txt") == []
    png = b"\x89PNG\r\n\x1a\n" + os.urandom(5000)
    assert not any(
        signal.signal_id == "entropy_high" for signal in static.analyze(png, "pic.png")
    )


def _bomb_zip() -> bytes:
    import io
    import zipfile

    for size in (50_000, 100_000, 250_000, 500_000, 1_000_000):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            archive.writestr("pad.bin", b"\x00" * size)
        payload = buf.getvalue()
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            info = archive.infolist()[0]
            if info.compress_size > 0 and info.file_size // info.compress_size >= 1000:
                return payload
    raise AssertionError("could not build a synthetic zip bomb")


def _build_pe(*, tls: bool) -> bytes:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x0102)
    optional = bytearray(224)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 92, 16)
    if tls:
        struct.pack_into("<II", optional, 96 + 9 * 8, 0x1000, 24)
    raw_ptr = 64 + 4 + 20 + 224 + 40
    section = bytearray(40)
    section[0:4] = b"UPX0"
    struct.pack_into("<I", section, 8, 64)
    struct.pack_into("<I", section, 12, 0x1000)
    struct.pack_into("<I", section, 16, 64)
    struct.pack_into("<I", section, 20, raw_ptr)
    struct.pack_into("<I", section, 36, 0x20000000 | 0x80000000 | 0x40000000)
    raw = bytearray(64)
    if tls:
        struct.pack_into("<I", raw, 12, 0x1018)
        struct.pack_into("<I", raw, 24, 0x2000)
        struct.pack_into("<I", raw, 28, 0)
    return bytes(dos) + pe_sig + coff + bytes(optional) + bytes(section) + bytes(raw)
