from app.engines.types import ScanResult
from app.services.scoring import build_report


def _result(**engines) -> ScanResult:
    return ScanResult(
        coverage="full",
        error_code=None,
        ruleset_version="abc",
        members=[{"path": "note.txt", "sha256": "aa", "size_bytes": 4, "depth": 0, "mime_type": "text/plain"}],
        engines=engines,
    )


def test_clean_score_is_zero():
    report = build_report(
        _result(
            clamav={"status": "ok", "classification": "clean", "signature": None, "hits": []},
            yara={"status": "ok", "matches": []},
            static={"status": "ok", "signals": []},
            archive={"status": "skipped", "signals": []},
        )
    )
    assert report["score"]["value"] == 0
    assert report["score"]["band"] == "clean"
    assert report["score"]["mode"] == "weighted_sum"


def test_eicar_signature_is_sure():
    report = build_report(
        _result(
            clamav={
                "status": "ok",
                "classification": "malware",
                "signature": "Win.Test.EICAR_HDB-1",
                "hits": [{"member_path": "eicar.com", "classification": "malware", "signature": "Win.Test.EICAR_HDB-1"}],
            },
            yara={
                "status": "ok",
                "matches": [
                    {"rule": "eicar", "severity": "critical", "member_path": "eicar.com"},
                    {"rule": "eicar", "severity": "critical", "member_path": "eicar.com"},
                ],
            },
            static={"status": "ok", "signals": []},
            archive={"status": "skipped", "signals": []},
        )
    )
    assert report["score"]["components"]["clamav"]["awarded"] == 55
    assert report["score"]["components"]["yara"]["awarded"] == 40
    assert report["score"]["evidence_sum"] == 95
    assert report["score"]["value"] == 100
    assert report["score"]["mode"] == "certainty_sure"
    assert report["score"]["band"] == "critical"
    assert len(report["score"]["components"]["yara"]["reasons"]) == 1


def test_critical_indicator_without_body_is_90():
    report = build_report(
        _result(
            clamav={"status": "ok", "classification": "clean", "signature": None, "hits": []},
            yara={
                "status": "ok",
                "matches": [{"rule": "fixture_ransom_note", "severity": "critical", "member_path": "note.txt"}],
            },
            static={"status": "ok", "signals": []},
            archive={"status": "skipped", "signals": []},
        )
    )
    assert report["score"]["components"]["yara"]["awarded"] == 40
    assert report["score"]["evidence_sum"] == 40
    assert report["score"]["floor"] == 90
    assert report["score"]["value"] == 90
    assert report["score"]["mode"] == "certainty_indicator"
    assert report["score"]["band"] == "critical"


def test_high_indicator_without_body_is_85():
    report = build_report(
        _result(
            clamav={"status": "ok", "classification": "clean", "signature": None, "hits": []},
            yara={
                "status": "ok",
                "matches": [{"rule": "suspicious_powershell", "severity": "high", "member_path": "note.ps1"}],
            },
            static={"status": "ok", "signals": [{"signal_id": "script_exec", "points": 5, "member_path": "note.ps1"}]},
            archive={"status": "skipped", "signals": []},
        )
    )
    assert report["score"]["evidence_sum"] == 25
    assert report["score"]["value"] == 85
    assert report["score"]["band"] == "critical"


def test_eicar_rule_alone_is_not_an_indicator_floor():
    report = build_report(
        _result(
            clamav={"status": "ok", "classification": "clean", "signature": None, "hits": []},
            yara={"status": "ok", "matches": [{"rule": "eicar", "severity": "critical", "member_path": "eicar.com"}]},
            static={"status": "ok", "signals": []},
            archive={"status": "skipped", "signals": []},
        )
    )
    assert report["score"]["value"] == 40
    assert report["score"]["mode"] == "weighted_sum"


def test_static_macro_stays_structural():
    report = build_report(
        _result(
            clamav={"status": "ok", "classification": "clean", "signature": None, "hits": []},
            yara={"status": "ok", "matches": []},
            static={"status": "ok", "signals": [{"signal_id": "office_macro", "points": 6, "member_path": "a.doc"}]},
            archive={"status": "skipped", "signals": []},
        )
    )
    assert report["score"]["value"] == 6
    assert report["score"]["band"] == "low"
    assert report["score"]["mode"] == "weighted_sum"


def test_policy_override_is_100():
    result = _result(archive={"status": "rejected", "signals": [], "error_code": "ZIP_BOMB"})
    result.error_code = "ZIP_BOMB"
    result.coverage = "none"
    report = build_report(result)
    assert report["score"]["mode"] == "policy_override"
    assert report["score"]["value"] == 100
    assert report["score"]["band"] == "critical"
    assert report["coverage"] == "none"
    assert report["score"]["components"]["archive"]["reasons"][0]["code"] == "ZIP_BOMB"
