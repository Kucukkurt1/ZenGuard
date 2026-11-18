from app.engines.types import ScanResult

POLICY_CODES = {
    "ZIP_BOMB",
    "SIZE_LIMIT",
    "ARCHIVE_COUNT",
    "ARCHIVE_DEPTH",
    "PATH_TRAVERSAL",
    "UNSAFE_MEMBER",
}

POLICY_LIMIT = {
    "ZIP_BOMB": "ratio>=1000",
    "SIZE_LIMIT": 104857600,
    "ARCHIVE_COUNT": 200,
    "ARCHIVE_DEPTH": 3,
    "PATH_TRAVERSAL": "path",
    "UNSAFE_MEMBER": "symlink",
}

YARA_POINTS = {"info": 0, "low": 5, "medium": 10, "high": 20, "critical": 40}
EICAR_RULES = {"eicar", "eicar_test"}
# Pattern seen, payload body not seen. Critical intent is higher than a high-severity script pattern.
INDICATOR_FLOOR = {"critical": 90, "high": 85}

COMPONENT_MAX = {"clamav": 55, "yara": 40, "static": 15, "archive": 10}


def band_for(score: int) -> str:
    if score <= 0:
        return "clean"
    if score <= 24:
        return "low"
    if score <= 49:
        return "medium"
    if score <= 79:
        return "high"
    return "critical"


def _certainty(clam_points: int, yara_reasons: list[dict]) -> tuple[str, int | None]:
    """Sure signature lifts the score to 100. A threat-class rule without that body lifts it to 85 or 90."""
    if clam_points >= 55:
        return "certainty_sure", 100
    rank = 0
    for reason in yara_reasons:
        rule = str(reason.get("rule") or reason.get("code") or "")
        if rule in EICAR_RULES:
            continue
        severity = str(reason.get("severity") or "")
        rank = max(rank, INDICATOR_FLOOR.get(severity, 0))
    if rank:
        return "certainty_indicator", rank
    return "weighted_sum", None


def _component(awarded: int, key: str, reasons: list[dict]) -> dict:
    return {"awarded": awarded, "max": COMPONENT_MAX[key], "reasons": reasons}


def _empty_components() -> dict:
    return {key: _component(0, key, []) for key in COMPONENT_MAX}


def build_report(result: ScanResult) -> dict:
    """Turn an engine result into report version 1, including the locked score."""
    if result.error_code in POLICY_CODES:
        return _policy_report(result)

    clam_points, clam_reasons = _clamav(result.engines.get("clamav") or {})
    yara_points, yara_reasons = _yara((result.engines.get("yara") or {}).get("matches") or [])
    static_points, static_reasons = _signals(
        (result.engines.get("static") or {}).get("signals") or [], 15
    )
    archive_points, archive_reasons = _signals(
        (result.engines.get("archive") or {}).get("signals") or [], 10
    )
    raw_sum = clam_points + yara_points + static_points + archive_points
    evidence = min(100, raw_sum)
    mode, floor = _certainty(clam_points, yara_reasons)
    value = evidence if floor is None else max(evidence, floor)
    return {
        "report_version": 1,
        "coverage": result.coverage,
        "members": result.members,
        "engines": _public_engines(result.engines),
        "score": {
            "mode": mode,
            "value": value,
            "band": band_for(value),
            "raw_sum": raw_sum,
            "clipped": raw_sum - evidence,
            "evidence_sum": evidence,
            "floor": floor,
            "components": {
                "clamav": _component(clam_points, "clamav", clam_reasons),
                "yara": _component(yara_points, "yara", yara_reasons),
                "static": _component(static_points, "static", static_reasons),
                "archive": _component(archive_points, "archive", archive_reasons),
            },
        },
    }


def _policy_report(result: ScanResult) -> dict:
    code = result.error_code or "POLICY"
    reason = {
        "code": code,
        "points": 100,
        "member_path": None,
        "evidence": {"limit": POLICY_LIMIT.get(code)},
    }
    components = _empty_components()
    components["archive"] = _component(0, "archive", [reason])
    engines = _public_engines(result.engines)
    engines["archive"] = {
        "status": "rejected",
        "signals": [],
        "error_code": code,
    }
    return {
        "report_version": 1,
        "coverage": "none",
        "members": [],
        "engines": engines,
        "score": {
            "mode": "policy_override",
            "value": 100,
            "band": "critical",
            "raw_sum": 100,
            "clipped": 0,
            "components": components,
        },
    }


def _public_engines(engines: dict) -> dict:
    clam = engines.get("clamav") or {}
    yara = engines.get("yara") or {}
    static = engines.get("static") or {}
    archive = engines.get("archive") or {}
    return {
        "clamav": {
            "status": clam.get("status", "skipped"),
            "signature": clam.get("signature"),
        },
        "yara": {
            "status": yara.get("status", "skipped"),
            "matches": yara.get("matches") or [],
        },
        "static": {
            "status": static.get("status", "skipped"),
            "signals": static.get("signals") or [],
        },
        "archive": {
            "status": archive.get("status", "skipped"),
            "signals": archive.get("signals") or [],
        },
    }


def _clamav(engine: dict) -> tuple[int, list[dict]]:
    kind = engine.get("classification")
    if kind == "malware":
        points = 55
        code = "malware_signature"
    elif kind == "pua":
        points = 25
        code = "pua_heuristic"
    else:
        return 0, []
    hits = engine.get("hits") or []
    paths = [hit.get("member_path") for hit in hits if hit.get("classification") == kind and hit.get("member_path")]
    return points, [
        {
            "code": code,
            "points": points,
            "member_path": paths[0] if paths else None,
            "evidence": {"signature": engine.get("signature"), "paths": paths},
        }
    ]


def _yara(matches: list[dict]) -> tuple[int, list[dict]]:
    grouped: dict[str, dict] = {}
    for match in matches:
        rule = str(match.get("rule") or "")
        if not rule:
            continue
        slot = grouped.setdefault(
            rule,
            {"severity": str(match.get("severity") or "medium"), "paths": []},
        )
        path = match.get("member_path")
        if path and path not in slot["paths"]:
            slot["paths"].append(path)
    reasons = []
    raw = 0
    for rule, slot in grouped.items():
        severity = slot["severity"] if slot["severity"] in YARA_POINTS else "medium"
        points = YARA_POINTS[severity]
        raw += points
        reasons.append(
            {
                "code": rule,
                "points": points,
                "rule": rule,
                "severity": severity,
                "member_path": slot["paths"][0] if slot["paths"] else None,
                "evidence": {"paths": slot["paths"]},
            }
        )
    return min(40, raw), reasons


def _signals(signals: list[dict], cap: int) -> tuple[int, list[dict]]:
    reasons = []
    raw = 0
    for signal in signals:
        points = int(signal.get("points") or 0)
        raw += points
        reasons.append(
            {
                "code": signal.get("signal_id"),
                "points": points,
                "member_path": signal.get("member_path"),
                "evidence": signal.get("evidence") or {},
            }
        )
    return min(cap, raw), reasons
