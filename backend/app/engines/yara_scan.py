import hashlib
from pathlib import Path

import yara

from app.engines.types import YaraHit

_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_CACHE: dict[str, object] = {"version": None, "rules": None}


class YaraError(Exception):
    error_code = "yara_error"


def rules_directory() -> Path:
    candidates = [
        Path("/rules/yara"),
        Path(__file__).resolve().parents[3] / "rules" / "yara",
    ]
    for candidate in candidates:
        if candidate.is_dir() and any(candidate.glob("*.yar")):
            return candidate
    raise YaraError("rules/yara is not available")


def _version_of(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.glob("*.yar")):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def load_ruleset() -> tuple[yara.Rules, str]:
    """Compile ``rules/yara/*.yar`` once per process, again only if the bytes change."""
    try:
        directory = rules_directory()
        version = _version_of(directory)
        cached_rules = _CACHE.get("rules")
        if cached_rules is not None and _CACHE.get("version") == version:
            return cached_rules, version  # type: ignore[return-value]
        filepaths = {path.stem: str(path) for path in sorted(directory.glob("*.yar"))}
        compiled = yara.compile(filepaths=filepaths)
    except YaraError:
        raise
    except Exception as exc:
        raise YaraError(str(exc)) from exc
    _CACHE["rules"] = compiled
    _CACHE["version"] = version
    return compiled, version


def ruleset_version() -> str:
    _, version = load_ruleset()
    return version


def scan_bytes(data: bytes, member_path: str | None = None) -> list[YaraHit]:
    """Match one member. The same rule name is recorded once for that member."""
    try:
        rules, _version = load_ruleset()
        matches = rules.match(data=data)
    except YaraError:
        raise
    except Exception as exc:
        raise YaraError(str(exc)) from exc
    hits: list[YaraHit] = []
    seen: set[str] = set()
    for match in matches:
        if match.rule in seen:
            continue
        seen.add(match.rule)
        meta = match.meta or {}
        severity = str(meta.get("severity", "medium")).lower()
        if severity not in _SEVERITIES:
            severity = "medium"
        hits.append(YaraHit(rule=match.rule, severity=severity, member_path=member_path))
    return hits


try:
    load_ruleset()
except YaraError:
    pass
