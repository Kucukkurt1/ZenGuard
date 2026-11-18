"""Pull the text lines a YARA rule actually matched.

Only used when the file is mostly text. Binary bodies return nothing.
"""

from app.engines.filetype import looks_like_text
from app.engines.yara_scan import YaraError, load_ruleset

_SKIP_PREFIXES = ("ZENG_FIXTURE_", "ZENG_BENIGN_")
_MAX_LINES = 8
_MAX_CHARS = 180


def _instances(match):
    for item in getattr(match, "strings", None) or []:
        instances = getattr(item, "instances", None)
        if instances is not None:
            for inst in instances:
                yield int(getattr(inst, "offset", 0) or 0), bytes(getattr(inst, "matched_data", b"") or b"")
            continue
        if isinstance(item, tuple) and len(item) >= 3 and isinstance(item[2], (bytes, bytearray)):
            yield int(item[0]), bytes(item[2])


def _line_at(data: bytes, offset: int) -> tuple[int, str] | None:
    if offset < 0 or offset > len(data):
        return None
    start = data.rfind(b"\n", 0, offset) + 1
    end = data.find(b"\n", offset)
    if end < 0:
        end = len(data)
    raw = data[start:end].replace(b"\r", b"")
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(ch) < 32 and ch != "\t" for ch in text):
        return None
    line_no = data[:start].count(b"\n") + 1
    return line_no, text[:_MAX_CHARS]


def excerpts_from(data: bytes) -> list[dict]:
    if not data or not looks_like_text(data):
        return []
    try:
        rules, _version = load_ruleset()
        matches = rules.match(data=data)
    except (YaraError, Exception):
        return []

    found: list[dict] = []
    seen: set[int] = set()
    for match in matches:
        for offset, blob in _instances(match):
            marker = blob.decode("utf-8", "replace").strip()
            if not marker or marker.upper().startswith(_SKIP_PREFIXES):
                continue
            located = _line_at(data, offset)
            if located is None:
                continue
            line_no, text = located
            if text.upper().startswith(_SKIP_PREFIXES):
                continue
            if line_no in seen:
                continue
            seen.add(line_no)
            found.append(
                {
                    "line": line_no,
                    "text": text,
                    "rule": match.rule,
                    "marker": marker[:80],
                }
            )
            if len(found) >= _MAX_LINES:
                return found
    return found
