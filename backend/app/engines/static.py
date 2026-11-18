import math
import struct

from app.engines.filetype import looks_like_text, magic_family
from app.engines.types import Signal

SIGNAL_POINTS = {
    "entropy_high": 5,
    "packer_section": 4,
    "double_extension": 4,
    "office_macro": 6,
    "pe_rwe_section": 3,
    "pe_tls_callback": 3,
    "pe_no_imports": 3,
    "script_exec": 5,
}

EXECUTABLE_EXTENSIONS = {
    "exe",
    "dll",
    "scr",
    "com",
    "pif",
    "msi",
    "cpl",
    "bat",
    "cmd",
    "js",
    "jse",
    "vbs",
    "vbe",
    "ps1",
    "hta",
    "wsf",
}

DOCUMENT_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
    "docm",
    "xls",
    "xlsx",
    "xlsm",
    "ppt",
    "pptx",
    "pptm",
    "rtf",
    "txt",
    "jpg",
    "jpeg",
    "png",
    "gif",
}

SCRIPT_EXTENSIONS = {
    "ps1",
    "psm1",
    "psd1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "bat",
    "cmd",
    "py",
    "sh",
}

PACKER_SECTIONS = {"UPX0", "UPX1", ".aspack", ".adata", "MPRESS1", ".petite"}

SCRIPT_PATTERNS = (
    b"invoke-expression",
    b"downloadstring",
    b"frombase64string",
    b"wscript.shell",
    b"createobject",
    b"powershell",
    b"cmd.exe",
    b"eval(",
    b"base64 -d",
    b"/bin/sh",
    b"os.system",
)

_EXECUTE = 0x20000000
_WRITE = 0x80000000
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _suffixes(path: str) -> list[str]:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.startswith("."):
        name = name[1:]
    return [part for part in name.split(".") if part]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if not count:
            continue
        prob = count / total
        entropy -= prob * math.log2(prob)
    return entropy


def parse_pe(data: bytes) -> dict | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    nsections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    if opt_size < 96 or opt + opt_size > len(data):
        return None
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        num_rva_off = opt + 92
        dd_off = opt + 96
        word = 4
    elif magic == 0x20B:
        num_rva_off = opt + 108
        dd_off = opt + 112
        word = 8
    else:
        return None
    if num_rva_off + 4 > len(data):
        return None
    n_rva = struct.unpack_from("<I", data, num_rva_off)[0]

    def directory(index: int) -> tuple[int, int]:
        if index >= n_rva:
            return 0, 0
        off = dd_off + index * 8
        if off + 8 > len(data):
            return 0, 0
        return struct.unpack_from("<II", data, off)

    sections = []
    sec = opt + opt_size
    for index in range(nsections):
        off = sec + index * 40
        if off + 40 > len(data):
            break
        name = data[off : off + 8].split(b"\x00", 1)[0].decode("latin1", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append(
            {
                "name": name,
                "vsize": vsize,
                "va": va,
                "rawsize": rawsize,
                "rawptr": rawptr,
                "chars": chars,
            }
        )
    return {
        "word": word,
        "sections": sections,
        "import": directory(1),
        "tls": directory(9),
        "data": data,
    }


def _rva_to_offset(sections: list[dict], rva: int) -> int | None:
    for section in sections:
        span = max(section["vsize"], section["rawsize"], 1)
        if section["va"] <= rva < section["va"] + span:
            return section["rawptr"] + (rva - section["va"])
    return None


def _tls_has_callback(pe: dict) -> bool:
    va, size = pe["tls"]
    if va == 0 or size == 0:
        return False
    off = _rva_to_offset(pe["sections"], va)
    if off is None:
        return False
    data: bytes = pe["data"]
    word = pe["word"]
    cb_pos = 12 if word == 4 else 24
    if off + cb_pos + word > len(data):
        return False
    if word == 4:
        callback_rva = struct.unpack_from("<I", data, off + cb_pos)[0]
    else:
        callback_rva = struct.unpack_from("<Q", data, off + cb_pos)[0]
    if callback_rva == 0:
        return False
    array = _rva_to_offset(pe["sections"], callback_rva)
    if array is None or array + word > len(data):
        return False
    if word == 4:
        first = struct.unpack_from("<I", data, array)[0]
    else:
        first = struct.unpack_from("<Q", data, array)[0]
    return first != 0


def _office_macro(data: bytes, path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    if lowered.endswith("vbaproject.bin"):
        return True
    if not data.startswith(_OLE):
        return False
    needles = (
        b"vbaProject.bin",
        "vbaProject.bin".encode("utf-16le"),
        b"_VBA_PROJECT",
        "_VBA_PROJECT".encode("utf-16le"),
    )
    return any(needle in data for needle in needles)


def _executable_or_unknown(data: bytes, path: str) -> bool:
    family = magic_family(data[:4096])
    if family in {"pe", "elf", "macho"}:
        return True
    suffixes = _suffixes(path)
    if suffixes and suffixes[-1] in EXECUTABLE_EXTENSIONS:
        return True
    if family is not None:
        return False
    return not looks_like_text(data)


def analyze(data: bytes, member_path: str) -> list[Signal]:
    """Static signals for one member. No network. Each signal id at most once."""
    found: dict[str, Signal] = {}

    def add(signal_id: str, evidence: dict) -> None:
        if signal_id in found:
            return
        found[signal_id] = Signal(
            signal_id,
            SIGNAL_POINTS[signal_id],
            member_path,
            evidence,
        )

    if len(data) >= 4096:
        entropy = shannon_entropy(data)
        if entropy >= 7.2 and _executable_or_unknown(data, member_path):
            add("entropy_high", {"entropy": f"{entropy:.4f}"})

    suffixes = _suffixes(member_path)
    if (
        len(suffixes) >= 2
        and suffixes[-1] in EXECUTABLE_EXTENSIONS
        and suffixes[-2] in DOCUMENT_EXTENSIONS
    ):
        add("double_extension", {"filename": member_path})

    if _office_macro(data, member_path):
        add("office_macro", {"marker": "vbaProject.bin"})

    pe = parse_pe(data) if data.startswith(b"MZ") else None
    if pe is not None:
        for section in pe["sections"]:
            if section["name"] in PACKER_SECTIONS:
                add("packer_section", {"section": section["name"]})
                break
        for section in pe["sections"]:
            chars = section["chars"]
            if chars & _EXECUTE and chars & _WRITE:
                add("pe_rwe_section", {"section": section["name"]})
                break
        if _tls_has_callback(pe):
            add("pe_tls_callback", {"present": True})
        import_va, import_size = pe["import"]
        if import_va == 0 or import_size == 0:
            add("pe_no_imports", {})

    if suffixes and suffixes[-1] in SCRIPT_EXTENSIONS:
        lowered = data.lower()
        for pattern in SCRIPT_PATTERNS:
            if pattern in lowered:
                add("script_exec", {"pattern": pattern.decode("ascii")})
                break

    return list(found.values())
