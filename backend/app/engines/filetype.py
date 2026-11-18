import io
import tarfile

EXT_FAMILY = {
    "zip": "zip",
    "7z": "7z",
    "tar": "tar",
    "tgz": "gzip",
    "gz": "gzip",
    "bz2": "bzip2",
    "tbz2": "bzip2",
    "png": "png",
    "jpg": "jpeg",
    "jpeg": "jpeg",
    "gif": "gif",
    "pdf": "pdf",
    "exe": "pe",
    "dll": "pe",
    "scr": "pe",
    "txt": "text",
    "md": "text",
    "csv": "text",
}

_MACHO = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}


def extension_family(name: str) -> str | None:
    lower = name.lower()
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        return "gzip"
    if lower.endswith(".tar.bz2") or lower.endswith(".tbz2"):
        return "bzip2"
    if "." not in lower:
        return None
    return EXT_FAMILY.get(lower.rsplit(".", 1)[-1])


def magic_family(data: bytes) -> str | None:
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "zip"
    if data.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"BZh"):
        return "bzip2"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if len(data) >= 4 and data[:4] in _MACHO:
        return "macho"
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    return None


def looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    textish = sum(byte in b"\t\r\n" or 32 <= byte < 127 for byte in sample)
    return textish / len(sample) >= 0.90


def mime_type(data: bytes) -> str:
    try:
        import magic

        detected = magic.from_buffer(data[:8192], mime=True)
        if detected:
            return detected
    except Exception:
        pass
    family = magic_family(data)
    if family == "pe":
        return "application/vnd.microsoft.portable-executable"
    if family == "elf":
        return "application/x-elf"
    if family == "pdf":
        return "application/pdf"
    if family == "png":
        return "image/png"
    if family == "jpeg":
        return "image/jpeg"
    if family == "zip":
        return "application/zip"
    if family == "gzip":
        return "application/gzip"
    if family == "7z":
        return "application/x-7z-compressed"
    if looks_like_text(data):
        return "text/plain"
    return "application/octet-stream"


def _tar_opens(source) -> bool:
    for mode in ("r:", "r:gz", "r:bz2"):
        try:
            if isinstance(source, (bytes, bytearray)):
                with tarfile.open(fileobj=io.BytesIO(source), mode=mode) as archive:
                    archive.getmembers()
                return True
            with open(source, "rb") as handle:
                with tarfile.open(fileobj=handle, mode=mode) as archive:
                    archive.getmembers()
                return True
        except (tarfile.TarError, OSError, EOFError):
            continue
    return False


def detect_container(data: bytes) -> str | None:
    family = magic_family(data[:4096] if len(data) > 4096 else data)
    if family == "zip":
        return "zip"
    if family == "7z":
        return "7z"
    if family in {"gzip", "bzip2", "tar"} and _tar_opens(data):
        return "tar"
    return None


def detect_container_path(path) -> str | None:
    with open(path, "rb") as handle:
        head = handle.read(4096)
    family = magic_family(head)
    if family == "zip":
        return "zip"
    if family == "7z":
        return "7z"
    if family in {"gzip", "bzip2", "tar"} and _tar_opens(path):
        return "tar"
    return None
