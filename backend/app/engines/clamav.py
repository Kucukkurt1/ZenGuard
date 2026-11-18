import os
import socket
import struct

from app.core.config import get_settings
from app.engines.types import ClamHit


class ClamavError(Exception):
    error_code = "clamav_error"


_CHUNK = 65536


def _tcp_endpoint() -> tuple[str, int]:
    settings = get_settings()
    host, _, port_str = settings.clamav_tcp_addr.rpartition(":")
    if not host or not port_str:
        raise ClamavError("CLAMAV_TCP_ADDR is not host:port")
    return host, int(port_str)


def _connect(timeout: float = 30.0) -> socket.socket:
    """Unix socket first. TCP is the fallback for hosts without the socket."""
    settings = get_settings()
    sock_path = settings.clamav_socket
    if sock_path and os.path.exists(sock_path):
        try:
            unix_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix_sock.settimeout(timeout)
            unix_sock.connect(sock_path)
            return unix_sock
        except OSError:
            pass
    host, port = _tcp_endpoint()
    try:
        tcp_sock = socket.create_connection((host, port), timeout=min(timeout, 10.0))
        tcp_sock.settimeout(timeout)
        return tcp_sock
    except OSError as exc:
        raise ClamavError(f"clamav unreachable: {exc}") from exc


def ping_tcp(timeout: float = 3.0) -> bool:
    """Health check on the internal TCP listener. Scan traffic does not use this."""
    try:
        host, port = _tcp_endpoint()
    except (ClamavError, ValueError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"zPING\0")
            data = sock.recv(64)
            return b"PONG" in data
    except OSError:
        return False


def channel_available() -> bool:
    try:
        sock = _connect(timeout=3.0)
    except ClamavError:
        return False
    sock.close()
    return True


def classify_response(raw: str) -> ClamHit:
    text = raw.strip().strip("\x00")
    if not text:
        raise ClamavError("empty clamd response")
    if "ERROR" in text.upper():
        raise ClamavError(text)
    if "FOUND" not in text and text.endswith("OK"):
        return ClamHit("clean", None)
    if "FOUND" in text:
        signature = text.split(":", 1)[-1].rsplit("FOUND", 1)[0].strip()
        if not signature:
            raise ClamavError(text)
        if signature.startswith("PUA.") or signature.startswith("Heuristics."):
            return ClamHit("pua", signature)
        return ClamHit("malware", signature)
    raise ClamavError(text)


def _recv_z(sock: socket.socket) -> str:
    buf = b""
    while b"\0" not in buf:
        part = sock.recv(4096)
        if not part:
            break
        buf += part
        if len(buf) > 65536:
            break
    return buf.split(b"\0", 1)[0].decode("utf-8", "replace")


def scan_bytes(data: bytes) -> ClamHit:
    """Scan one buffer with clamd ``zINSTREAM``.

    Malware wins over PUA. ``PUA.*`` and ``Heuristics.*`` alone are PUA.
    Connection and protocol failures raise ``ClamavError``.
    """
    try:
        sock = _connect()
    except ClamavError:
        raise
    try:
        sock.sendall(b"zINSTREAM\0")
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            chunk = view[offset : offset + _CHUNK]
            sock.sendall(struct.pack(">I", len(chunk)))
            sock.sendall(chunk)
            offset += len(chunk)
        sock.sendall(struct.pack(">I", 0))
        return classify_response(_recv_z(sock))
    except ClamavError:
        raise
    except OSError as exc:
        raise ClamavError(f"clamav instream failed: {exc}") from exc
    finally:
        sock.close()
