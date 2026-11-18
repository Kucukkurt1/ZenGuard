import asyncio
import socket

import redis.asyncio as aioredis
from fastapi import APIRouter
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import get_settings
from app.schemas.analysis import HealthResponse
from fastapi import Depends

router = APIRouter(tags=["health"])


async def check_db(session: AsyncSession) -> str:
    try:
        await session.execute(text("SELECT 1"))
        return "ok"
    except Exception:
        return "down"


async def check_redis() -> str:
    settings = get_settings()
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        pong = await client.ping()
        return "ok" if pong else "down"
    except Exception:
        return "down"
    finally:
        await client.aclose()


async def check_clamav_tcp() -> str:
    settings = get_settings()
    host, _, port_str = settings.clamav_tcp_addr.rpartition(":")
    if not host or not port_str:
        return "down"
    port = int(port_str)

    def _ping() -> bool:
        try:
            with socket.create_connection((host, port), timeout=3.0) as sock:
                sock.sendall(b"zPING\0")
                data = sock.recv(64)
                return b"PONG" in data
        except OSError:
            return False

    ok = await asyncio.to_thread(_ping)
    return "ok" if ok else "down"


@router.get("/health", response_model=HealthResponse)
async def health(session: AsyncSession = Depends(get_db)) -> HealthResponse:
    db_status, redis_status, clamav_status = await asyncio.gather(
        check_db(session),
        check_redis(),
        check_clamav_tcp(),
    )
    return HealthResponse(
        api="ok",
        db=db_status,
        redis=redis_status,
        clamav=clamav_status,
    )
