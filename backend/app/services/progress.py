import json
from uuid import UUID

import redis

from app.core.config import get_settings

_PREFIX = "zg:progress:"


def _client() -> redis.Redis:
    return redis.Redis.from_url(get_settings().redis_url, decode_responses=True)


def set_progress(analysis_id: UUID, percent: int, stage: str) -> None:
    bounded = max(0, min(100, int(percent)))
    try:
        client = _client()
        try:
            client.set(
                f"{_PREFIX}{analysis_id}",
                json.dumps({"percent": bounded, "stage": stage}, ensure_ascii=False),
                ex=3600,
            )
        finally:
            client.close()
    except redis.RedisError:
        return


def get_progress(analysis_id: UUID) -> tuple[int, str] | None:
    try:
        client = _client()
        try:
            raw = client.get(f"{_PREFIX}{analysis_id}")
        finally:
            client.close()
    except redis.RedisError:
        return None
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    percent = payload.get("percent")
    stage = payload.get("stage")
    if not isinstance(percent, int) or not isinstance(stage, str):
        return None
    return percent, stage


def clear_progress(analysis_id: UUID) -> None:
    try:
        client = _client()
        try:
            client.delete(f"{_PREFIX}{analysis_id}")
        finally:
            client.close()
    except redis.RedisError:
        return
