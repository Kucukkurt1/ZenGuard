import os

# Phase 3 unit tests run the engines in-process. This is not the isolation boundary.
os.environ["ZENG_SANDBOX_MODE"] = "inprocess"

_DEFAULTS = {
    "POSTGRES_USER": "zenguard",
    "POSTGRES_PASSWORD": "zenguard",
    "POSTGRES_DB": "zenguard",
    "DATABASE_URL": "postgresql+asyncpg://zenguard:zenguard@localhost:5432/zenguard",
    "DATABASE_URL_SYNC": "postgresql+psycopg://zenguard:zenguard@localhost:5432/zenguard",
    "REDIS_URL": "redis://:zenguard@localhost:6379/0",
    "CLAMAV_SOCKET": "/run/clamav/clamd.sock",
    "CLAMAV_TCP_ADDR": "clamav:3310",
    "ZENG_MAX_UPLOAD_BYTES": "52428800",
    "ZENG_MAX_UNCOMPRESSED_BYTES": "104857600",
    "ZENG_MAX_ARCHIVE_DEPTH": "3",
    "ZENG_MAX_ARCHIVE_FILES": "200",
    "ZENG_ZIP_BOMB_RATIO": "1000",
}
for _key, _value in _DEFAULTS.items():
    os.environ.setdefault(_key, _value)
