from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    postgres_user: str = Field(validation_alias="POSTGRES_USER")
    postgres_password: str = Field(validation_alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(validation_alias="POSTGRES_DB")

    database_url: str = Field(validation_alias="DATABASE_URL")
    database_url_sync: str = Field(validation_alias="DATABASE_URL_SYNC")

    redis_url: str = Field(validation_alias="REDIS_URL")
    celery_result_ttl_seconds: int = Field(
        default=3600, validation_alias="CELERY_RESULT_TTL_SECONDS"
    )

    clamav_socket: str = Field(validation_alias="CLAMAV_SOCKET")
    clamav_tcp_addr: str = Field(validation_alias="CLAMAV_TCP_ADDR")

    zeng_sandbox_mode: str = Field(
        default="docker", validation_alias="ZENG_SANDBOX_MODE"
    )
    zeng_max_upload_bytes: int = Field(
        default=52_428_800, validation_alias="ZENG_MAX_UPLOAD_BYTES"
    )
    zeng_max_uncompressed_bytes: int = Field(
        default=104_857_600, validation_alias="ZENG_MAX_UNCOMPRESSED_BYTES"
    )
    zeng_max_archive_depth: int = Field(
        default=3, validation_alias="ZENG_MAX_ARCHIVE_DEPTH"
    )
    zeng_max_archive_files: int = Field(
        default=200, validation_alias="ZENG_MAX_ARCHIVE_FILES"
    )
    zeng_zip_bomb_ratio: int = Field(
        default=1000, validation_alias="ZENG_ZIP_BOMB_RATIO"
    )
    zeng_sandbox_timeout_seconds: int = Field(
        default=120, validation_alias="ZENG_SANDBOX_TIMEOUT_SECONDS"
    )

    zeng_quarantine_dir: str = Field(
        default="./data/quarantine", validation_alias="ZENG_QUARANTINE_DIR"
    )
    zeng_cors_origins: str = Field(
        default="http://127.0.0.1:3000,http://localhost:3000",
        validation_alias="ZENG_CORS_ORIGINS",
    )

    @field_validator("zeng_sandbox_mode")
    @classmethod
    def sandbox_mode_allowed(cls, value: str) -> str:
        allowed = {"docker", "inprocess"}
        if value not in allowed:
            raise ValueError(f"ZENG_SANDBOX_MODE must be one of {allowed}")
        return value

    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.zeng_cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
