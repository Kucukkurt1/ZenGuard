from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import analyses, health
from app.core.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    from pathlib import Path

    Path(settings.zeng_quarantine_dir).mkdir(parents=True, exist_ok=True)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ZenGuard API",
        version="0.2.0",
        description="Birleşik tehdit ve statik analiz platformu",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(analyses.router, prefix="/api/v1")

    @app.get("/")
    async def root():
        return {"service": "zenguard", "docs": "/docs", "api": "/api/v1"}

    return app


app = create_app()
