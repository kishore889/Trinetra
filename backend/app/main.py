"""
TRINETRA — Main FastAPI Application Entry Point

AI-Powered Real-Time Phishing Detection & Threat Intelligence System
"""

# Ensure .env at project root is loaded before anything else imports settings
import os as _os
from pathlib import Path as _Path

_backend_dir = _Path(__file__).parent.parent          # d:/TRINETRA/backend
_project_root = _backend_dir.parent                   # d:/TRINETRA
_env_in_backend = _backend_dir / ".env"
_env_in_root    = _project_root / ".env"

if not _env_in_backend.exists() and _env_in_root.exists():
    # Symlink / copy not needed — just pre-load it into os.environ before
    # pydantic-settings (lru_cached) runs for the first time.
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(dotenv_path=str(_env_in_root), override=False)

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, logger
from app.core.middleware import (
    SecurityHeadersMiddleware,
    RateLimitingMiddleware,
    SanitizedErrorMiddleware,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for startup and shutdown events."""
    configure_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    logger.info(
        "trinetra_starting",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        env=settings.APP_ENV,
    )
    # Safe database initialization & seeding
    try:
        import app.models  # noqa: F401
        from app.db.base import Base
        from app.db.session import engine, SessionLocal
        from app.services.seed_service import seed_initial_data_if_empty

        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            seed_initial_data_if_empty(db)
        logger.info("database_tables_and_seed_ready")
    except Exception as e:
        logger.warning("database_auto_init_skipped", error=str(e))

    yield
    logger.info("trinetra_stopping", service=settings.APP_NAME)


def create_application() -> FastAPI:
    """FastAPI application factory for TRINETRA with security hardening."""
    app = FastAPI(
        title=settings.APP_NAME,
        description=settings.APP_FULL_NAME,
        version=settings.APP_VERSION,
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # 1. Security Headers Middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # 2. Rate Limiting Middleware
    app.add_middleware(RateLimitingMiddleware, max_requests=settings.RATE_LIMIT_PER_MINUTE)

    # 3. Sanitized Error Middleware
    app.add_middleware(SanitizedErrorMiddleware)

    # 4. CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
    )

    # Global Exception Handlers
    register_exception_handlers(app)

    # Include API Routers
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # Root endpoint — production-safe API identity response
    @app.get("/", include_in_schema=False)
    async def root_endpoint() -> JSONResponse:
        """TRINETRA API root — service identification only. No secrets exposed."""
        return JSONResponse(
            status_code=200,
            content={
                "service": "TRINETRA",
                "description": "AI-Powered Real-Time Phishing Detection & Threat Intelligence System",
                "status": "ok",
                "version": settings.APP_VERSION,
                "docs": "/docs",
                "health": "/health",
                "openapi": f"{settings.API_V1_PREFIX}/openapi.json",
            },
        )

    # Direct /health endpoint (delegates to API v1 health logic)
    @app.get("/health", include_in_schema=False)
    def root_health():
        """Direct health endpoint for load balancers and system monitoring."""
        return {
            "service": "TRINETRA",
            "status": "healthy",
            "version": settings.APP_VERSION,
            "api_health": f"{settings.API_V1_PREFIX}/health",
        }

    return app


app = create_application()
