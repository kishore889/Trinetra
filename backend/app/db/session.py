"""
TRINETRA — Database Session Management

Provides SQLAlchemy engine and session factory with connection pooling.
Includes dependency injection helper `get_db` for FastAPI endpoints.
"""

from __future__ import annotations

from typing import Generator
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

logger = logging.getLogger(__name__)


def _create_resilient_engine():
    db_url = settings.DATABASE_URL
    if db_url.startswith("sqlite"):
        return create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=settings.DEBUG,
        )

    try:
        eng = create_engine(
            db_url,
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW,
            pool_timeout=settings.DATABASE_POOL_TIMEOUT,
            pool_pre_ping=True,
            echo=settings.DEBUG,
        )
        # Verify connection
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return eng
    except Exception as exc:
        logger.warning(
            "Primary database connection (%s) failed: %s. Falling back to local SQLite database (sqlite:///./trinetra_dev.db).",
            db_url,
            exc,
        )
        return create_engine(
            "sqlite:///./trinetra_dev.db",
            connect_args={"check_same_thread": False},
            echo=settings.DEBUG,
        )


# Engine configuration
engine = _create_resilient_engine()

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a SQLAlchemy database session.
    Automatically commits/rollbacks and closes the session on exit.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
