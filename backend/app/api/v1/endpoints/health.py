"""
TRINETRA — Health Check Endpoint
GET /api/v1/health
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.schemas.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
def get_health_status(db: Session = Depends(get_db)) -> HealthResponse:
    """
    TRINETRA Service Health Status.
    Checks database connection and reports active configuration status.
    """
    db_connected = False
    try:
        db.execute(text("SELECT 1"))
        db_connected = True
    except Exception:
        db_connected = False

    return HealthResponse(
        service="TRINETRA",
        status="healthy" if db_connected else "degraded",
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        database_connected=db_connected,
        active_layers=[
            "Content Intelligence",
            "URL / Domain Intelligence",
            "Identity / Spoofing Intelligence",
            "Threat Intelligence",
            "Graph Intelligence",
            "Central Risk Engine",
            "Explainability",
        ],
    )
