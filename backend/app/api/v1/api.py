"""
TRINETRA — API v1 Router Registration
"""

from fastapi import APIRouter
from app.api.v1.endpoints import health, gmail_auth, emails, monitoring, content_analysis

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(gmail_auth.router, prefix="/auth", tags=["Gmail OAuth"])
api_router.include_router(emails.router, prefix="/emails", tags=["Emails"])
api_router.include_router(monitoring.router, prefix="/monitor", tags=["Monitoring"])
api_router.include_router(content_analysis.router, prefix="/analyze/content", tags=["Content Intelligence"])
