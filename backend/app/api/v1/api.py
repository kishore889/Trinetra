"""
TRINETRA — API v1 Router Registration
"""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    health,
    gmail_auth,
    emails,
    monitoring,
    content_analysis,
    url_analysis,
    identity_analysis,
    threat_intel,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(gmail_auth.router, prefix="/auth", tags=["Gmail OAuth"])
api_router.include_router(emails.router, prefix="/emails", tags=["Emails"])
api_router.include_router(monitoring.router, prefix="/monitor", tags=["Monitoring"])
api_router.include_router(content_analysis.router, prefix="/analyze/content", tags=["Content Intelligence"])
api_router.include_router(url_analysis.router, prefix="/analyze/url", tags=["URL & Domain Intelligence"])
api_router.include_router(identity_analysis.router, prefix="/analyze/identity", tags=["Identity & Spoofing Intelligence"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["Threat Intelligence"])
