"""
TRINETRA — API v1 Router Registration
"""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    health,
    auth,
    gmail_auth,
    emails,
    monitoring,
    content_analysis,
    url_analysis,
    identity_analysis,
    threat_intel,
    graph_analysis,
    risk_evaluation,
    explainability,
    gmail_actions,
    dashboard,
    realtime,
    incidents,
    review,
    demo,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["User Authentication"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard Telemetry"])
api_router.include_router(realtime.router, prefix="/realtime", tags=["Real-Time Streaming"])
api_router.include_router(gmail_auth.router, prefix="/auth", tags=["Gmail OAuth"])
api_router.include_router(emails.router, prefix="/emails", tags=["Emails"])
api_router.include_router(monitoring.router, prefix="/monitor", tags=["Monitoring"])
api_router.include_router(content_analysis.router, prefix="/analyze/content", tags=["Content Intelligence"])
api_router.include_router(url_analysis.router, prefix="/analyze/url", tags=["URL & Domain Intelligence"])
api_router.include_router(identity_analysis.router, prefix="/analyze/identity", tags=["Identity & Spoofing Intelligence"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["Threat Intelligence"])
api_router.include_router(graph_analysis.router, prefix="/graph", tags=["Graph Intelligence"])
api_router.include_router(risk_evaluation.router, prefix="/risk", tags=["Central Risk Engine"])
api_router.include_router(explainability.router, prefix="/explain", tags=["Explainable AI"])
api_router.include_router(gmail_actions.router, prefix="/actions", tags=["Gmail Actions"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incident Management"])
api_router.include_router(review.router, prefix="/review", tags=["HITL Review Queue"])
api_router.include_router(demo.router, prefix="/demo", tags=["Demo Center"])


