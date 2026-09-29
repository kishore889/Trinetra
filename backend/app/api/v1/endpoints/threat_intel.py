"""
TRINETRA — Threat Intelligence API Endpoints (Phase 9)

POST   /api/v1/threat-intel/lookup           → Single indicator lookup across all providers
POST   /api/v1/threat-intel/match            → Match full email entity set against all TI
GET    /api/v1/threat-intel/providers        → Provider health & availability status
GET    /api/v1/threat-intel/indicators       → List local TI database indicators
POST   /api/v1/threat-intel/indicators       → Add indicator to local TI database
DELETE /api/v1/threat-intel/indicators/{id} → Deactivate a local indicator
GET    /api/v1/threat-intel/certin           → List CERT-In advisory index
POST   /api/v1/threat-intel/report          → Generate incident report (analyst-initiated)
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Severity, ThreatIndicator
from app.services.threat_providers import (
    CERTInProvider,
    IndicatorType,
    NormalizedIndicator,
    ProviderHealthStatus,
    ThreatMatchResult,
    provider_registry,
)
from app.services.threat_intel_service import run_threat_intel_matching
from app.services.incident_report import IncidentReport, build_incident_report

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class IndicatorLookupRequest(BaseModel):
    indicator_type: str = Field(..., description="IP | DOMAIN | URL | EMAIL | HASH")
    value: str = Field(..., description="The indicator value to look up")


class EmailEntityMatchRequest(BaseModel):
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    urls: List[str] = []
    subject: Optional[str] = None


class AddIndicatorRequest(BaseModel):
    indicator_type: str = Field(..., description="IP | DOMAIN | URL | EMAIL | HASH")
    indicator_value: str
    source: str = "MANUAL"
    severity: str = "MEDIUM"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    description: Optional[str] = None


class IndicatorResponse(BaseModel):
    id: str
    indicator_type: str
    indicator_value: str
    source: str
    severity: str
    confidence: float
    description: Optional[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    is_active: bool


class IncidentReportRequest(BaseModel):
    incident_id: Optional[str] = None
    detection_time: Optional[str] = None
    email_message_id: Optional[str] = None
    email_subject: Optional[str] = None
    sender: Optional[str] = None
    sender_domain: Optional[str] = None
    recipient: Optional[str] = None
    urls: List[str] = []
    domains: List[str] = []
    ips: List[str] = []
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    final_risk_score: float = 0.0
    severity: str = "LOW"
    decision: str = "ALLOW"
    confidence: float = 0.0
    content_risk: float = 0.0
    url_risk: float = 0.0
    identity_risk: float = 0.0
    threat_intel_risk: float = 0.0
    graph_risk: float = 0.0
    explanation_summary: Optional[str] = None
    recommended_action: Optional[str] = None
    analyst_feedback: Optional[str] = None
    analyst_comments: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/lookup", response_model=List[NormalizedIndicator], status_code=status.HTTP_200_OK)
async def lookup_indicator(payload: IndicatorLookupRequest, db: Session = Depends(get_db)):
    """
    Queries all available TI providers for a single indicator.
    Returns a list of NormalizedIndicator matches (empty list = no match = no error).
    """
    itype = payload.indicator_type.upper()
    if itype not in {
        IndicatorType.IP, IndicatorType.DOMAIN,
        IndicatorType.URL, IndicatorType.EMAIL, IndicatorType.HASH,
    }:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid indicator_type '{payload.indicator_type}'. "
                   f"Must be one of: IP, DOMAIN, URL, EMAIL, HASH.",
        )
    return await provider_registry.lookup_all(itype, payload.value.strip(), db)


@router.post("/match", response_model=ThreatMatchResult, status_code=status.HTTP_200_OK)
async def match_email_entities(payload: EmailEntityMatchRequest, db: Session = Depends(get_db)):
    """
    Matches all extractable entities from an email (sender, domain, URLs, IPs)
    against all configured threat intelligence providers concurrently.
    Returns consolidated match result and threat_intel_risk score.
    """
    return await run_threat_intel_matching(
        sender_email=payload.sender_email,
        sender_domain=payload.sender_domain,
        urls=payload.urls,
        subject=payload.subject,
        db=db,
    )


@router.get("/providers", response_model=List[ProviderHealthStatus])
def get_provider_health():
    """Returns health and availability status of all configured TI providers."""
    return provider_registry.all_health()


@router.get("/indicators", response_model=List[IndicatorResponse])
def list_local_indicators(
    active_only: bool = True,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Lists indicators in the local TRINETRA threat intelligence database."""
    query = db.query(ThreatIndicator)
    if active_only:
        query = query.filter(ThreatIndicator.is_active == True)  # noqa: E712
    indicators = query.order_by(ThreatIndicator.last_seen.desc()).limit(limit).all()

    return [
        IndicatorResponse(
            id=str(ind.id),
            indicator_type=ind.indicator_type,
            indicator_value=ind.indicator_value,
            source=ind.source,
            severity=ind.severity.value if hasattr(ind.severity, "value") else str(ind.severity),
            confidence=ind.confidence,
            description=ind.description,
            first_seen=ind.first_seen.isoformat() if ind.first_seen else None,
            last_seen=ind.last_seen.isoformat() if ind.last_seen else None,
            is_active=ind.is_active,
        )
        for ind in indicators
    ]


@router.post("/indicators", response_model=IndicatorResponse, status_code=status.HTTP_201_CREATED)
def add_local_indicator(payload: AddIndicatorRequest, db: Session = Depends(get_db)):
    """
    Adds a new indicator to the local TRINETRA threat intelligence database.
    Analyst-initiated. Does NOT automatically submit to external providers.
    """
    itype = payload.indicator_type.upper()
    if itype not in {
        IndicatorType.IP, IndicatorType.DOMAIN,
        IndicatorType.URL, IndicatorType.EMAIL, IndicatorType.HASH, IndicatorType.SENDER,
    }:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid indicator_type '{payload.indicator_type}'.",
        )

    try:
        sev = Severity(payload.severity.upper())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid severity '{payload.severity}'. Must be LOW | MEDIUM | HIGH | CRITICAL.",
        )

    value_lower = payload.indicator_value.strip().lower()

    # Check for existing indicator
    existing = (
        db.query(ThreatIndicator)
        .filter(ThreatIndicator.indicator_value == value_lower)
        .first()
    )
    if existing:
        # Reactivate and update if it was soft-deleted
        existing.is_active = True
        existing.last_seen = datetime.now(timezone.utc)
        existing.severity = sev
        existing.confidence = payload.confidence
        db.commit()
        db.refresh(existing)
        ind = existing
    else:
        now = datetime.now(timezone.utc)
        ind = ThreatIndicator(
            indicator_type=itype,
            indicator_value=value_lower,
            source=payload.source,
            severity=sev,
            confidence=payload.confidence,
            description=payload.description,
            first_seen=now,
            last_seen=now,
            is_active=True,
        )
        db.add(ind)
        db.commit()
        db.refresh(ind)

    # Invalidate cache for this indicator
    from app.services.threat_providers import _cache
    _cache.clear()

    return IndicatorResponse(
        id=str(ind.id),
        indicator_type=ind.indicator_type,
        indicator_value=ind.indicator_value,
        source=ind.source,
        severity=ind.severity.value if hasattr(ind.severity, "value") else str(ind.severity),
        confidence=ind.confidence,
        description=ind.description,
        first_seen=ind.first_seen.isoformat() if ind.first_seen else None,
        last_seen=ind.last_seen.isoformat() if ind.last_seen else None,
        is_active=ind.is_active,
    )


@router.delete("/indicators/{indicator_id}", status_code=status.HTTP_200_OK)
def deactivate_indicator(indicator_id: str, db: Session = Depends(get_db)):
    """
    Soft-deactivates a local threat indicator. Data is preserved for audit.
    Analyst-initiated only.
    """
    try:
        uid = uuid.UUID(indicator_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid UUID.")

    ind = db.query(ThreatIndicator).filter(ThreatIndicator.id == uid).first()
    if not ind:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found.")

    ind.is_active = False
    db.commit()

    from app.services.threat_providers import _cache
    _cache.clear()

    return {"detail": f"Indicator '{ind.indicator_value}' deactivated.", "id": indicator_id}


@router.get("/certin")
def list_certin_advisories():
    """
    Returns the local CERT-In advisory index.

    NOTE: CERT-In does not provide a real-time public phishing classification API.
    These entries are sourced from published CERT-In advisories and maintained locally.
    """
    provider = CERTInProvider()
    return {
        "provider": provider.name,
        "provider_type": provider.provider_type,
        "note": (
            "CERT-In is an advisory intelligence source. "
            "Entries are derived from published advisories — not a real-time automated feed."
        ),
        "advisory_count": len(CERTInProvider.list_advisories()),
        "advisories": CERTInProvider.list_advisories(),
    }


@router.post("/report", response_model=IncidentReport, status_code=status.HTTP_200_OK)
def generate_incident_report(payload: IncidentReportRequest):
    """
    Generates a structured incident report from detection data.

    IMPORTANT: This report is for analyst review only.
    It is NOT automatically submitted to any external service.
    External submission requires explicit analyst action.
    """
    detection_dt: Optional[datetime] = None
    if payload.detection_time:
        try:
            detection_dt = datetime.fromisoformat(payload.detection_time)
        except ValueError:
            detection_dt = datetime.now(timezone.utc)

    report = build_incident_report(
        incident_id=payload.incident_id,
        detection_time=detection_dt,
        email_message_id=payload.email_message_id,
        email_subject=payload.email_subject,
        sender=payload.sender,
        sender_domain=payload.sender_domain,
        recipient=payload.recipient,
        urls=payload.urls,
        domains=payload.domains,
        ips=payload.ips,
        spf_result=payload.spf_result,
        dkim_result=payload.dkim_result,
        dmarc_result=payload.dmarc_result,
        final_risk_score=payload.final_risk_score,
        severity=payload.severity,
        decision=payload.decision,
        confidence=payload.confidence,
        content_risk=payload.content_risk,
        url_risk=payload.url_risk,
        identity_risk=payload.identity_risk,
        threat_intel_risk=payload.threat_intel_risk,
        graph_risk=payload.graph_risk,
        explanation_summary=payload.explanation_summary,
        recommended_action=payload.recommended_action,
        analyst_feedback=payload.analyst_feedback,
        analyst_comments=payload.analyst_comments,
    )
    return report
