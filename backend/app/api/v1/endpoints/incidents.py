"""
TRINETRA — SOC Incident Response Endpoints

GET  /api/v1/incidents -> Lists security incidents created from high-risk phishing detections
GET  /api/v1/incidents/{id} -> Incident details with linked email, threat indicators, and resolution notes
POST /api/v1/incidents/{id}/status -> Updates incident status (OPEN, INVESTIGATING, RESOLVED, CLOSED)
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.session import get_db
from app.models import Incident, IncidentStatus, Severity, Email, User
from app.core.exceptions import ResourceNotFoundError

logger = logging.getLogger(__name__)

router = APIRouter()


class IncidentSummary(BaseModel):
    id: str
    email_id: str
    title: str
    status: str
    severity: str
    summary: Optional[str] = None
    resolution_notes: Optional[str] = None
    created_at: str
    updated_at: str


class IncidentStatusUpdateRequest(BaseModel):
    status: str = Field(..., description="OPEN, INVESTIGATING, RESOLVED, CLOSED")
    resolution_notes: Optional[str] = Field(None, description="Analyst notes explaining incident resolution")


@router.get("", response_model=List[IncidentSummary], summary="List security incidents")
def list_incidents(db: Session = Depends(get_db)):
    """Retrieve list of active SOC security incidents."""
    incidents = db.query(Incident).order_by(desc(Incident.created_at)).all()
    results = []
    for inc in incidents:
        results.append(
            IncidentSummary(
                id=str(inc.id),
                email_id=str(inc.email_id),
                title=inc.title,
                status=inc.status.value if hasattr(inc.status, "value") else str(inc.status),
                severity=inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity),
                summary=inc.summary,
                resolution_notes=inc.resolution_notes,
                created_at=inc.created_at.isoformat() if inc.created_at else "",
                updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
            )
        )
    return results


@router.get("/{incident_id}", response_model=IncidentSummary, summary="Get incident details")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Get incident detail by ID."""
    try:
        uid = uuid.UUID(incident_id)
        inc = db.query(Incident).filter(Incident.id == uid).first()
    except ValueError:
        inc = None

    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    return IncidentSummary(
        id=str(inc.id),
        email_id=str(inc.email_id),
        title=inc.title,
        status=inc.status.value if hasattr(inc.status, "value") else str(inc.status),
        severity=inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity),
        summary=inc.summary,
        resolution_notes=inc.resolution_notes,
        created_at=inc.created_at.isoformat() if inc.created_at else "",
        updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
    )


@router.post("/{incident_id}/status", response_model=IncidentSummary, summary="Update incident status")
def update_incident_status(
    incident_id: str,
    req: IncidentStatusUpdateRequest,
    db: Session = Depends(get_db),
):
    """Update status and resolution notes of an incident."""
    try:
        uid = uuid.UUID(incident_id)
        inc = db.query(Incident).filter(Incident.id == uid).first()
    except ValueError:
        inc = None

    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")

    try:
        new_status = IncidentStatus(req.status.upper())
        inc.status = new_status
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid incident status: {req.status}")

    if req.resolution_notes:
        inc.resolution_notes = req.resolution_notes

    db.commit()
    db.refresh(inc)

    return IncidentSummary(
        id=str(inc.id),
        email_id=str(inc.email_id),
        title=inc.title,
        status=inc.status.value if hasattr(inc.status, "value") else str(inc.status),
        severity=inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity),
        summary=inc.summary,
        resolution_notes=inc.resolution_notes,
        created_at=inc.created_at.isoformat() if inc.created_at else "",
        updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
    )
