"""
TRINETRA — Pydantic Schemas
Defines request and response schemas for system health, emails, detections, and feedback.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models import Decision, EmailState, FeedbackClassification, IncidentStatus, Severity


# ==================================================
# Base Config Schema
# ==================================================

class TRINETRABaseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ==================================================
# Health Schemas
# ==================================================

class HealthResponse(TRINETRABaseModel):
    service: str = "TRINETRA"
    status: str = "healthy"
    version: str
    environment: str
    database_connected: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    active_layers: List[str]


# ==================================================
# Email Schemas
# ==================================================

class EmailBase(TRINETRABaseModel):
    message_id: str
    thread_id: Optional[str] = None
    sender: str
    sender_domain: str
    recipient: str
    subject: str
    received_at: datetime
    state: EmailState = EmailState.RECEIVED


class EmailCreate(EmailBase):
    gmail_account_id: uuid.UUID
    raw_headers: Optional[Dict[str, Any]] = None


class EmailRead(EmailBase):
    id: uuid.UUID
    gmail_account_id: uuid.UUID
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# ==================================================
# Risk & Detection Schemas
# ==================================================

class RiskSignalRead(TRINETRABaseModel):
    id: uuid.UUID
    layer: str
    signal_type: str
    score: float
    description: str
    metadata_payload: Optional[Dict[str, Any]] = None


class DetectionRead(TRINETRABaseModel):
    id: uuid.UUID
    email_id: uuid.UUID
    content_risk: float
    url_risk: float
    identity_risk: float
    threat_intel_risk: float
    graph_risk: float
    final_risk_score: float
    severity: Severity
    decision: Decision
    confidence: float
    explanation_summary: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    recommended_action: Optional[str] = None
    created_at: datetime
    risk_signals: List[RiskSignalRead] = []


# ==================================================
# Feedback Schemas
# ==================================================

class FeedbackCreate(TRINETRABaseModel):
    classification: FeedbackClassification
    comments: Optional[str] = None


class FeedbackRead(TRINETRABaseModel):
    id: uuid.UUID
    detection_id: uuid.UUID
    analyst_id: uuid.UUID
    classification: FeedbackClassification
    comments: Optional[str] = None
    reviewed_at: datetime
