"""
TRINETRA — Phase 15: Human-in-the-Loop Review Queue API

Endpoints:
  GET  /api/v1/review/queue           → Detections pending analyst review
  GET  /api/v1/review/queue/{id}      → Full review detail for a single detection
  POST /api/v1/review/{detection_id}  → Submit analyst classification + comment
  GET  /api/v1/review/history         → Paginated feedback history (audit trail)
  GET  /api/v1/review/stats           → Review dashboard statistics
  GET  /api/v1/review/export          → Export feedback as JSON for model improvement

Design rules:
  - Medium-confidence (0.35–0.65) and border-case detections surface in review queue.
  - Review submission is fully audited: who, what, when, why.
  - Export is analyst-initiated ONLY. No automatic retraining from unvalidated feedback.
  - No mock statistics — all figures are derived from the real database.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, and_, or_

from app.db.session import get_db
from app.models import (
    Email,
    EmailState,
    Detection,
    Feedback,
    FeedbackClassification,
    RiskSignal,
    Severity,
    Decision,
    User,
    ActionAudit,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Constants — Review Queue Criteria
# ---------------------------------------------------------------------------

# Emails meeting ANY of these criteria surface in the review queue:
#  1. Confidence is below CONFIDENCE_THRESHOLD (uncertain detections)
#  2. Decision is WARN (inherently medium-confidence)
#  3. Email is in REVIEW state (manually flagged)
CONFIDENCE_THRESHOLD = 0.70   # detections with confidence < this are reviewable
QUEUE_LIMIT_DEFAULT = 100


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------

class RiskSignalItem(BaseModel):
    layer: str
    signal_type: str
    score: float
    description: str
    metadata_payload: Optional[Dict[str, Any]] = None


class ReviewQueueItem(BaseModel):
    """Summary item shown in the queue list."""
    email_id: str
    detection_id: str
    message_id: str
    subject: str
    sender: str
    sender_domain: str
    recipient: str
    received_at: str
    state: str
    final_risk_score: float
    severity: str
    decision: str
    confidence: float
    explanation_summary: Optional[str] = None
    recommended_action: Optional[str] = None
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    urls_count: int = 0
    has_feedback: bool = False
    reviewed_at: Optional[str] = None


class ReviewDetail(BaseModel):
    """Full review context for a single detection — all signals, evidence, metadata."""
    email_id: str
    detection_id: str
    message_id: str
    subject: str
    sender: str
    sender_domain: str
    recipient: str
    received_at: str
    state: str
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    urls: List[str] = []

    # Risk Engine outputs
    final_risk_score: float
    severity: str
    decision: str
    confidence: float
    content_risk: float
    url_risk: float
    identity_risk: float
    threat_intel_risk: float
    graph_risk: float

    # Evidence
    explanation_summary: Optional[str] = None
    recommended_action: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    risk_signals: List[RiskSignalItem] = []

    # Existing feedback if already reviewed
    existing_feedback: Optional["FeedbackRecord"] = None


class FeedbackRecord(BaseModel):
    """Existing analyst feedback on a detection."""
    feedback_id: str
    classification: str
    comments: Optional[str] = None
    analyst_name: Optional[str] = None
    reviewed_at: str
    review_source: str


class SubmitReviewRequest(BaseModel):
    """Analyst review submission payload."""
    classification: str = Field(
        ...,
        description="TRUE_POSITIVE | FALSE_POSITIVE | TRUE_NEGATIVE | FALSE_NEGATIVE"
    )
    comments: Optional[str] = Field(
        None,
        description="Analyst rationale — used for audit trail and future model improvement",
        max_length=4000,
    )
    analyst_name: str = Field(
        default="SOC Analyst",
        description="Name or ID of the reviewing analyst",
        max_length=255,
    )
    review_source: str = Field(
        default="REVIEW_QUEUE",
        description="UI surface originating this review",
        max_length=100,
    )


class SubmitReviewResponse(BaseModel):
    feedback_id: str
    detection_id: str
    email_id: str
    classification: str
    analyst_name: str
    reviewed_at: str
    review_source: str
    audit_ref: str   # ActionAudit ID for external traceability


class ReviewStatsResponse(BaseModel):
    """Dashboard-ready review statistics. All values are derived from the real DB."""
    pending_reviews: int
    reviewed_today: int
    reviewed_total: int
    feedback_distribution: Dict[str, int]
    false_positive_rate: float         # FP / (TP + FP) where TP+FP > 0
    analyst_activity: List[Dict[str, Any]]
    review_queue_by_severity: Dict[str, int]
    avg_confidence_in_queue: float


class FeedbackHistoryItem(BaseModel):
    feedback_id: str
    detection_id: str
    email_id: str
    subject: str
    sender: str
    final_risk_score: float
    severity: str
    decision: str
    classification: str
    comments: Optional[str] = None
    analyst_name: Optional[str] = None
    reviewed_at: str
    review_source: str


ReviewDetail.model_rebuild()


# ---------------------------------------------------------------------------
# Helper: resolve analyst (system user for solo/API use)
# ---------------------------------------------------------------------------

def _get_or_create_system_analyst(db: Session) -> User:
    """
    Returns the system SOC analyst user.
    Creates one if no users exist (supports standalone/API usage without auth).
    """
    analyst = db.query(User).filter(User.is_active == True).first()  # noqa: E712
    if not analyst:
        analyst = User(
            email="soc-analyst@trinetra.ai",
            hashed_password="system_placeholder",
            full_name="SOC Analyst",
            role="analyst",
            is_active=True,
        )
        db.add(analyst)
        db.flush()
    return analyst


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=ReviewStatsResponse, summary="Review queue dashboard statistics")
def get_review_stats(db: Session = Depends(get_db)):
    """
    Returns real review queue statistics for the SOC dashboard.
    All metrics are derived directly from the database — no manufactured values.
    """
    # ── Pending queue: unreviewed detections that meet review criteria ──
    pending_q = (
        db.query(Detection)
        .join(Email, Detection.email_id == Email.id)
        .outerjoin(Feedback, Feedback.detection_id == Detection.id)
        .filter(
            Feedback.id == None,  # noqa: E711 — no feedback yet
            or_(
                Detection.confidence < CONFIDENCE_THRESHOLD,
                Detection.decision == Decision.WARN,
                Email.state == EmailState.REVIEW,
            )
        )
    )
    pending_reviews = pending_q.count()

    # ── Reviewed today ──
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    reviewed_today = (
        db.query(func.count(Feedback.id))
        .filter(Feedback.reviewed_at >= today_start)
        .scalar() or 0
    )

    # ── Total reviewed ──
    reviewed_total = db.query(func.count(Feedback.id)).scalar() or 0

    # ── Feedback distribution ──
    dist_rows = (
        db.query(Feedback.classification, func.count(Feedback.id))
        .group_by(Feedback.classification)
        .all()
    )
    feedback_distribution: Dict[str, int] = {
        "TRUE_POSITIVE": 0,
        "FALSE_POSITIVE": 0,
        "TRUE_NEGATIVE": 0,
        "FALSE_NEGATIVE": 0,
    }
    for cls, cnt in dist_rows:
        key = cls.value if hasattr(cls, "value") else str(cls)
        feedback_distribution[key] = cnt

    # ── False Positive Rate ──
    tp = feedback_distribution.get("TRUE_POSITIVE", 0)
    fp = feedback_distribution.get("FALSE_POSITIVE", 0)
    false_positive_rate = round(fp / (tp + fp), 4) if (tp + fp) > 0 else 0.0

    # ── Analyst activity: last 10 distinct analyst names ──
    analyst_rows = (
        db.query(Feedback.analyst_name, func.count(Feedback.id), func.max(Feedback.reviewed_at))
        .group_by(Feedback.analyst_name)
        .order_by(desc(func.max(Feedback.reviewed_at)))
        .limit(10)
        .all()
    )
    analyst_activity = [
        {
            "analyst_name": row[0] or "Unknown Analyst",
            "reviews_submitted": row[1],
            "last_active": row[2].isoformat() if row[2] else None,
        }
        for row in analyst_rows
    ]

    # ── Queue breakdown by severity ──
    pending_with_sev = pending_q.with_entities(Detection.severity, func.count(Detection.id)).group_by(Detection.severity).all()
    review_queue_by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for sev, cnt in pending_with_sev:
        key = sev.value if hasattr(sev, "value") else str(sev)
        review_queue_by_severity[key] = cnt

    # ── Average confidence in queue ──
    avg_conf_result = pending_q.with_entities(func.avg(Detection.confidence)).scalar()
    avg_confidence_in_queue = round(float(avg_conf_result), 3) if avg_conf_result else 0.0

    return ReviewStatsResponse(
        pending_reviews=pending_reviews,
        reviewed_today=reviewed_today,
        reviewed_total=reviewed_total,
        feedback_distribution=feedback_distribution,
        false_positive_rate=false_positive_rate,
        analyst_activity=analyst_activity,
        review_queue_by_severity=review_queue_by_severity,
        avg_confidence_in_queue=avg_confidence_in_queue,
    )


@router.get("/queue", response_model=List[ReviewQueueItem], summary="Get pending analyst review queue")
def get_review_queue(
    include_reviewed: bool = False,
    severity: Optional[str] = Query(None, description="Filter by severity: LOW|MEDIUM|HIGH|CRITICAL"),
    limit: int = Query(QUEUE_LIMIT_DEFAULT, le=500),
    db: Session = Depends(get_db),
):
    """
    Returns detections queued for analyst review.

    Review criteria:
      - Confidence below 0.70 (uncertain detection)
      - Decision is WARN (medium-confidence warning)
      - Email manually placed in REVIEW state

    Optionally includes already-reviewed items for context.
    """
    query = (
        db.query(Detection, Email, Feedback)
        .join(Email, Detection.email_id == Email.id)
        .outerjoin(Feedback, Feedback.detection_id == Detection.id)
        .filter(
            or_(
                Detection.confidence < CONFIDENCE_THRESHOLD,
                Detection.decision == Decision.WARN,
                Email.state == EmailState.REVIEW,
            )
        )
    )

    if not include_reviewed:
        query = query.filter(Feedback.id == None)  # noqa: E711

    if severity:
        try:
            sev_enum = Severity(severity.upper())
            query = query.filter(Detection.severity == sev_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity '{severity}'")

    query = query.order_by(desc(Detection.final_risk_score)).limit(limit)
    rows = query.all()

    items = []
    for det, em, fb in rows:
        items.append(ReviewQueueItem(
            email_id=str(em.id),
            detection_id=str(det.id),
            message_id=em.message_id,
            subject=em.subject,
            sender=em.sender,
            sender_domain=em.sender_domain,
            recipient=em.recipient,
            received_at=em.received_at.isoformat(),
            state=em.state.value if hasattr(em.state, "value") else str(em.state),
            final_risk_score=det.final_risk_score,
            severity=det.severity.value if hasattr(det.severity, "value") else str(det.severity),
            decision=det.decision.value if hasattr(det.decision, "value") else str(det.decision),
            confidence=det.confidence,
            explanation_summary=det.explanation_summary,
            recommended_action=det.recommended_action,
            spf_result=em.spf_result,
            dkim_result=em.dkim_result,
            dmarc_result=em.dmarc_result,
            urls_count=len(em.urls) if em.urls else 0,
            has_feedback=fb is not None,
            reviewed_at=fb.reviewed_at.isoformat() if fb else None,
        ))

    return items


@router.get("/queue/{detection_id}", response_model=ReviewDetail, summary="Full review context for a detection")
def get_review_detail(detection_id: str, db: Session = Depends(get_db)):
    """
    Returns the full review context for a single detection:
    email, signals, evidence, risk scores, URLs, existing feedback.
    """
    try:
        uid = uuid.UUID(detection_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid detection UUID.")

    det = db.query(Detection).filter(Detection.id == uid).first()
    if not det:
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found.")

    em = det.email
    signals = [
        RiskSignalItem(
            layer=s.layer,
            signal_type=s.signal_type,
            score=s.score,
            description=s.description,
            metadata_payload=s.metadata_payload,
        )
        for s in (det.risk_signals or [])
    ]

    existing_fb = None
    if det.feedback:
        fb = det.feedback
        existing_fb = FeedbackRecord(
            feedback_id=str(fb.id),
            classification=fb.classification.value if hasattr(fb.classification, "value") else str(fb.classification),
            comments=fb.comments,
            analyst_name=fb.analyst_name,
            reviewed_at=fb.reviewed_at.isoformat(),
            review_source=fb.review_source,
        )

    urls = [u.raw_url for u in (em.urls or [])]

    return ReviewDetail(
        email_id=str(em.id),
        detection_id=str(det.id),
        message_id=em.message_id,
        subject=em.subject,
        sender=em.sender,
        sender_domain=em.sender_domain,
        recipient=em.recipient,
        received_at=em.received_at.isoformat(),
        state=em.state.value if hasattr(em.state, "value") else str(em.state),
        spf_result=em.spf_result,
        dkim_result=em.dkim_result,
        dmarc_result=em.dmarc_result,
        urls=urls,
        final_risk_score=det.final_risk_score,
        severity=det.severity.value if hasattr(det.severity, "value") else str(det.severity),
        decision=det.decision.value if hasattr(det.decision, "value") else str(det.decision),
        confidence=det.confidence,
        content_risk=det.content_risk,
        url_risk=det.url_risk,
        identity_risk=det.identity_risk,
        threat_intel_risk=det.threat_intel_risk,
        graph_risk=det.graph_risk,
        explanation_summary=det.explanation_summary,
        recommended_action=det.recommended_action,
        evidence=det.evidence,
        risk_signals=signals,
        existing_feedback=existing_fb,
    )


@router.post("/{detection_id}", response_model=SubmitReviewResponse, status_code=status.HTTP_201_CREATED,
             summary="Submit analyst classification for a detection")
def submit_review(
    detection_id: str,
    req: SubmitReviewRequest,
    db: Session = Depends(get_db),
):
    """
    Records an analyst's classification for a detection.

    Audit trail: every review creates an ActionAudit record capturing
    WHO (analyst_name), WHAT (classification), WHEN (reviewed_at), WHY (comments).

    IMPORTANT: Feedback is stored for future model improvement analysis only.
    It does NOT automatically retrain the production model.
    """
    try:
        uid = uuid.UUID(detection_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid detection UUID.")

    det = db.query(Detection).filter(Detection.id == uid).first()
    if not det:
        raise HTTPException(status_code=404, detail=f"Detection {detection_id} not found.")

    # Validate classification
    try:
        cls_enum = FeedbackClassification(req.classification.upper())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid classification '{req.classification}'. "
                   f"Must be: TRUE_POSITIVE | FALSE_POSITIVE | TRUE_NEGATIVE | FALSE_NEGATIVE"
        )

    # Get or create system analyst
    analyst = _get_or_create_system_analyst(db)

    now = datetime.now(timezone.utc)

    if det.feedback:
        # Update existing feedback (analyst correcting a previous review)
        fb = det.feedback
        old_classification = fb.classification.value if hasattr(fb.classification, "value") else str(fb.classification)
        fb.classification = cls_enum
        fb.comments = req.comments
        fb.analyst_name = req.analyst_name
        fb.reviewed_at = now
        fb.review_source = req.review_source
        db.flush()
    else:
        # Create new feedback record
        old_classification = "UNREVIEWED"
        fb = Feedback(
            detection_id=det.id,
            analyst_id=analyst.id,
            analyst_name=req.analyst_name,
            classification=cls_enum,
            comments=req.comments,
            reviewed_at=now,
            review_source=req.review_source,
        )
        db.add(fb)
        db.flush()

    # ── Audit trail: full who/what/when/why record ──
    audit = ActionAudit(
        email_id=det.email_id,
        message_id=det.email.message_id if det.email else "UNKNOWN",
        action=f"ANALYST_REVIEW_{req.classification.upper()}",
        actor=req.analyst_name,
        reason=req.comments or f"Analyst classified detection as {req.classification}",
        previous_state=old_classification,
        new_state=req.classification.upper(),
        target_email=det.email.sender if det.email else None,
        details={
            "detection_id": str(det.id),
            "final_risk_score": det.final_risk_score,
            "severity": det.severity.value if hasattr(det.severity, "value") else str(det.severity),
            "original_decision": det.decision.value if hasattr(det.decision, "value") else str(det.decision),
            "classification": req.classification.upper(),
            "confidence": det.confidence,
            "review_source": req.review_source,
            "note": "Feedback stored for analyst review only. No automatic model retraining.",
        },
    )
    db.add(audit)
    db.commit()
    db.refresh(fb)
    db.refresh(audit)

    logger.info(
        "analyst_review_submitted",
        analyst=req.analyst_name,
        detection_id=detection_id,
        classification=req.classification,
        audit_id=str(audit.id),
    )

    return SubmitReviewResponse(
        feedback_id=str(fb.id),
        detection_id=str(det.id),
        email_id=str(det.email_id),
        classification=cls_enum.value,
        analyst_name=req.analyst_name,
        reviewed_at=fb.reviewed_at.isoformat(),
        review_source=req.review_source,
        audit_ref=str(audit.id),
    )


@router.get("/history", response_model=List[FeedbackHistoryItem], summary="Analyst review history (audit trail)")
def get_review_history(
    limit: int = Query(200, le=1000),
    classification: Optional[str] = Query(None),
    analyst_name: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Full auditable history of all analyst reviews.
    Supports filtering by classification and analyst name.
    """
    query = (
        db.query(Feedback, Detection, Email)
        .join(Detection, Feedback.detection_id == Detection.id)
        .join(Email, Detection.email_id == Email.id)
        .order_by(desc(Feedback.reviewed_at))
    )

    if classification:
        try:
            cls_enum = FeedbackClassification(classification.upper())
            query = query.filter(Feedback.classification == cls_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid classification '{classification}'")

    if analyst_name:
        query = query.filter(Feedback.analyst_name.ilike(f"%{analyst_name}%"))

    rows = query.limit(limit).all()

    return [
        FeedbackHistoryItem(
            feedback_id=str(fb.id),
            detection_id=str(det.id),
            email_id=str(em.id),
            subject=em.subject,
            sender=em.sender,
            final_risk_score=det.final_risk_score,
            severity=det.severity.value if hasattr(det.severity, "value") else str(det.severity),
            decision=det.decision.value if hasattr(det.decision, "value") else str(det.decision),
            classification=fb.classification.value if hasattr(fb.classification, "value") else str(fb.classification),
            comments=fb.comments,
            analyst_name=fb.analyst_name,
            reviewed_at=fb.reviewed_at.isoformat(),
            review_source=fb.review_source,
        )
        for fb, det, em in rows
    ]


@router.get("/export", summary="Export feedback for model improvement analysis")
def export_feedback(
    format: str = Query("json", description="json or csv"),
    db: Session = Depends(get_db),
):
    """
    Exports all analyst feedback as JSON or CSV for future model improvement analysis.

    IMPORTANT SAFETY RULE:
      This export is for offline analysis and validation only.
      TRINETRA does NOT automatically retrain the production model from this data.
      All retraining requires explicit offline validation and deployment approval.
    """
    rows = (
        db.query(Feedback, Detection, Email)
        .join(Detection, Feedback.detection_id == Detection.id)
        .join(Email, Detection.email_id == Email.id)
        .order_by(desc(Feedback.reviewed_at))
        .all()
    )

    records = []
    for fb, det, em in rows:
        records.append({
            "feedback_id": str(fb.id),
            "detection_id": str(det.id),
            "email_id": str(em.id),
            "message_id": em.message_id,
            "sender": em.sender,
            "sender_domain": em.sender_domain,
            "subject": em.subject,
            "received_at": em.received_at.isoformat(),
            "spf_result": em.spf_result,
            "dkim_result": em.dkim_result,
            "dmarc_result": em.dmarc_result,
            "final_risk_score": det.final_risk_score,
            "severity": det.severity.value if hasattr(det.severity, "value") else str(det.severity),
            "original_decision": det.decision.value if hasattr(det.decision, "value") else str(det.decision),
            "confidence": det.confidence,
            "content_risk": det.content_risk,
            "url_risk": det.url_risk,
            "identity_risk": det.identity_risk,
            "threat_intel_risk": det.threat_intel_risk,
            "graph_risk": det.graph_risk,
            "analyst_classification": fb.classification.value if hasattr(fb.classification, "value") else str(fb.classification),
            "analyst_name": fb.analyst_name,
            "analyst_comments": fb.comments,
            "reviewed_at": fb.reviewed_at.isoformat(),
            "review_source": fb.review_source,
            "export_note": "For offline model improvement analysis only. Not for automated retraining.",
        })

    if format.lower() == "csv":
        if not records:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["No feedback records available."])
            output.seek(0)
        else:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=list(records[0].keys()))
            writer.writeheader()
            writer.writerows(records)
            output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=trinetra_feedback_export.csv"},
        )

    # JSON export
    export_payload = {
        "export_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_records": len(records),
            "system": "TRINETRA SOC Intelligence Platform",
            "export_purpose": "Analyst feedback for offline model improvement analysis",
            "safety_note": (
                "This export must NOT be used for automated production model retraining "
                "without explicit validation, offline testing, and deployment approval."
            ),
        },
        "feedback_records": records,
    }
    json_bytes = json.dumps(export_payload, indent=2).encode("utf-8")
    return StreamingResponse(
        iter([json_bytes]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=trinetra_feedback_export.json"},
    )
