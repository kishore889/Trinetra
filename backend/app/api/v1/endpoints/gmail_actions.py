"""
TRINETRA — Phase 13: Gmail Response & Action API Endpoints

Provides REST API endpoints for safe automated and analyst-initiated response actions:
- Auto-apply decision actions (ALLOW -> SAFE, WARN -> WARN, QUARANTINE -> QUARANTINE)
- Analyst actions: quarantine, release, mark safe, review, reprocess
- High-impact confirmation checks
- Permanent deletion rejection (Safety enforcement)
- Action audit trail and summary stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Decision
from app.services import gmail_action_service as action_svc
from app.core.exceptions import SafetyViolationError, ResourceNotFoundError

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic Request & Response Schemas
# ---------------------------------------------------------------------------

class AutoApplyRequest(BaseModel):
    email_id: str = Field(..., description="UUID or message_id of the email")
    decision: str = Field(..., description="Decision from Risk Engine: ALLOW, WARN, QUARANTINE")
    reason: Optional[str] = Field(None, description="Optional reasoning for the action")


class AnalystActionRequest(BaseModel):
    email_id: str = Field(..., description="UUID or message_id of the email")
    actor: str = Field("analyst@trinetra.soc", description="Email or identifier of SOC analyst")
    reason: str = Field("Analyst manual action", description="Detailed reason for analyst intervention")
    confirmed: bool = Field(False, description="Explicit confirmation for high-impact actions (quarantine/release)")


class ActionAuditFilter(BaseModel):
    email_id: Optional[str] = None
    limit: int = Field(50, ge=1, le=500)
    offset: int = Field(0, ge=0)


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@router.post("/auto-apply", response_model=Dict[str, Any], summary="Auto-apply Risk Engine decision action")
async def auto_apply_decision(
    req: AutoApplyRequest,
    db: Session = Depends(get_db),
):
    """
    Apply automated Gmail action based on Risk Engine decision.
    - ALLOW -> TRINETRA/SAFE label
    - WARN -> TRINETRA/WARN label
    - QUARANTINE -> TRINETRA/QUARANTINE label + remove INBOX (controlled quarantine)
    """
    try:
        res = await action_svc.apply_auto_decision_action(
            db=db,
            identifier=req.email_id,
            decision=req.decision,
            reason=req.reason,
        )
        return res
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_444_NOT_FOUND if hasattr(status, 'HTTP_444_NOT_FOUND') else 404, detail=str(e))
    except Exception as e:
        logger.error(f"Error in auto_apply_decision: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/quarantine", response_model=Dict[str, Any], summary="Analyst manual quarantine email")
async def quarantine_email(
    req: AnalystActionRequest,
    db: Session = Depends(get_db),
):
    """
    Quarantine an email (Analyst action).
    High-impact action: Requires `confirmed: true`.
    """
    try:
        res = await action_svc.analyst_quarantine(
            db=db,
            identifier=req.email_id,
            actor=req.actor,
            reason=req.reason,
            confirmed=req.confirmed,
        )
        if res.get("confirmation_required"):
            return res
        return res
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/release", response_model=Dict[str, Any], summary="Analyst release quarantined email")
async def release_email(
    req: AnalystActionRequest,
    db: Session = Depends(get_db),
):
    """
    Release a quarantined email back to INBOX (Analyst action).
    High-impact action: Requires `confirmed: true`.
    """
    try:
        res = await action_svc.analyst_release(
            db=db,
            identifier=req.email_id,
            actor=req.actor,
            reason=req.reason,
            confirmed=req.confirmed,
        )
        if res.get("confirmation_required"):
            return res
        return res
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mark-safe", response_model=Dict[str, Any], summary="Analyst mark email as safe")
async def mark_safe_email(
    req: AnalystActionRequest,
    db: Session = Depends(get_db),
):
    """
    Mark email as SAFE (Analyst action).
    """
    try:
        return await action_svc.analyst_mark_safe(
            db=db,
            identifier=req.email_id,
            actor=req.actor,
            reason=req.reason,
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/review", response_model=Dict[str, Any], summary="Analyst flag email for review")
async def review_email(
    req: AnalystActionRequest,
    db: Session = Depends(get_db),
):
    """
    Flag email for SOC tier-2 review (Analyst action).
    """
    try:
        return await action_svc.analyst_flag_review(
            db=db,
            identifier=req.email_id,
            actor=req.actor,
            reason=req.reason,
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reprocess", response_model=Dict[str, Any], summary="Analyst reprocess email analysis")
async def reprocess_email(
    req: AnalystActionRequest,
    db: Session = Depends(get_db),
):
    """
    Re-run TRINETRA detection pipeline on an email (Analyst action).
    """
    try:
        return await action_svc.analyst_reprocess(
            db=db,
            identifier=req.email_id,
            actor=req.actor,
            reason=req.reason,
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/delete/{email_id}", response_model=Dict[str, Any], summary="Attempt email deletion (Forbidden)")
async def attempt_delete_email(email_id: str):
    """
    Safety Guard Endpoint: Deletion is strictly prohibited in TRINETRA.
    Always returns HTTP 403 Forbidden.
    """
    try:
        action_svc.delete_email_forbidden(email_id)
    except SafetyViolationError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.get("/audit", response_model=List[Dict[str, Any]], summary="Get traceable action audit logs")
def get_action_audit_logs(
    email_id: Optional[str] = Query(None, description="Filter by email UUID or message_id"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """
    Retrieve audit trail entries for response actions.
    """
    return action_svc.get_audit_trail(db=db, email_id=email_id, limit=limit, offset=offset)


@router.get("/summary", response_model=Dict[str, int], summary="Get action summary metrics for UI")
def get_action_summary(db: Session = Depends(get_db)):
    """
    Returns summary stats: Action Taken, Action Pending, Analyst Review, Quarantined, Released.
    """
    return action_svc.get_action_summary_stats(db)


@router.post("/labels/ensure", response_model=Dict[str, str], summary="Ensure TRINETRA labels exist in Gmail")
async def ensure_labels():
    """
    Ensure all TRINETRA labels (SAFE, WARN, QUARANTINE, REVIEW) are created in Gmail.
    """
    return await action_svc.ensure_trinetra_labels()
