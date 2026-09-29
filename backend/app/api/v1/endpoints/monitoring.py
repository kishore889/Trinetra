"""
TRINETRA — Gmail Webhook & Monitoring Status Endpoints

POST /api/v1/monitor/webhook     -> Google Cloud Pub/Sub Push Webhook
POST /api/v1/monitor/watch/setup -> Registers/Renews Gmail Watch
POST /api/v1/monitor/poll        -> Development polling fallback
GET  /api/v1/monitor/status      -> Real monitoring telemetry for SOC dashboard
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import logger
from app.db.session import get_db
from app.models import GmailAccount, Email
from app.services.gmail_monitor import (
    setup_gmail_watch,
    sync_gmail_history,
    poll_recent_messages_fallback,
    renew_watch_if_expiring_soon,
)

router = APIRouter()

# In-memory monitoring event metrics
_MONITORING_METRICS = {
    "last_sync": None,
    "last_event": None,
    "messages_processed": 0,
    "processing_errors": 0,
    "last_error": None,
}


class PubSubMessagePayload(BaseModel):
    message: Dict[str, Any]
    subscription: Optional[str] = None


class MonitoringStatusResponse(BaseModel):
    monitoring_active: bool
    mode: str  # "PUBSUB_PUSH" (production) or "DEV_POLLING" (fallback) or "INACTIVE"
    last_sync: Optional[str] = None
    last_event: Optional[str] = None
    messages_processed: int = 0
    processing_errors: int = 0
    watch_status: str  # "ACTIVE", "EXPIRING_SOON", "EXPIRED", "UNREGISTERED"
    watch_expiry: Optional[str] = None
    history_id: Optional[str] = None
    pubsub_configured: bool = False


@router.get("/status", response_model=MonitoringStatusResponse)
def get_monitoring_status(db: Session = Depends(get_db)):
    """Returns actual real-time telemetry of the Gmail monitoring engine."""
    account = db.query(GmailAccount).filter(GmailAccount.is_active == True).first()
    total_emails = db.query(Email).count()

    if not account:
        return MonitoringStatusResponse(
            monitoring_active=False,
            mode="INACTIVE",
            watch_status="UNREGISTERED",
            pubsub_configured=settings.pubsub_configured,
            messages_processed=total_emails,
        )

    # Determine watch status
    watch_status = "UNREGISTERED"
    watch_expiry_str = None
    if account.watch_expiration:
        watch_expiry_str = account.watch_expiration.isoformat()
        now = datetime.now(timezone.utc)
        if account.watch_expiration < now:
            watch_status = "EXPIRED"
        elif (account.watch_expiration - now).total_seconds() < 86400:
            watch_status = "EXPIRING_SOON"
        else:
            watch_status = "ACTIVE"

    mode = "PUBSUB_PUSH" if (watch_status == "ACTIVE" and settings.pubsub_configured) else "DEV_POLLING"

    return MonitoringStatusResponse(
        monitoring_active=True,
        mode=mode,
        last_sync=_MONITORING_METRICS["last_sync"],
        last_event=_MONITORING_METRICS["last_event"],
        messages_processed=total_emails,
        processing_errors=_MONITORING_METRICS["processing_errors"],
        watch_status=watch_status,
        watch_expiry=watch_expiry_str,
        history_id=account.history_id,
        pubsub_configured=settings.pubsub_configured,
    )


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def pubsub_push_webhook(payload: PubSubMessagePayload, db: Session = Depends(get_db)):
    """
    Receives Google Cloud Pub/Sub Push events notifying of new Gmail inbox events.
    Decodes message data: {"emailAddress": "...", "historyId": "123456"}
    Triggers incremental delta sync via Gmail History API.
    """
    try:
        msg = payload.message
        data_b64 = msg.get("data", "")
        if not data_b64:
            return {"status": "ignored", "reason": "empty_data"}

        decoded_json = json.loads(base64.b64decode(data_b64).decode("utf-8"))
        email_addr = decoded_json.get("emailAddress")
        history_id = decoded_json.get("historyId")

        _MONITORING_METRICS["last_event"] = datetime.now(timezone.utc).isoformat()
        logger.info("pubsub_event_received", email_address=email_addr, history_id=history_id)

        account = db.query(GmailAccount).filter(GmailAccount.email_address == email_addr, GmailAccount.is_active == True).first()
        if not account:
            # Fallback to any active account
            account = db.query(GmailAccount).filter(GmailAccount.is_active == True).first()

        if account and history_id:
            ingested = await sync_gmail_history(account, str(history_id), db)
            _MONITORING_METRICS["last_sync"] = datetime.now(timezone.utc).isoformat()
            _MONITORING_METRICS["messages_processed"] += len(ingested)
            return {"status": "synced", "ingested_count": len(ingested)}

        return {"status": "acknowledged"}
    except Exception as exc:
        _MONITORING_METRICS["processing_errors"] += 1
        _MONITORING_METRICS["last_error"] = str(exc)
        logger.error("pubsub_webhook_error", error=str(exc))
        # Always return 200 to acknowledge Pub/Sub delivery unless catastrophic
        return {"status": "error_recorded", "error": str(exc)}


@router.post("/watch/setup", status_code=status.HTTP_200_OK)
async def register_watch(db: Session = Depends(get_db)):
    """Registers or manually renews Gmail Watch with Google Cloud Pub/Sub."""
    account = db.query(GmailAccount).filter(GmailAccount.is_active == True).first()
    if not account:
        raise HTTPException(status_code=400, detail="No active Gmail account connected. Complete OAuth first.")

    res = await setup_gmail_watch(account, db)
    return {"status": "watch_registered", "details": res}


@router.post("/poll", status_code=status.HTTP_200_OK)
async def trigger_dev_polling(max_results: int = 10, db: Session = Depends(get_db)):
    """
    LOCAL DEVELOPMENT FALLBACK.
    Polls recent inbox messages when Pub/Sub push is unavailable locally.
    """
    account = db.query(GmailAccount).filter(GmailAccount.is_active == True).first()
    if not account:
        raise HTTPException(status_code=400, detail="No active Gmail account connected.")

    ingested = await poll_recent_messages_fallback(account, db, max_results=max_results)
    _MONITORING_METRICS["last_sync"] = datetime.now(timezone.utc).isoformat()
    _MONITORING_METRICS["messages_processed"] += len(ingested)

    return {
        "status": "polled",
        "mode": "DEV_POLLING_FALLBACK",
        "new_messages_ingested": len(ingested),
        "message_ids": ingested,
    }
