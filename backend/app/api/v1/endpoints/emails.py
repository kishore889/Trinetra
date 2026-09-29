"""
TRINETRA — Email Ingestion & Live Feeds Endpoints

GET  /api/v1/emails        -> Lists ingested emails with state, urls, and signals
GET  /api/v1/emails/{id}   -> Detailed metadata of specific ingested email
POST /api/v1/emails/ingest-raw -> Ingests raw RFC 822 MIME bytes directly (for testing/simulations)
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, UploadFile, File, status, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Email, EmailState, EmailUrl, GmailAccount, User
from app.services.email_parser import parse_raw_mime
from app.services.email_ingestion import persist_parsed_email

router = APIRouter()


class IngestedEmailSummary(BaseModel):
    id: str
    message_id: str
    sender: str
    sender_domain: str
    recipient: str
    subject: str
    received_at: str
    state: str
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    urls_count: int = 0
    attachments_count: int = 0


class IngestedEmailDetail(IngestedEmailSummary):
    urls: List[str] = []
    body_snippet: Optional[str] = None


@router.get("", response_model=List[IngestedEmailSummary])
def list_emails(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Returns chronologically ordered list of ingested emails for SOC live view."""
    emails = (
        db.query(Email)
        .order_by(Email.received_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    result = []
    for em in emails:
        headers = em.raw_headers or {}
        result.append(
            IngestedEmailSummary(
                id=str(em.id),
                message_id=em.message_id,
                sender=em.sender,
                sender_domain=em.sender_domain,
                recipient=em.recipient,
                subject=em.subject,
                received_at=em.received_at.isoformat(),
                state=em.state.value if hasattr(em.state, "value") else str(em.state),
                spf_result=em.spf_result,
                dkim_result=em.dkim_result,
                dmarc_result=em.dmarc_result,
                urls_count=len(em.urls),
                attachments_count=len(headers.get("attachments", [])),
            )
        )
    return result


@router.get("/{email_id}", response_model=IngestedEmailDetail)
def get_email_detail(email_id: str, db: Session = Depends(get_db)):
    """Fetches complete parsed email details by ID."""
    try:
        val_id = uuid.UUID(email_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid email UUID")

    em = db.query(Email).filter(Email.id == val_id).first()
    if not em:
        raise HTTPException(status_code=404, detail="Email not found")

    headers = em.raw_headers or {}
    return IngestedEmailDetail(
        id=str(em.id),
        message_id=em.message_id,
        sender=em.sender,
        sender_domain=em.sender_domain,
        recipient=em.recipient,
        subject=em.subject,
        received_at=em.received_at.isoformat(),
        state=em.state.value if hasattr(em.state, "value") else str(em.state),
        spf_result=em.spf_result,
        dkim_result=em.dkim_result,
        dmarc_result=em.dmarc_result,
        urls_count=len(em.urls),
        attachments_count=len(headers.get("attachments", [])),
        urls=[u.raw_url for u in em.urls],
        body_snippet=headers.get("body_snippet"),
    )


@router.post("/ingest-raw", response_model=IngestedEmailDetail, status_code=status.HTTP_201_CREATED)
async def ingest_raw_email(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Ingests and parses raw RFC 822 (.eml) MIME content.
    Demonstrates zero-execution safe MIME parsing and database persistence.
    """
    raw_content = await file.read()
    if not raw_content:
        raise HTTPException(status_code=400, detail="Empty file payload")

    # Get active account or create local dev inbox account
    account = db.query(GmailAccount).first()
    if not account:
        user = db.query(User).first()
        if not user:
            user = User(
                email="soc@trinetra.ai",
                hashed_password="local_password_hash",
                full_name="SOC Admin",
            )
            db.add(user)
            db.flush()

        account = GmailAccount(
            user_id=user.id,
            email_address="soc-inbox@trinetra.ai",
        )
        db.add(account)
        db.commit()
        db.refresh(account)

    parsed = parse_raw_mime(raw_content)
    email_rec, created = persist_parsed_email(db, account, parsed)

    headers = email_rec.raw_headers or {}
    return IngestedEmailDetail(
        id=str(email_rec.id),
        message_id=email_rec.message_id,
        sender=email_rec.sender,
        sender_domain=email_rec.sender_domain,
        recipient=email_rec.recipient,
        subject=email_rec.subject,
        received_at=email_rec.received_at.isoformat(),
        state=email_rec.state.value if hasattr(email_rec.state, "value") else str(email_rec.state),
        spf_result=email_rec.spf_result,
        dkim_result=email_rec.dkim_result,
        dmarc_result=email_rec.dmarc_result,
        urls_count=len(email_rec.urls),
        attachments_count=len(headers.get("attachments", [])),
        urls=[u.raw_url for u in email_rec.urls],
        body_snippet=headers.get("body_snippet"),
    )
