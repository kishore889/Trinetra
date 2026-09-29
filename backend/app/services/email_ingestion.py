"""
TRINETRA — Gmail Ingestion & Persistence Service

Manages full ingestion lifecycle:
RECEIVED -> PARSING -> ANALYZING -> ANALYZED -> ACTION_PENDING -> ACTIONED / FAILED

Enforces idempotency using `message_id`.
Persists Email, extracted EmailUrls, and Domains with relational integrity.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple
import httpx
from sqlalchemy.orm import Session

from app.core.exceptions import ResourceAlreadyExistsError, EmailProcessingError
from app.core.logging import logger
from app.models import Domain, Email, EmailState, EmailUrl, GmailAccount
from app.services.email_parser import (
    ParsedEmailData,
    extract_domain_from_url,
    parse_gmail_api_message,
    parse_raw_mime,
)
from app.services.gmail_oauth import refresh_access_token_if_needed

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"


async def fetch_gmail_message_raw(account: GmailAccount, message_id: str, db: Session) -> Dict[str, Any]:
    """Fetch complete RFC 822 raw message bytes from Gmail API using valid credentials."""
    token = await refresh_access_token_if_needed(account, db)
    if not token:
        raise EmailProcessingError(message_id, "Could not acquire valid access token for Gmail account.")

    url = f"{GMAIL_API_BASE}/messages/{message_id}?format=raw"
    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            raise EmailProcessingError(message_id, f"Gmail API error {resp.status_code}: {resp.text}")
        return resp.json()


def persist_parsed_email(
    db: Session,
    gmail_account: GmailAccount,
    parsed: ParsedEmailData,
) -> Tuple[Email, bool]:
    """
    Idempotently persists parsed email into the database with URL and domain relationships.
    Returns (Email, was_created).
    """
    # Duplicate Protection Check (Idempotency Key: message_id)
    existing = db.query(Email).filter(Email.message_id == parsed.message_id).first()
    if existing:
        logger.info("duplicate_message_skipped", message_id=parsed.message_id)
        return existing, False

    # Create Email record in RECEIVED state
    email_record = Email(
        gmail_account_id=gmail_account.id,
        message_id=parsed.message_id,
        thread_id=parsed.thread_id,
        sender=parsed.sender,
        sender_domain=parsed.sender_domain,
        recipient=parsed.recipient,
        subject=parsed.subject,
        received_at=parsed.received_at,
        state=EmailState.RECEIVED,
        spf_result=parsed.spf_result,
        dkim_result=parsed.dkim_result,
        dmarc_result=parsed.dmarc_result,
        raw_headers={
            "headers": parsed.headers_dict,
            "cc": parsed.cc,
            "bcc": parsed.bcc,
            "attachments": [a.model_dump() for a in parsed.attachments],
            "body_snippet": parsed.normalized_body_text[:500] if parsed.normalized_body_text else "",
        },
    )
    db.add(email_record)
    db.flush() # populate email_record.id

    # Advance state to PARSING
    email_record.state = EmailState.PARSING
    db.flush()

    # Persist extracted URLs and link Domain entities
    for raw_url in parsed.extracted_urls:
        domain_name = extract_domain_from_url(raw_url)
        domain_record = None

        if domain_name:
            domain_record = db.query(Domain).filter(Domain.domain_name == domain_name).first()
            if not domain_record:
                domain_record = Domain(
                    domain_name=domain_name,
                    reputation_score=0.0,
                    is_lookalike=False,
                )
                db.add(domain_record)
                db.flush()

        url_record = EmailUrl(
            email_id=email_record.id,
            domain_id=domain_record.id if domain_record else None,
            raw_url=raw_url,
            normalized_url=raw_url.lower().strip(),
            url_risk_score=0.0,
            is_suspicious=False,
        )
        db.add(url_record)

    # Email is now successfully parsed and ready for intelligence layers
    email_record.state = EmailState.ANALYZED
    db.commit()
    db.refresh(email_record)

    logger.info(
        "email_ingested_and_parsed",
        email_id=str(email_record.id),
        message_id=parsed.message_id,
        urls_count=len(parsed.extracted_urls),
        attachments_count=len(parsed.attachments),
    )

    return email_record, True
