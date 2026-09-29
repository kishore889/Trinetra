"""
TRINETRA — Real-Time Gmail Event Monitoring Engine

Production Path:
Gmail -> Gmail Watch -> Google Cloud Pub/Sub -> TRINETRA Webhook -> Gmail History API -> Ingestion Pipeline

Local Development Fallback:
Polling via `messages.list(q="newer_than:1d")` when Pub/Sub is not configured.
Polling is clearly designated as a development fallback, not production architecture.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import EmailProcessingError, ProviderUnavailableError
from app.core.logging import logger
from app.models import GmailAccount, Email
from app.services.email_parser import parse_gmail_api_message
from app.services.email_ingestion import persist_parsed_email
from app.services.gmail_oauth import refresh_access_token_if_needed

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"


# ==================================================
# 1. Production Gmail Watch Registration & Renewal
# ==================================================

async def setup_gmail_watch(account: GmailAccount, db: Session) -> Dict[str, Any]:
    """
    Registers a push watch notification with the Gmail API targeting Google Cloud Pub/Sub.
    POST https://gmail.googleapis.com/gmail/v1/users/me/watch
    Payload:
    {
      "topicName": "projects/{project}/topics/{topic}",
      "labelIds": ["INBOX"]
    }
    Gmail watches automatically expire after 7 days.
    """
    if not settings.pubsub_configured:
        raise ProviderUnavailableError("Google Cloud Pub/Sub is not configured in TRINETRA settings.")

    token = await refresh_access_token_if_needed(account, db)
    if not token:
        raise EmailProcessingError(str(account.id), "Valid access token unavailable for watch setup.")

    url = f"{GMAIL_API_BASE}/watch"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "topicName": settings.GOOGLE_PUBSUB_TOPIC,
        "labelIds": ["INBOX"],
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code != 200:
            logger.error("gmail_watch_setup_failed", status=resp.status_code, body=resp.text)
            raise EmailProcessingError(str(account.id), f"Failed to register Gmail Watch: {resp.text}")

        data = resp.json()
        history_id = data.get("historyId")
        # Gmail expiration is Unix timestamp in ms (~7 days)
        expiration_ms = int(data.get("expiration", "0"))
        expiration_dt = (
            datetime.fromtimestamp(expiration_ms / 1000.0, tz=timezone.utc)
            if expiration_ms
            else datetime.now(timezone.utc) + timedelta(days=7)
        )

        account.history_id = str(history_id)
        account.watch_expiration = expiration_dt
        db.commit()

        logger.info(
            "gmail_watch_registered",
            account_id=str(account.id),
            history_id=history_id,
            expiration=expiration_dt.isoformat(),
        )
        return data


async def renew_watch_if_expiring_soon(account: GmailAccount, db: Session) -> bool:
    """
    Checks if Gmail watch expires within 24 hours and triggers renewal.
    """
    if not account.watch_expiration:
        return False

    now = datetime.now(timezone.utc)
    if account.watch_expiration - now < timedelta(hours=24):
        try:
            await setup_gmail_watch(account, db)
            return True
        except Exception as e:
            logger.error("watch_auto_renewal_failed", account_id=str(account.id), error=str(e))
            return False
    return False


# ==================================================
# 2. History API Synchronization (Delta Sync)
# ==================================================

async def sync_gmail_history(account: GmailAccount, new_history_id: str, db: Session) -> List[str]:
    """
    Synchronizes newly added messages since the last known history_id using the Gmail History API.
    GET https://gmail.googleapis.com/gmail/v1/users/me/history?startHistoryId={lastHistoryId}&historyTypes=messageAdded
    """
    token = await refresh_access_token_if_needed(account, db)
    if not token:
        return []

    start_history_id = account.history_id or new_history_id
    url = f"{GMAIL_API_BASE}/history?startHistoryId={start_history_id}&historyTypes=messageAdded"
    headers = {"Authorization": f"Bearer {token}"}

    ingested_msg_ids = []
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 404:
            # History ID out of date; re-baseline
            account.history_id = str(new_history_id)
            db.commit()
            return []

        if resp.status_code != 200:
            logger.error("gmail_history_sync_failed", status=resp.status_code, body=resp.text)
            return []

        data = resp.json()
        history_records = data.get("history", [])

        for record in history_records:
            messages_added = record.get("messagesAdded", [])
            for item in messages_added:
                msg = item.get("message", {})
                msg_id = msg.get("id")
                if msg_id:
                    # Ingest new message
                    try:
                        fetched_json = await fetch_gmail_message_full(account, msg_id, token)
                        if fetched_json:
                            parsed = parse_gmail_api_message(fetched_json)
                            email_rec, created = persist_parsed_email(db, account, parsed)
                            if created:
                                ingested_msg_ids.append(email_rec.message_id)
                    except Exception as err:
                        logger.error("history_message_ingest_error", msg_id=msg_id, error=str(err))

        # Update last known history ID
        account.history_id = str(new_history_id)
        db.commit()

    return ingested_msg_ids


async def fetch_gmail_message_full(account: GmailAccount, msg_id: str, token: str) -> Optional[Dict[str, Any]]:
    """Fetches a full Gmail message representation."""
    url = f"{GMAIL_API_BASE}/messages/{msg_id}?format=full"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            return resp.json()
    return None


# ==================================================
# 3. Local Polling Fallback (Development Only)
# ==================================================

async def poll_recent_messages_fallback(account: GmailAccount, db: Session, max_results: int = 10) -> List[str]:
    """
    LOCAL DEVELOPMENT FALLBACK ONLY.
    Polls the most recent messages when Google Cloud Pub/Sub is not configured.
    NOTE: Polling is not equivalent to production push architecture (Watch + Pub/Sub).
    """
    token = await refresh_access_token_if_needed(account, db)
    if not token:
        return []

    url = f"{GMAIL_API_BASE}/messages?maxResults={max_results}&q=label:INBOX"
    headers = {"Authorization": f"Bearer {token}"}

    new_ingested = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            logger.warning("dev_polling_failed", status=resp.status_code, body=resp.text)
            return []

        data = resp.json()
        messages = data.get("messages", [])

        for m in messages:
            msg_id = m.get("id")
            if not msg_id:
                continue

            # Skip if already ingested (idempotency check)
            existing = db.query(Email).filter(Email.message_id == msg_id).first()
            if existing:
                continue

            try:
                fetched_json = await fetch_gmail_message_full(account, msg_id, token)
                if fetched_json:
                    parsed = parse_gmail_api_message(fetched_json)
                    _, created = persist_parsed_email(db, account, parsed)
                    if created:
                        new_ingested.append(parsed.message_id)
            except Exception as err:
                logger.error("polling_ingest_error", msg_id=msg_id, error=str(err))

    return new_ingested
