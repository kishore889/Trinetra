"""
TRINETRA — Security Audit Logging Service

Provides structured, tamper-evident security audit logging for authentication,
authorization events, quarantine responses, and settings changes. Automatically
redacts sensitive fields (passwords, tokens, API keys).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.core.security import sanitize_log_value
from app.models import ActionAudit

logger = logging.getLogger("trinetra.audit")

_SENSITIVE_KEYS = {
    "password", "hashed_password", "token", "access_token", "refresh_token",
    "secret", "api_key", "authorization", "cookie", "client_secret"
}


def redact_sensitive_dict(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Recursively redact sensitive key values in dictionaries for safe logging."""
    if not data or not isinstance(data, dict):
        return {}

    redacted = {}
    for k, v in data.items():
        if k.lower() in _SENSITIVE_KEYS:
            redacted[k] = "***REDACTED***"
        elif isinstance(v, dict):
            redacted[k] = redact_sensitive_dict(v)
        elif isinstance(v, list):
            redacted[k] = [
                redact_sensitive_dict(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            redacted[k] = v
    return redacted


def log_security_event(
    db: Session,
    event_type: str,
    actor: str,
    target: str,
    reason: str,
    details: Optional[Dict[str, Any]] = None,
    previous_state: str = "UNKNOWN",
    new_state: str = "COMPLETED",
) -> ActionAudit:
    """
    Log a structured security audit event to DB and structured logger.
    """
    clean_actor = sanitize_log_value(actor)
    clean_reason = sanitize_log_value(reason, max_length=200)
    clean_details = redact_sensitive_dict(details)

    logger.info(
        f"AUDIT_EVENT: type={event_type} actor={clean_actor} target={target} status={new_state}",
        extra={
            "event_type": event_type,
            "actor": clean_actor,
            "target": target,
            "reason": clean_reason,
            "details": clean_details,
        },
    )

    audit_entry = ActionAudit(
        action=event_type,
        actor=clean_actor,
        target_email=target,
        message_id=target,
        reason=clean_reason,
        previous_state=previous_state,
        new_state=new_state,
        details=clean_details,
    )
    db.add(audit_entry)
    db.commit()
    return audit_entry
