"""
TRINETRA — Phase 13: Gmail Response and Action Engine

Enforces safe Gmail actions based on automated risk fusion decisions and analyst interventions.

Safety Rules:
- NEVER permanently delete emails automatically.
- Prefer labeling, warning, controlled quarantine, analyst-approved actions.
- Decisions: ALLOW, WARN, QUARANTINE.
- Required Labels: TRINETRA/SAFE, TRINETRA/WARN, TRINETRA/QUARANTINE, TRINETRA/REVIEW.
- Analyst Actions: quarantine, release, mark safe, review, reprocess.
- High-impact actions require explicit analyst confirmation.
- Traceable audit logging for every single action.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from app.models import Email, EmailState, Decision, ActionAudit
from app.core.exceptions import SafetyViolationError, ResourceNotFoundError

logger = logging.getLogger(__name__)

# Official TRINETRA Gmail Labels
TRINETRA_LABELS = {
    "SAFE": "TRINETRA/SAFE",
    "WARN": "TRINETRA/WARN",
    "QUARANTINE": "TRINETRA/QUARANTINE",
    "REVIEW": "TRINETRA/REVIEW",
}

HIGH_IMPACT_ACTIONS = {"QUARANTINE", "RELEASE", "DELETE"}

GMAIL_LABELS_API_URL = "https://gmail.googleapis.com/gmail/v1/users/me/labels"
GMAIL_MESSAGES_API_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages"


async def ensure_trinetra_labels(access_token: Optional[str] = None) -> Dict[str, str]:
    """
    Ensure all TRINETRA Gmail labels (SAFE, WARN, QUARANTINE, REVIEW) exist on the user's Gmail account.
    Returns a dictionary mapping label name -> label ID.
    If access_token is missing or API call fails, falls back gracefully to standard label name maps.
    """
    label_map: Dict[str, str] = {label: label for label in TRINETRA_LABELS.values()}

    if not access_token:
        return label_map

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(GMAIL_LABELS_API_URL, headers=headers)
            if resp.status_code == 200:
                existing_labels = resp.json().get("labels", [])
                existing_names = {lbl.get("name"): lbl.get("id") for lbl in existing_labels}

                for label_key, label_name in TRINETRA_LABELS.items():
                    if label_name in existing_names:
                        label_map[label_name] = existing_names[label_name]
                    else:
                        # Create missing label via Gmail API
                        create_payload = {
                            "name": label_name,
                            "labelListVisibility": "labelShow",
                            "messageListVisibility": "show",
                        }
                        create_resp = await client.post(GMAIL_LABELS_API_URL, headers=headers, json=create_payload)
                        if create_resp.status_code in (200, 201):
                            new_label = create_resp.json()
                            label_map[label_name] = new_label.get("id", label_name)
                            logger.info(f"Created Gmail label: {label_name} ({new_label.get('id')})")
    except Exception as e:
        logger.warning(f"Failed to query/create Gmail labels via API: {e}. Falling back to default label map.")

    return label_map


async def modify_gmail_message_labels(
    message_id: str,
    add_labels: List[str],
    remove_labels: List[str],
    access_token: Optional[str] = None,
) -> bool:
    """
    Modify labels on a Gmail message (add/remove labels).
    """
    if not access_token or not message_id:
        return False

    url = f"{GMAIL_MESSAGES_API_URL}/{message_id}/modify"
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {
        "addLabelIds": add_labels,
        "removeLabelIds": remove_labels,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                logger.info(f"Successfully modified Gmail labels for message {message_id}: +{add_labels} -{remove_labels}")
                return True
            else:
                logger.warning(f"Gmail modify label API returned status {resp.status_code}: {resp.text}")
    except Exception as e:
        logger.warning(f"Failed to modify Gmail message labels for {message_id}: {e}")
    return False


def _get_email_by_id_or_msg_id(db: Session, identifier: str | uuid.UUID) -> Email:
    """Helper to fetch Email by UUID or message_id."""
    email = None
    if isinstance(identifier, uuid.UUID):
        email = db.query(Email).filter(Email.id == identifier).first()
    else:
        try:
            uid = uuid.UUID(identifier)
            email = db.query(Email).filter(Email.id == uid).first()
        except (ValueError, TypeError):
            email = None

    if not email:
        email = db.query(Email).filter(Email.message_id == str(identifier)).first()

    if not email:
        raise ResourceNotFoundError(f"Email '{identifier}' not found in TRINETRA database.")

    return email



def record_action_audit(
    db: Session,
    email: Email,
    action: str,
    actor: str,
    reason: str,
    previous_state: str,
    new_state: str,
    details: Optional[Dict[str, Any]] = None,
) -> ActionAudit:
    """Record a traceable audit log entry for any response action."""
    audit = ActionAudit(
        email_id=email.id,
        message_id=email.message_id,
        action=action,
        actor=actor,
        reason=reason,
        previous_state=previous_state,
        new_state=new_state,
        target_email=email.recipient,
        details=details or {},
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)
    return audit


async def apply_auto_decision_action(
    db: Session,
    identifier: str,
    decision: str | Decision,
    reason: Optional[str] = None,
    access_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Apply automated response action based on Risk Engine decision (ALLOW, WARN, QUARANTINE).
    """
    email = _get_email_by_id_or_msg_id(db, identifier)
    dec_val = decision.value if isinstance(decision, Decision) else str(decision).upper()

    prev_state = email.state.value if hasattr(email.state, "value") else str(email.state)
    add_labels: List[str] = []
    remove_labels: List[str] = []

    if dec_val == Decision.ALLOW.value:
        new_state = EmailState.SAFE
        action_name = "AUTO_ALLOW"
        add_labels.append(TRINETRA_LABELS["SAFE"])
        remove_labels.extend([TRINETRA_LABELS["WARN"], TRINETRA_LABELS["QUARANTINE"]])
        default_reason = "Automated risk fusion evaluation passed safety thresholds (ALLOW)."
    elif dec_val == Decision.WARN.value:
        new_state = EmailState.ACTIONED
        action_name = "AUTO_WARN"
        add_labels.append(TRINETRA_LABELS["WARN"])
        default_reason = "Automated risk fusion evaluation flagged medium risk signals (WARN)."
    elif dec_val == Decision.QUARANTINE.value:
        new_state = EmailState.QUARANTINED
        action_name = "AUTO_QUARANTINE"
        add_labels.append(TRINETRA_LABELS["QUARANTINE"])
        remove_labels.append("INBOX") # Controlled quarantine: remove from Inbox
        default_reason = "Automated risk fusion evaluation flagged critical risk signals (QUARANTINE)."
    else:
        new_state = EmailState.ACTIONED
        action_name = f"AUTO_{dec_val}"
        default_reason = f"Automated response action applied for decision {dec_val}."

    actual_reason = reason or default_reason
    email.state = new_state
    db.commit()

    # Modify Gmail API labels if token available
    gmail_applied = False
    if access_token:
        gmail_applied = await modify_gmail_message_labels(
            message_id=email.message_id,
            add_labels=add_labels,
            remove_labels=remove_labels,
            access_token=access_token,
        )

    audit = record_action_audit(
        db=db,
        email=email,
        action=action_name,
        actor="SYSTEM",
        reason=actual_reason,
        previous_state=prev_state,
        new_state=new_state.value if hasattr(new_state, "value") else str(new_state),
        details={"decision": dec_val, "labels_added": add_labels, "labels_removed": remove_labels, "gmail_api_applied": gmail_applied},
    )

    return {
        "success": True,
        "email_id": str(email.id),
        "message_id": email.message_id,
        "decision": dec_val,
        "action_taken": action_name,
        "previous_state": prev_state,
        "new_state": email.state.value if hasattr(email.state, "value") else str(email.state),
        "labels_modified": {"added": add_labels, "removed": remove_labels},
        "audit_id": str(audit.id),
        "gmail_api_applied": gmail_applied,
    }


async def analyst_quarantine(
    db: Session,
    identifier: str,
    actor: str = "analyst@trinetra.soc",
    reason: str = "Analyst manual threat containment",
    confirmed: bool = False,
    access_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyst action to quarantine an email.
    High-impact action: Requires explicit analyst confirmation (`confirmed=True`).
    """
    if not confirmed:
        return {
            "success": False,
            "confirmation_required": True,
            "action": "QUARANTINE",
            "message": "High-impact action: Quarantining an email removes it from the user's Inbox. Confirmation required.",
            "impact_warning": "This action will isolate the email with label TRINETRA/QUARANTINE and remove it from INBOX.",
        }

    email = _get_email_by_id_or_msg_id(db, identifier)
    prev_state = email.state.value if hasattr(email.state, "value") else str(email.state)

    email.state = EmailState.QUARANTINED
    db.commit()

    add_labels = [TRINETRA_LABELS["QUARANTINE"], TRINETRA_LABELS["REVIEW"]]
    remove_labels = ["INBOX"]

    gmail_applied = False
    if access_token:
        gmail_applied = await modify_gmail_message_labels(
            message_id=email.message_id,
            add_labels=add_labels,
            remove_labels=remove_labels,
            access_token=access_token,
        )

    audit = record_action_audit(
        db=db,
        email=email,
        action="ANALYST_QUARANTINE",
        actor=actor,
        reason=reason,
        previous_state=prev_state,
        new_state=EmailState.QUARANTINED.value,
        details={"confirmed": True, "labels_added": add_labels, "labels_removed": remove_labels, "gmail_api_applied": gmail_applied},
    )

    return {
        "success": True,
        "email_id": str(email.id),
        "message_id": email.message_id,
        "action_taken": "ANALYST_QUARANTINE",
        "previous_state": prev_state,
        "new_state": EmailState.QUARANTINED.value,
        "audit_id": str(audit.id),
        "actor": actor,
        "reason": reason,
        "gmail_api_applied": gmail_applied,
    }


async def analyst_release(
    db: Session,
    identifier: str,
    actor: str = "analyst@trinetra.soc",
    reason: str = "Analyst manual release after verification",
    confirmed: bool = False,
    access_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyst action to release a quarantined email back to INBOX.
    High-impact action: Requires explicit analyst confirmation (`confirmed=True`).
    """
    if not confirmed:
        return {
            "success": False,
            "confirmation_required": True,
            "action": "RELEASE",
            "message": "High-impact action: Releasing a quarantined email restores it to the recipient's Inbox. Confirmation required.",
            "impact_warning": "This action will remove the TRINETRA/QUARANTINE label and restore the email to INBOX.",
        }

    email = _get_email_by_id_or_msg_id(db, identifier)
    prev_state = email.state.value if hasattr(email.state, "value") else str(email.state)

    email.state = EmailState.RELEASED
    db.commit()

    add_labels = ["INBOX", TRINETRA_LABELS["SAFE"]]
    remove_labels = [TRINETRA_LABELS["QUARANTINE"]]

    gmail_applied = False
    if access_token:
        gmail_applied = await modify_gmail_message_labels(
            message_id=email.message_id,
            add_labels=add_labels,
            remove_labels=remove_labels,
            access_token=access_token,
        )

    audit = record_action_audit(
        db=db,
        email=email,
        action="ANALYST_RELEASE",
        actor=actor,
        reason=reason,
        previous_state=prev_state,
        new_state=EmailState.RELEASED.value,
        details={"confirmed": True, "labels_added": add_labels, "labels_removed": remove_labels, "gmail_api_applied": gmail_applied},
    )

    return {
        "success": True,
        "email_id": str(email.id),
        "message_id": email.message_id,
        "action_taken": "ANALYST_RELEASE",
        "previous_state": prev_state,
        "new_state": EmailState.RELEASED.value,
        "audit_id": str(audit.id),
        "actor": actor,
        "reason": reason,
        "gmail_api_applied": gmail_applied,
    }


async def analyst_mark_safe(
    db: Session,
    identifier: str,
    actor: str = "analyst@trinetra.soc",
    reason: str = "Analyst validated email as safe/legitimate",
    access_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyst action to mark an email as SAFE.
    """
    email = _get_email_by_id_or_msg_id(db, identifier)
    prev_state = email.state.value if hasattr(email.state, "value") else str(email.state)

    email.state = EmailState.SAFE
    db.commit()

    add_labels = [TRINETRA_LABELS["SAFE"], "INBOX"]
    remove_labels = [TRINETRA_LABELS["WARN"], TRINETRA_LABELS["QUARANTINE"]]

    gmail_applied = False
    if access_token:
        gmail_applied = await modify_gmail_message_labels(
            message_id=email.message_id,
            add_labels=add_labels,
            remove_labels=remove_labels,
            access_token=access_token,
        )

    audit = record_action_audit(
        db=db,
        email=email,
        action="ANALYST_MARK_SAFE",
        actor=actor,
        reason=reason,
        previous_state=prev_state,
        new_state=EmailState.SAFE.value,
        details={"labels_added": add_labels, "labels_removed": remove_labels, "gmail_api_applied": gmail_applied},
    )

    return {
        "success": True,
        "email_id": str(email.id),
        "message_id": email.message_id,
        "action_taken": "ANALYST_MARK_SAFE",
        "previous_state": prev_state,
        "new_state": EmailState.SAFE.value,
        "audit_id": str(audit.id),
        "actor": actor,
        "reason": reason,
        "gmail_api_applied": gmail_applied,
    }


async def analyst_flag_review(
    db: Session,
    identifier: str,
    actor: str = "analyst@trinetra.soc",
    reason: str = "Flagged for second-tier analyst review",
    access_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyst action to flag an email for REVIEW.
    """
    email = _get_email_by_id_or_msg_id(db, identifier)
    prev_state = email.state.value if hasattr(email.state, "value") else str(email.state)

    email.state = EmailState.REVIEW
    db.commit()

    add_labels = [TRINETRA_LABELS["REVIEW"]]
    remove_labels = []

    gmail_applied = False
    if access_token:
        gmail_applied = await modify_gmail_message_labels(
            message_id=email.message_id,
            add_labels=add_labels,
            remove_labels=[],
            access_token=access_token,
        )

    audit = record_action_audit(
        db=db,
        email=email,
        action="ANALYST_REVIEW",
        actor=actor,
        reason=reason,
        previous_state=prev_state,
        new_state=EmailState.REVIEW.value,
        details={"labels_added": add_labels, "gmail_api_applied": gmail_applied},
    )

    return {
        "success": True,
        "email_id": str(email.id),
        "message_id": email.message_id,
        "action_taken": "ANALYST_REVIEW",
        "previous_state": prev_state,
        "new_state": EmailState.REVIEW.value,
        "audit_id": str(audit.id),
        "actor": actor,
        "reason": reason,
        "gmail_api_applied": gmail_applied,
    }


async def analyst_reprocess(
    db: Session,
    identifier: str,
    actor: str = "analyst@trinetra.soc",
    reason: str = "Analyst requested pipeline re-analysis",
    access_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyst action to reprocess an email through the TRINETRA detection & risk fusion pipeline.
    """
    email = _get_email_by_id_or_msg_id(db, identifier)
    prev_state = email.state.value if hasattr(email.state, "value") else str(email.state)

    email.state = EmailState.ANALYZING
    db.commit()

    # Log reprocess audit
    audit = record_action_audit(
        db=db,
        email=email,
        action="ANALYST_REPROCESS",
        actor=actor,
        reason=reason,
        previous_state=prev_state,
        new_state=EmailState.ANALYZING.value,
        details={"reprocessed_at": datetime.now(timezone.utc).isoformat()},
    )

    return {
        "success": True,
        "email_id": str(email.id),
        "message_id": email.message_id,
        "action_taken": "ANALYST_REPROCESS",
        "previous_state": prev_state,
        "new_state": EmailState.ANALYZING.value,
        "audit_id": str(audit.id),
        "actor": actor,
        "reason": reason,
    }


def delete_email_forbidden(identifier: str) -> None:
    """
    CRITICAL SAFETY ENFORCEMENT: Automatic or unapproved permanent deletion is forbidden.
    """
    raise SafetyViolationError(
        "TRINETRA Safety Violation: Permanent deletion of emails is strictly prohibited by policy. "
        "Use controlled quarantine or analyst review instead."
    )


def get_audit_trail(
    db: Session,
    email_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """
    Retrieve traceable audit log records.
    """
    query = db.query(ActionAudit).order_by(desc(ActionAudit.created_at))

    if email_id:
        try:
            uid = uuid.UUID(email_id)
            query = query.filter(ActionAudit.email_id == uid)
        except ValueError:
            query = query.filter(ActionAudit.message_id == email_id)

    audits = query.offset(offset).limit(limit).all()

    results = []
    for a in audits:
        results.append({
            "id": str(a.id),
            "email_id": str(a.email_id) if a.email_id else None,
            "message_id": a.message_id,
            "action": a.action,
            "actor": a.actor,
            "reason": a.reason,
            "previous_state": a.previous_state,
            "new_state": a.new_state,
            "target_email": a.target_email,
            "timestamp": a.created_at.isoformat() if a.created_at else None,
            "details": a.details or {},
        })
    return results


def get_action_summary_stats(db: Session) -> Dict[str, int]:
    """
    Compute UI action summary counts:
    - Action Taken
    - Action Pending
    - Analyst Review
    - Quarantined
    - Released
    """
    total_emails = db.query(func.count(Email.id)).scalar() or 0
    quarantined = db.query(func.count(Email.id)).filter(Email.state == EmailState.QUARANTINED).scalar() or 0
    released = db.query(func.count(Email.id)).filter(Email.state == EmailState.RELEASED).scalar() or 0
    analyst_review = db.query(func.count(Email.id)).filter(Email.state == EmailState.REVIEW).scalar() or 0
    action_pending = db.query(func.count(Email.id)).filter(Email.state.in_([
        EmailState.RECEIVED, EmailState.PARSING, EmailState.ANALYZING, EmailState.ANALYZED, EmailState.ACTION_PENDING
    ])).scalar() or 0
    action_taken = db.query(func.count(Email.id)).filter(Email.state.in_([
        EmailState.ACTIONED, EmailState.SAFE, EmailState.QUARANTINED, EmailState.RELEASED
    ])).scalar() or 0

    return {
        "total_emails": total_emails,
        "action_taken": action_taken,
        "action_pending": action_pending,
        "analyst_review": analyst_review,
        "quarantined": quarantined,
        "released": released,
    }
