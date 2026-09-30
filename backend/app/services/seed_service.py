"""
TRINETRA — Database Seeding Service

Populates initial database records with realistic phishing detection samples,
threat indicators, graph entities, detections, incidents, and audit trails if the database is empty.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.models import (
    User,
    GmailAccount,
    Email,
    EmailUrl,
    Domain,
    Detection,
    RiskSignal,
    ThreatIndicator,
    GraphEntity,
    GraphRelationship,
    Feedback,
    Incident,
    EmailState,
    Severity,
    Decision,
    IncidentStatus,
    ActionAudit,
)

logger = logging.getLogger(__name__)


def seed_initial_data_if_empty(db: Session) -> int:
    """Seed initial realistic data if database has no emails."""
    existing_count = db.query(Email).count()
    if existing_count > 0:
        return 0

    logger.info("Database is empty. Seeding realistic TRINETRA SOC dataset...")

    from app.core.security import hash_password

    # 1. Create system admin user
    user = User(
        email="soc-lead@trinetra.ai",
        hashed_password=hash_password("admin123"),
        full_name="SOC Lead Analyst",
        role="admin",
        is_active=True,
    )
    db.add(user)

    # 1b. Create system analyst user
    analyst_user = User(
        email="analyst@trinetra.ai",
        hashed_password=hash_password("analyst123"),
        full_name="SOC Analyst",
        role="analyst",
        is_active=True,
    )
    db.add(analyst_user)
    db.flush()

    # 2. Create connected Gmail account
    account = GmailAccount(
        user_id=user.id,
        email_address="soc-monitor@enterprise.com",
        history_id="1098421",
        is_active=True,
    )
    db.add(account)
    db.flush()

    now = datetime.now(timezone.utc)

    # 3. Create Threat Indicators
    certin_ti = ThreatIndicator(
        indicator_type="domain",
        indicator_value="system-update-security.info",
        source="CERT-In Advisory CIAD-2026-0819",
        severity=Severity.CRITICAL,
        confidence=0.95,
        description="Active phishing campaign targeting Indian enterprise credentials.",
    )
    vt_ti = ThreatIndicator(
        indicator_type="url",
        indicator_value="https://secure-banking-update.xyz/login",
        source="VirusTotal Malicious URL Feed",
        severity=Severity.HIGH,
        confidence=0.90,
        description="Flagged by 24 security vendors as credential harvester.",
    )
    db.add_all([certin_ti, vt_ti])
    db.flush()

    # 4. Create Domains
    dom1 = Domain(
        domain_name="micros0ft-support.com",
        reputation_score=0.95,
        is_lookalike=True,
        target_brand="Microsoft",
    )
    dom2 = Domain(
        domain_name="sbi-online-verify.xyz",
        reputation_score=0.85,
        is_lookalike=True,
        target_brand="State Bank of India",
    )
    db.add_all([dom1, dom2])
    db.flush()

    # 5. Seed Emails with full pipeline detections
    emails_data = [
        {
            "msg_id": "msg-9821-phish",
            "sender": "security-update@micros0ft-support.com",
            "sender_domain": "micros0ft-support.com",
            "recipient": "cfo@enterprise-finance.com",
            "subject": "Urgent: Verify Your Microsoft 365 Account Immediately",
            "received_at": now - timedelta(minutes=15),
            "state": EmailState.QUARANTINED,
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "score": 0.94,
            "sev": Severity.CRITICAL,
            "dec": Decision.QUARANTINE,
            "conf": 0.98,
            "summary": "High confidence Microsoft brand impersonation with credential harvesting URL.",
            "url": "https://micros0ft-support.com/auth/login",
            "action": "AUTO_QUARANTINE",
            "actor": "SYSTEM",
        },
        {
            "msg_id": "msg-8821-wire",
            "sender": "ceo.office@gmail.com",
            "sender_domain": "gmail.com",
            "recipient": "treasury@enterprise-finance.com",
            "subject": "Wire Transfer Authorization #8821",
            "received_at": now - timedelta(minutes=45),
            "state": EmailState.QUARANTINED,
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "none",
            "score": 0.88,
            "sev": Severity.HIGH,
            "dec": Decision.QUARANTINE,
            "conf": 0.92,
            "summary": "Executive impersonation (BEC) targeting finance department with free-mail provider.",
            "url": "https://secure-doc-share.xyz/wire-invoice.pdf",
            "action": "ANALYST_QUARANTINE",
            "actor": "analyst@trinetra.soc",
        },
        {
            "msg_id": "msg-6641-sbi",
            "sender": "alert@sbi-online-verify.xyz",
            "sender_domain": "sbi-online-verify.xyz",
            "recipient": "employee1@enterprise-finance.com",
            "subject": "SBI Account Suspension Notice — Update Mandatory KYC",
            "received_at": now - timedelta(hours=2),
            "state": EmailState.ACTIONED,
            "spf": "neutral",
            "dkim": "fail",
            "dmarc": "fail",
            "score": 0.68,
            "sev": Severity.MEDIUM,
            "dec": Decision.WARN,
            "conf": 0.85,
            "summary": "Banking brand impersonation with urgent KYC compliance language and suspicious .xyz URL.",
            "url": "https://sbi-online-verify.xyz/kyc",
            "action": "AUTO_WARN",
            "actor": "SYSTEM",
        },
        {
            "msg_id": "msg-0819-cert",
            "sender": "support@system-update-security.info",
            "sender_domain": "system-update-security.info",
            "recipient": "it-admin@enterprise-finance.com",
            "subject": "Critical Security Advisory Update CIAD-2026-0819",
            "received_at": now - timedelta(hours=4),
            "state": EmailState.QUARANTINED,
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "score": 0.96,
            "sev": Severity.CRITICAL,
            "dec": Decision.QUARANTINE,
            "conf": 0.99,
            "summary": "Matched CERT-In published threat indicator CIAD-2026-0819 targeting IT administrative credentials.",
            "url": "https://system-update-security.info/patch.exe",
            "action": "AUTO_QUARANTINE",
            "actor": "SYSTEM",
        },
        {
            "msg_id": "msg-4401-rel",
            "sender": "billing@partner-vendor.com",
            "sender_domain": "partner-vendor.com",
            "recipient": "accounts@enterprise-finance.com",
            "subject": "Vendor Invoice Payment Confirmation #4401",
            "received_at": now - timedelta(hours=6),
            "state": EmailState.RELEASED,
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "score": 0.76,
            "sev": Severity.HIGH,
            "dec": Decision.QUARANTINE,
            "conf": 0.82,
            "summary": "Initial quarantine overridden by analyst after verifying vendor invoice authenticity.",
            "url": "https://partner-vendor.com/invoices/4401",
            "action": "ANALYST_RELEASE",
            "actor": "soc_lead@trinetra.ai",
        },
        {
            "msg_id": "msg-1001-clean",
            "sender": "finance@enterprise-finance.com",
            "sender_domain": "enterprise-finance.com",
            "recipient": "all-staff@enterprise-finance.com",
            "subject": "Quarterly Financial Review Meeting Agenda",
            "received_at": now - timedelta(hours=8),
            "state": EmailState.SAFE,
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "score": 0.04,
            "sev": Severity.LOW,
            "dec": Decision.ALLOW,
            "conf": 0.99,
            "summary": "Legitimate internal communication from verified enterprise domain.",
            "url": "https://internal.enterprise-finance.com/portal",
            "action": "AUTO_ALLOW",
            "actor": "SYSTEM",
        },
    ]

    for item in emails_data:
        email = Email(
            gmail_account_id=account.id,
            message_id=item["msg_id"],
            sender=item["sender"],
            sender_domain=item["sender_domain"],
            recipient=item["recipient"],
            subject=item["subject"],
            received_at=item["received_at"],
            state=item["state"],
            spf_result=item["spf"],
            dkim_result=item["dkim"],
            dmarc_result=item["dmarc"],
            raw_headers={
                "body_snippet": f"This is an automated message regarding {item['subject']}. Please review immediately.",
                "attachments": [],
            },
        )
        db.add(email)
        db.flush()

        # Email URL
        url_rec = EmailUrl(
            email_id=email.id,
            raw_url=item["url"],
            normalized_url=item["url"],
            url_risk_score=item["score"],
            is_suspicious=item["score"] >= 0.5,
        )
        db.add(url_rec)

        # Detection
        det = Detection(
            email_id=email.id,
            content_risk=round(item["score"] * 0.95, 2),
            url_risk=round(item["score"] * 0.98, 2),
            identity_risk=round(item["score"] * 0.90, 2),
            threat_intel_risk=round(item["score"] * 0.85, 2),
            graph_risk=round(item["score"] * 0.80, 2),
            final_risk_score=item["score"],
            severity=item["sev"],
            decision=item["dec"],
            confidence=item["conf"],
            explanation_summary=item["summary"],
            evidence={
                "signals": [
                    "credential harvesting intent",
                    "suspicious URL structure",
                    "brand impersonation check",
                ]
            },
            recommended_action=f"Apply {item['dec'].value} policy.",
        )
        db.add(det)
        db.flush()

        # Action Audit
        audit = ActionAudit(
            email_id=email.id,
            message_id=email.message_id,
            action=item["action"],
            actor=item["actor"],
            reason=f"Action applied for decision {item['dec'].value}: {item['summary']}",
            previous_state=EmailState.ANALYZED.value,
            new_state=item["state"].value if hasattr(item["state"], "value") else str(item["state"]),
            target_email=email.recipient,
            details={"decision": item["dec"].value},
        )
        db.add(audit)

        # Incident for high risk
        if item["sev"] in (Severity.HIGH, Severity.CRITICAL):
            inc = Incident(
                email_id=email.id,
                assigned_to=user.id,
                title=f"Phishing Alert: {item['subject']}",
                status=IncidentStatus.INVESTIGATING if item["state"] == EmailState.QUARANTINED else IncidentStatus.RESOLVED,
                severity=item["sev"],
                summary=item["summary"],
                resolution_notes="Quarantined and isolated via TRINETRA Gmail Action Engine.",
            )
            db.add(inc)

    # 6. Seed Graph Entities & Relationships
    g_sender = GraphEntity(
        entity_type="SENDER",
        identifier="security-update@micros0ft-support.com",
        risk_score=0.95,
        properties={"domain": "micros0ft-support.com"},
    )
    g_domain = GraphEntity(
        entity_type="DOMAIN",
        identifier="micros0ft-support.com",
        risk_score=0.95,
        properties={"target_brand": "Microsoft"},
    )
    g_url = GraphEntity(
        entity_type="URL",
        identifier="https://micros0ft-support.com/auth/login",
        risk_score=0.98,
        properties={"tld": ".com"},
    )
    g_ti = GraphEntity(
        entity_type="THREAT_INDICATOR",
        identifier="CIAD-2026-0819",
        risk_score=0.99,
        properties={"source": "CERT-In"},
    )
    db.add_all([g_sender, g_domain, g_url, g_ti])
    db.flush()

    rel1 = GraphRelationship(
        source_entity_id=g_sender.id,
        target_entity_id=g_domain.id,
        relationship_type="SENT_BY",
        weight=1.0,
    )
    rel2 = GraphRelationship(
        source_entity_id=g_domain.id,
        target_entity_id=g_url.id,
        relationship_type="HOSTED_ON",
        weight=1.0,
    )
    rel3 = GraphRelationship(
        source_entity_id=g_domain.id,
        target_entity_id=g_ti.id,
        relationship_type="MATCHES",
        weight=1.0,
    )
    db.add_all([rel1, rel2, rel3])

    db.commit()
    logger.info("Successfully seeded 6 realistic emails, detections, graph entities, and action audit records!")
    return 6
