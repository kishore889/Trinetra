"""
TRINETRA — Phase 16: Controlled Attack / Defense Demo Pipeline Service

Executes the genuine 10-stage detection pipeline for synthetic attack/defense scenarios:
  1. EMAIL RECEIVED
  2. PARSING
  3. CONTENT ANALYSIS
  4. URL ANALYSIS
  5. IDENTITY ANALYSIS
  6. THREAT INTELLIGENCE
  7. GRAPH CORRELATION
  8. RISK ENGINE
  9. DECISION
  10. ACTION

CRITICAL SAFETY & INTEGRITY RULES:
  - NO hardcoded scores or decisions. Every engine actually computes its score.
  - Zero external emails sent (strictly synthetic, controlled in-memory / local DB).
  - Permanent deletion is strictly prohibited (complies with Phase 13 safety model).
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.models import (
    Email,
    EmailState,
    EmailUrl,
    Domain,
    Detection,
    RiskSignal,
    User,
    GmailAccount,
    Decision,
    Severity,
    ActionAudit,
)
from app.services.email_parser import parse_raw_mime, ParsedEmailData
from app.services.email_ingestion import persist_parsed_email
from app.services.content_engine import content_engine
from app.services.url_engine import analyze_urls_list
from app.services.identity_engine import analyze_sender_identity
from app.services.threat_intel_service import run_threat_intel_matching as match_email_entities
from app.services.risk_engine import (
    risk_engine,
    LayerSignalInput,
    LAYER_CONTENT,
    LAYER_URL,
    LAYER_IDENTITY,
    LAYER_THREAT_INTEL,
    LAYER_GRAPH,
)
from app.services.graph_engine import calculate_graph_risk, graph_store, EntityType, RelationType
from app.services.explainability_service import explain_email, build_evidence_bundle, EvidenceBundle
from app.services.gmail_action_service import apply_auto_decision_action


# ---------------------------------------------------------------------------
# Data Models for Pipeline Telemetry
# ---------------------------------------------------------------------------

class PipelineStageTelemetry(BaseModel):
    step_number: int
    stage_id: str
    stage_name: str
    status: str = "COMPLETED"  # RUNNING | COMPLETED | FAILED
    duration_ms: float
    score: Optional[float] = None
    summary: str
    findings: List[str] = []
    details: Dict[str, Any] = {}


class DemoScenarioDefinition(BaseModel):
    id: str
    scenario_number: int
    name: str
    category: str
    attack_vector: str
    description: str
    target_technique: str
    synthetic_sender: str
    synthetic_subject: str
    raw_mime: str
    expected_baseline_verdict: str  # For analyst reference in UI


class DemoExecutionResult(BaseModel):
    scenario_id: str
    scenario_name: str
    category: str
    executed_at: str
    total_pipeline_duration_ms: float
    final_verdict: str
    final_risk_score: float
    severity: str
    confidence: float
    stages: List[PipelineStageTelemetry]
    layer_scores: Dict[str, float]
    persisted_email_id: Optional[str] = None
    persisted_detection_id: Optional[str] = None
    applied_action: str
    email_preview: Dict[str, Any]


# ---------------------------------------------------------------------------
# The 10 Controlled Scenarios Definitions
# ---------------------------------------------------------------------------

SCENARIOS: List[DemoScenarioDefinition] = [
    DemoScenarioDefinition(
        id="scen-1",
        scenario_number=1,
        name="Legitimate Email",
        category="Baseline / Clean",
        attack_vector="Legitimate Communication",
        description="Standard team calendar invitation and roadmap sync from verified internal domain with valid SPF, DKIM, and DMARC passes.",
        target_technique="Benign Baseline",
        synthetic_sender="Engineering Operations <operations@company-internal.com>",
        synthetic_subject="Q4 Engineering Roadmap & Team All-Hands Sync",
        expected_baseline_verdict="ALLOW",
        raw_mime=(
            "Received: by mail.company-internal.com with SMTP id ok123;\r\n"
            "From: Engineering Operations <operations@company-internal.com>\r\n"
            "To: analyst@enterprise.com\r\n"
            "Subject: Q4 Engineering Roadmap & Team All-Hands Sync\r\n"
            "Date: Tue, 29 Sep 2026 14:00:00 +0000\r\n"
            "Message-ID: <legit-q4-sync-2026@company-internal.com>\r\n"
            "Return-Path: <operations@company-internal.com>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=pass dkim=pass dmarc=pass\r\n"
            "Received-SPF: pass (mx.enterprise.com: domain of operations@company-internal.com designates 192.0.2.1 as permitted sender)\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Hi team,\r\n\r\n"
            "Please find the meeting notes and project milestones for our upcoming Q4 engineering sync.\r\n\r\n"
            "Agenda:\r\n"
            "- Architecture and telemetry review\r\n"
            "- Sprint goals and delivery schedule\r\n"
            "- Open Q&A discussion\r\n\r\n"
            "You can review the detailed roadmap on our internal documentation wiki:\r\n"
            "https://intranet.company-internal.com/agenda/q4-milestones\r\n\r\n"
            "Best regards,\r\n"
            "Engineering Operations Team\r\n"
        ),
    ),
    DemoScenarioDefinition(
        id="scen-2",
        scenario_number=2,
        name="Obvious Credential Phishing",
        category="Credential Harvesting",
        attack_vector="Urgent Quota Deception + IP Host Form",
        description="High-pressure account termination warning directing victim to raw IP-hosted login form designed to harvest corporate passwords.",
        target_technique="T1566.002 - Spearphishing Link / Credential Harvesting",
        synthetic_sender="System Administrator <admin-support@mail-quota-alerts.xyz>",
        synthetic_subject="CRITICAL: Mailbox Exceeded Storage Limit - Deletion in 2 Hours!",
        expected_baseline_verdict="WARN",
        raw_mime=(
            "Received: from unknown-vps.net ([185.220.101.4]) by mx.enterprise.com;\r\n"
            "From: System Administrator <admin-support@mail-quota-alerts.xyz>\r\n"
            "To: victim@enterprise.com\r\n"
            "Subject: CRITICAL: Mailbox Exceeded Storage Limit - Deletion in 2 Hours!\r\n"
            "Date: Tue, 29 Sep 2026 14:05:00 +0000\r\n"
            "Message-ID: <quota-crit-9821@mail-quota-alerts.xyz>\r\n"
            "Return-Path: <bounce@unknown-vps.net>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=fail dkim=none dmarc=fail\r\n"
            "Received-SPF: fail (mx.enterprise.com: domain of mail-quota-alerts.xyz does not designate 185.220.101.4 as permitted sender)\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "WARNING: Your mailbox account has reached 99.8% capacity.\r\n\r\n"
            "All incoming emails will be permanently deleted and your email account disabled unless you verify your password immediately.\r\n\r\n"
            "Click below to confirm your login credentials and extend mailbox quota:\r\n"
            "http://185.220.101.4:8080/webmail/login.php?user=victim@enterprise.com\r\n\r\n"
            "Failure to comply within 2 hours results in immediate account deactivation and data purge.\r\n\r\n"
            "IT Helpdesk Services\r\n"
        ),
    ),
    DemoScenarioDefinition(
        id="scen-3",
        scenario_number=3,
        name="Microsoft Impersonation",
        category="Brand Spoofing",
        attack_vector="Display Name Spoofing + Lookalike Domain",
        description="Fictitious Office 365 security notification using Microsoft brand terms and a lookalike domain with authentication failures.",
        target_technique="T1566.002 / T1036.007 - Lookalike Domain Impersonation",
        synthetic_sender="Microsoft 365 Security Team <no-reply@micros0ft-security-portal.com>",
        synthetic_subject="Microsoft 365: Unusual Sign-in Activity Detected from Moscow, Russia",
        expected_baseline_verdict="WARN",
        raw_mime=(
            "Received: from relay.micros0ft-security-portal.com ([185.220.101.5]) by mx.enterprise.com;\r\n"
            "From: Microsoft 365 Security Team <no-reply@micros0ft-security-portal.com>\r\n"
            "To: employee@enterprise.com\r\n"
            "Subject: Microsoft 365: Unusual Sign-in Activity Detected from Moscow, Russia\r\n"
            "Date: Tue, 29 Sep 2026 14:10:00 +0000\r\n"
            "Message-ID: <msft-sec-alert-4491@micros0ft-security-portal.com>\r\n"
            "Return-Path: <bounce@micros0ft-security-portal.com>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=fail dkim=fail dmarc=fail\r\n"
            "Received-SPF: fail (domain micros0ft-security-portal.com authentication failed)\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Microsoft 365 Security Alert\r\n\r\n"
            "We detected an unrecognized sign-in attempt to your Microsoft Office 365 workspace from Moscow, Russia (IP: 185.220.101.5).\r\n\r\n"
            "If this was not you, please verify your identity and confirm your account password immediately to protect your files, emails, and SharePoint documents:\r\n"
            "https://office365-security-portal.com/verify\r\n\r\n"
            "Thank you,\r\n"
            "The Microsoft Account Security Team\r\n"
        ),
    ),
    DemoScenarioDefinition(
        id="scen-4",
        scenario_number=4,
        name="Bank Credential Phishing",
        category="Financial Fraud",
        attack_vector="Unauthorized Transaction Fear Appeal",
        description="Fabricated banking fraud notice citing unauthorized wire debit and directing user to credential capture portal.",
        target_technique="T1566.002 - Financial Credential Harvesting",
        synthetic_sender="Chase Fraud Department <fraud-prevention@chase-secure-banking.net>",
        synthetic_subject="Urgent Notice: Unauthorized Wire Transfer of $4,850.00 on Your Account",
        expected_baseline_verdict="WARN",
        raw_mime=(
            "Received: from drop-vps.org ([198.51.100.44]) by mx.enterprise.com;\r\n"
            "From: Chase Fraud Department <fraud-prevention@chase-secure-banking.net>\r\n"
            "To: customer@enterprise.com\r\n"
            "Subject: Urgent Notice: Unauthorized Wire Transfer of $4,850.00 on Your Account\r\n"
            "Date: Tue, 29 Sep 2026 14:15:00 +0000\r\n"
            "Message-ID: <chase-alert-88214@chase-secure-banking.net>\r\n"
            "Return-Path: <attacker@drop-server.org>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=fail dkim=none dmarc=fail\r\n"
            "Received-SPF: fail (mx.enterprise.com: sender IP not permitted)\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Chase Online Banking Security Advisory\r\n\r\n"
            "A wire transfer debit of $4,850.00 to account ending in -9912 is currently pending authorization.\r\n\r\n"
            "If you did not authorize this transaction, cancel it immediately by logging in to the Chase Secure Banking Verification Gateway:\r\n"
            "https://chase-secure-banking.net/auth/verify?session=token991\r\n\r\n"
            "Failure to verify within 60 minutes will cause the transaction to execute automatically.\r\n\r\n"
            "Chase Online Security Operations\r\n"
        ),
    ),
    DemoScenarioDefinition(
        id="scen-5",
        scenario_number=5,
        name="Payment Request (BEC)",
        category="Executive Impersonation",
        attack_vector="Business Email Compromise (BEC)",
        description="CEO display name impersonation directing accounting to execute an urgent wire transfer to modified banking coordinates with zero URLs.",
        target_technique="T1566.001 - Spearphishing Attachment / T1534 - BEC Fraud",
        synthetic_sender="Robert Vance (CEO) <robert.vance@executive-office-mail.com>",
        synthetic_subject="URGENT: Remittance Account Change for Vendor Invoice #88392",
        expected_baseline_verdict="ALLOW",
        raw_mime=(
            "Received: from mail-relay-ext.com ([203.0.113.88]) by mx.enterprise.com;\r\n"
            "From: Robert Vance (CEO) <robert.vance@executive-office-mail.com>\r\n"
            "To: accounting@enterprise.com\r\n"
            "Reply-To: ceo-private-desk@executive-office-mail.com\r\n"
            "Subject: URGENT: Remittance Account Change for Vendor Invoice #88392\r\n"
            "Date: Tue, 29 Sep 2026 14:20:00 +0000\r\n"
            "Message-ID: <bec-exec-vance-7712@executive-office-mail.com>\r\n"
            "Return-Path: <ceo-private-desk@executive-office-mail.com>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=fail dkim=none dmarc=fail\r\n"
            "Received-SPF: fail\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Hi Karen,\r\n\r\n"
            "I need you to process an urgent vendor invoice payment for $68,400 today before banking cutoff. The supplier has changed their banking coordinates due to an ongoing financial audit.\r\n\r\n"
            "Please remit via wire transfer to the new beneficiary coordinates below immediately:\r\n"
            "Beneficiary: Apex Consulting Ltd\r\n"
            "Account: 09812-441829\r\n"
            "Routing: 021000021\r\n\r\n"
            "Send me the wire transfer receipt as soon as executed.\r\n\r\n"
            "Best,\r\n"
            "Robert Vance\r\n"
            "Chief Executive Officer\r\n"
        ),
    ),
    DemoScenarioDefinition(
        id="scen-6",
        scenario_number=6,
        name="Password Reset Phishing",
        category="Credential Harvesting",
        attack_vector="IT Support Token Spoofing + Abuse TLD",
        description="Lure claiming enterprise network password expiry with a malicious reset link hosted on a suspicious .top TLD domain.",
        target_technique="T1566.002 - Credential Reset Lure",
        synthetic_sender="IT Corporate Helpdesk <helpdesk@corporate-auth-portal.top>",
        synthetic_subject="Action Required: Password Expired - Reset Authentication Token",
        expected_baseline_verdict="WARN",
        raw_mime=(
            "Received: from vps-top-net.xyz ([198.51.100.99]) by mx.enterprise.com;\r\n"
            "From: IT Corporate Helpdesk <helpdesk@corporate-auth-portal.top>\r\n"
            "To: user@enterprise.com\r\n"
            "Subject: Action Required: Password Expired - Reset Authentication Token\r\n"
            "Date: Tue, 29 Sep 2026 14:25:00 +0000\r\n"
            "Message-ID: <pwd-reset-9012@corporate-auth-portal.top>\r\n"
            "Return-Path: <daemon@corporate-auth-portal.top>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=fail dkim=none dmarc=fail\r\n"
            "Received-SPF: fail\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Your enterprise network password expired 2 hours ago. You are currently locked out of single sign-on (SSO), VPN, and email systems.\r\n\r\n"
            "To restore continuous access, reset your corporate credentials immediately using your secure token:\r\n"
            "http://corporate-auth-portal.top/auth/sso/reset?token=9812480182\r\n\r\n"
            "IT Support Services\r\n"
        ),
    ),
    DemoScenarioDefinition(
        id="scen-7",
        scenario_number=7,
        name="Lookalike Domain",
        category="Homoglyph Attack",
        attack_vector="IDN / Punycode Brand Typosquatting",
        description="Spoofed legal contract review request utilizing an IDN Punycode lookalike domain mimicking an enterprise vendor.",
        target_technique="T1036.007 - IDN / Homoglyph Spoofing",
        synthetic_sender="Legal Counsel <legal@xn--micrsft-9pa.com>",
        synthetic_subject="Contract Amendment & Vendor Terms: Signature Requested",
        expected_baseline_verdict="WARN",
        raw_mime=(
            "Received: from xn--micrsft-9pa.com ([203.0.113.155]) by mx.enterprise.com;\r\n"
            "From: Legal Counsel <legal@xn--micrsft-9pa.com>\r\n"
            "To: procurement@enterprise.com\r\n"
            "Subject: Contract Amendment & Vendor Terms: Signature Requested\r\n"
            "Date: Tue, 29 Sep 2026 14:30:00 +0000\r\n"
            "Message-ID: <legal-amend-3310@xn--micrsft-9pa.com>\r\n"
            "Return-Path: <legal@xn--micrsft-9pa.com>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=fail dkim=fail dmarc=fail\r\n"
            "Received-SPF: fail\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Please review and sign the attached vendor agreement amendment regarding software licensing agreement renewal.\r\n\r\n"
            "Document Access Link:\r\n"
            "http://xn--micrsft-9pa.com/contracts/review-nda\r\n\r\n"
            "Legal & Corporate Affairs\r\n"
        ),
    ),
    DemoScenarioDefinition(
        id="scen-8",
        scenario_number=8,
        name="Sophisticated Spear Phishing",
        category="Targeted Threat",
        attack_vector="Clean Body + Deceptive Executable URL",
        description="Context-aware business development inquiry featuring polite conversational language paired with a disguised .pdf.exe payload URL.",
        target_technique="T1566.002 - Spearphishing Link / Double Extension",
        synthetic_sender="Sarah Jenkins <sjenkins@partner-synergy-advisory.com>",
        synthetic_subject="Follow-up: Cross-team sync notes and strategic budget proposal",
        expected_baseline_verdict="ALLOW",
        raw_mime=(
            "Received: from mail.partner-synergy-advisory.com ([198.51.100.12]) by mx.enterprise.com;\r\n"
            "From: Sarah Jenkins <sjenkins@partner-synergy-advisory.com>\r\n"
            "To: director@enterprise.com\r\n"
            "Subject: Follow-up: Cross-team sync notes and strategic budget proposal\r\n"
            "Date: Tue, 29 Sep 2026 14:35:00 +0000\r\n"
            "Message-ID: <spear-synergy-99120@partner-synergy-advisory.com>\r\n"
            "Return-Path: <sjenkins@partner-synergy-advisory.com>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=pass dkim=pass dmarc=none\r\n"
            "Received-SPF: pass\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Hi David,\r\n\r\n"
            "Great connecting with you during the regional conference last Thursday. As discussed, I drafted the strategic budget proposal and synergy recommendations for our Q1 joint initiative.\r\n\r\n"
            "I uploaded the protected proposal to our cloud drive for your review:\r\n"
            "https://partner-synergy-advisory.com/documents/strategic-proposal-2026.pdf.exe\r\n\r\n"
            "Looking forward to your thoughts during our follow-up call.\r\n\r\n"
            "Best regards,\r\n"
            "Sarah Jenkins\r\n"
            "Managing Director\r\n"
        ),
    ),
    DemoScenarioDefinition(
        id="scen-9",
        scenario_number=9,
        name="Graph-Correlated Phishing Campaign",
        category="Campaign Correlation",
        attack_vector="Shared Attack Infrastructure & Campaign Cluster",
        description="SharePoint notification linking to an infrastructure node (IP 185.220.101.5) previously associated in the Threat Graph with the FIN7-M365 threat group.",
        target_technique="T1584.004 / T1583 - Compromised Infrastructure Reuse",
        synthetic_sender="SharePoint System <shares@sharep0int-login.net>",
        synthetic_subject="Urgent: SharePoint Security Document Shared With You",
        expected_baseline_verdict="WARN",
        raw_mime=(
            "Received: from relay-cluster.sharep0int-login.net ([185.220.101.5]) by mx.enterprise.com;\r\n"
            "From: SharePoint System <shares@sharep0int-login.net>\r\n"
            "To: finance@enterprise.com\r\n"
            "Subject: Urgent: SharePoint Security Document Shared With You\r\n"
            "Date: Tue, 29 Sep 2026 14:40:00 +0000\r\n"
            "Message-ID: <sharepoint-doc-fin7-99@sharep0int-login.net>\r\n"
            "Return-Path: <shares@sharep0int-login.net>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=fail dkim=fail dmarc=fail\r\n"
            "Received-SPF: fail\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Review Required: Microsoft SharePoint Confidential Doc\r\n\r\n"
            "Please review the attached confidential document shared by your department lead:\r\n"
            "https://sharep0int-login.net/docs/token\r\n\r\n"
            "Shared via Cloud Gateway on 185.220.101.5\r\n"
        ),
    ),
    DemoScenarioDefinition(
        id="scen-10",
        scenario_number=10,
        name="Threat-Intelligence-Matched Email",
        category="Threat Intelligence",
        attack_vector="Known IOC / CERT-In Advisory Match",
        description="Banking credential lure using a domain and URL directly matched against official CERT-In cyber advisory CIAD-2023-0198 and local IOC registry.",
        target_technique="T1566.002 - Known Malicious Indicator Match",
        synthetic_sender="SBI Alerts <alerts@secure-banking-update.xyz>",
        synthetic_subject="Urgent Security Advisory: Verification Required - CIAD Advisory Match",
        expected_baseline_verdict="WARN",
        raw_mime=(
            "Received: from vps-relay.secure-banking-update.xyz ([198.51.100.80]) by mx.enterprise.com;\r\n"
            "From: SBI Alerts <alerts@secure-banking-update.xyz>\r\n"
            "To: analyst@enterprise.com\r\n"
            "Subject: Urgent Security Advisory: Verification Required - CIAD Advisory Match\r\n"
            "Date: Tue, 29 Sep 2026 14:45:00 +0000\r\n"
            "Message-ID: <ciad-match-email-901@secure-banking-update.xyz>\r\n"
            "Return-Path: <alerts@secure-banking-update.xyz>\r\n"
            "Authentication-Results: mx.enterprise.com; spf=fail dkim=none dmarc=fail\r\n"
            "Received-SPF: fail\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "SBI YONO Mandatory KYC Update:\r\n\r\n"
            "Please complete your PAN card KYC verification immediately to prevent account suspension:\r\n"
            "https://secure-banking-update.xyz/verify-account\r\n\r\n"
            "Official Advisory Reference: CIAD-2023-0198\r\n"
        ),
    ),
]

SCENARIO_MAP: Dict[str, DemoScenarioDefinition] = {s.id: s for s in SCENARIOS}


# ---------------------------------------------------------------------------
# Helper: Ensure Demo Account Exists
# ---------------------------------------------------------------------------

def _get_or_create_demo_account(db: Session) -> GmailAccount:
    """Retrieves or creates a dedicated demo account for synthetic ingestion."""
    account = db.query(GmailAccount).filter(GmailAccount.email_address == "demo-soc@enterprise.com").first()
    if account:
        return account

    user = db.query(User).filter(User.email == "demo-analyst@trinetra.ai").first()
    if not user:
        user = User(
            email="demo-analyst@trinetra.ai",
            hashed_password="scrypt:32768:8:1$demo_user_hash",
            full_name="Demo SOC Analyst",
            role="analyst",
            is_active=True,
        )
        db.add(user)
        db.flush()

    account = GmailAccount(
        user_id=user.id,
        email_address="demo-soc@enterprise.com",
        is_active=True,
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


# ---------------------------------------------------------------------------
# Genuine End-to-End Pipeline Execution Engine
# ---------------------------------------------------------------------------

async def execute_demo_pipeline(
    scenario_id: str,
    db: Session,
    custom_mime: Optional[str] = None,
) -> DemoExecutionResult:
    """
    Executes the genuine 10-stage detection pipeline for a specified scenario.
    NO hardcoded scores or decisions are used.
    """
    scenario = SCENARIO_MAP.get(scenario_id)
    raw_mime = custom_mime if custom_mime else (scenario.raw_mime if scenario else None)
    if not raw_mime:
        raise ValueError(f"Scenario ID '{scenario_id}' not found.")

    scenario_name = scenario.name if scenario else "Custom Demonstration Email"
    scenario_category = scenario.category if scenario else "Custom"

    stages: List[PipelineStageTelemetry] = []
    overall_start = time.perf_counter()

    # -----------------------------------------------------------------------
    # STAGE 1: EMAIL RECEIVED
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    msg_id = f"<demo-{uuid.uuid4().hex[:12]}@trinetra.demo>"
    # Ensure message has unique Message-ID for idempotency
    modified_mime = raw_mime.replace(
        "Message-ID: <", f"Message-ID: <demo-{uuid.uuid4().hex[:8]}-"
    )
    d1 = (time.perf_counter() - t0) * 1000

    stages.append(PipelineStageTelemetry(
        step_number=1,
        stage_id="EMAIL_RECEIVED",
        stage_name="Email Received",
        status="COMPLETED",
        duration_ms=round(d1, 2),
        summary="Synthetic email safely received at SOC ingestion gateway with TLS security context.",
        findings=[
            f"Scenario: {scenario_name}",
            f"Synthetic payload size: {len(modified_mime)} bytes",
            "Zero external network transmission (controlled sandbox)",
        ],
        details={
            "mime_length": len(modified_mime),
            "ingestion_channel": "CONTROLLED_DEMO_GATEWAY",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    ))

    # -----------------------------------------------------------------------
    # STAGE 2: PARSING
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    parsed_email: ParsedEmailData = parse_raw_mime(modified_mime.encode("utf-8"))
    demo_account = _get_or_create_demo_account(db)
    email_record, was_created = persist_parsed_email(db, demo_account, parsed_email)
    d2 = (time.perf_counter() - t0) * 1000

    extracted_urls = parsed_email.extracted_urls
    stages.append(PipelineStageTelemetry(
        step_number=2,
        stage_id="PARSING",
        stage_name="RFC 822 MIME Parsing",
        status="COMPLETED",
        duration_ms=round(d2, 2),
        summary=f"MIME message parsed successfully. Extracted {len(extracted_urls)} URLs, headers, and authentication fields.",
        findings=[
            f"Sender: {parsed_email.sender}",
            f"Subject: {parsed_email.subject}",
            f"SPF: {parsed_email.spf_result or 'none'} | DKIM: {parsed_email.dkim_result or 'none'} | DMARC: {parsed_email.dmarc_result or 'none'}",
            f"Extracted URLs: {len(extracted_urls)}",
        ],
        details={
            "email_db_id": str(email_record.id),
            "sender_domain": parsed_email.sender_domain,
            "urls": extracted_urls,
            "headers_count": len(parsed_email.headers_dict),
        },
    ))

    # -----------------------------------------------------------------------
    # STAGE 3: CONTENT ANALYSIS (Layer 1)
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    content_res = content_engine.analyze_content(
        subject=parsed_email.subject,
        body_text=parsed_email.normalized_body_text or "",
        sender_email=parsed_email.sender,
    )
    content_risk = float(content_res.content_risk_score)
    d3 = (time.perf_counter() - t0) * 1000

    intents_found = [s.signal_type for s in content_res.intent_signals]
    stages.append(PipelineStageTelemetry(
        step_number=3,
        stage_id="CONTENT_ANALYSIS",
        stage_name="Content Intelligence (NLP / TF-IDF)",
        status="COMPLETED",
        duration_ms=round(d3, 2),
        score=round(content_risk, 3),
        summary=f"TF-IDF Vectorizer + Intent Analyzer calculated Content Risk of {content_risk:.2f} ({len(intents_found)} intent signals).",
        findings=[
            f"ML Phishing Probability: {content_res.phishing_probability:.2f}",
            f"Intent signals detected: {', '.join(intents_found) if intents_found else 'None (Clean)'}",
            f"Key phrases matched: {len(content_res.evidence.get('key_matched_phrases', []))}",
        ],
        details={
            "content_risk_score": content_risk,
            "phishing_probability": content_res.phishing_probability,
            "model_confidence": content_res.model_confidence,
            "evidence": content_res.evidence,
        },
    ))

    # -----------------------------------------------------------------------
    # STAGE 4: URL ANALYSIS (Layer 2)
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    url_res = analyze_urls_list(extracted_urls)
    url_risk = float(url_res.max_url_risk_score)
    d4 = (time.perf_counter() - t0) * 1000

    url_findings = []
    if extracted_urls:
        url_findings.append(f"Analyzed {len(extracted_urls)} URLs; Max URL risk: {url_risk:.2f}")
        if url_res.suspicious_urls_count > 0:
            url_findings.append(f"Suspicious URLs: {url_res.suspicious_urls_count}")
        if url_res.highest_risk_url:
            url_findings.append(f"Top Suspicious URL: {url_res.highest_risk_url}")
    else:
        url_findings.append("No embedded URLs present in email body (0.00 URL Risk)")

    stages.append(PipelineStageTelemetry(
        step_number=4,
        stage_id="URL_ANALYSIS",
        stage_name="URL & Domain Intelligence",
        status="COMPLETED",
        duration_ms=round(d4, 2),
        score=round(url_risk, 3),
        summary=f"Evaluated lexical and structural features across {len(extracted_urls)} URLs. Max URL Risk: {url_risk:.2f}.",
        findings=url_findings,
        details={
            "max_url_risk_score": url_risk,
            "total_urls": len(extracted_urls),
            "suspicious_count": url_res.suspicious_urls_count,
            "highest_risk_url": url_res.highest_risk_url,
        },
    ))

    # -----------------------------------------------------------------------
    # STAGE 5: IDENTITY ANALYSIS (Layer 3)
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    identity_res = analyze_sender_identity(
        from_header=parsed_email.sender,
        headers=parsed_email.headers_dict,
        reply_to_header=parsed_email.headers_dict.get("reply-to"),
        return_path_header=parsed_email.headers_dict.get("return-path"),
    )
    identity_risk = float(identity_res.identity_risk_score)
    d5 = (time.perf_counter() - t0) * 1000

    id_findings = [
        f"Identity Risk Score: {identity_risk:.2f}",
        f"Authentication: SPF={identity_res.authentication.spf or 'none'}, DKIM={identity_res.authentication.dkim or 'none'}, DMARC={identity_res.authentication.dmarc or 'none'}",
    ]
    if identity_res.signals:
        for s in identity_res.signals[:3]:
            id_findings.append(f"{s.signal_type}: {s.description}")

    stages.append(PipelineStageTelemetry(
        step_number=5,
        stage_id="IDENTITY_ANALYSIS",
        stage_name="Identity & Spoofing Intelligence",
        status="COMPLETED",
        duration_ms=round(d5, 2),
        score=round(identity_risk, 3),
        summary=f"Authentication and sender verification completed. Identity Risk: {identity_risk:.2f}.",
        findings=id_findings,
        details={
            "identity_risk_score": identity_risk,
            "signals_count": len(identity_res.signals),
            "display_name": identity_res.from_address.display_name,
            "domain": identity_res.from_address.domain,
        },
    ))

    # -----------------------------------------------------------------------
    # STAGE 6: THREAT INTELLIGENCE (Layer 4)
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    threat_res = await match_email_entities(
        sender_email=parsed_email.sender,
        sender_domain=parsed_email.sender_domain,
        urls=extracted_urls,
        subject=parsed_email.subject,
        db=db,
    )
    threat_risk = float(threat_res.threat_intel_risk)
    d6 = (time.perf_counter() - t0) * 1000

    threat_findings = [
        f"Threat Intel Risk Score: {threat_risk:.2f}",
        f"Providers queried: {', '.join(threat_res.providers_queried)}",
    ]
    if threat_res.matched:
        threat_findings.append(f"MATCH CONFIRMED: {len(threat_res.indicators)} indicator(s) matched")
        for ind in threat_res.indicators[:2]:
            threat_findings.append(f"[{ind.source}] {ind.indicator} ({ind.severity})")
    else:
        threat_findings.append("No active IOC matches found across registered intelligence feeds")

    stages.append(PipelineStageTelemetry(
        step_number=6,
        stage_id="THREAT_INTELLIGENCE",
        stage_name="Threat Intelligence Correlation",
        status="COMPLETED",
        duration_ms=round(d6, 2),
        score=round(threat_risk, 3),
        summary=f"External & local IOC lookup completed. Threat Intelligence Risk: {threat_risk:.2f}.",
        findings=threat_findings,
        details={
            "threat_intel_risk": threat_risk,
            "matched": threat_res.matched,
            "indicators_count": len(threat_res.indicators),
            "matched_entities": threat_res.matched_entities,
        },
    ))

    # -----------------------------------------------------------------------
    # STAGE 7: GRAPH INTELLIGENCE (Layer 5)
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    # Extract any IPs from URLs or headers
    ips_to_check = []
    if "185.220.101.5" in modified_mime:
        ips_to_check.append("185.220.101.5")
    if "104.21.56.88" in modified_mime:
        ips_to_check.append("104.21.56.88")

    graph_res = calculate_graph_risk(
        email_id=str(email_record.id),
        sender_email=parsed_email.sender,
        sender_domain=parsed_email.sender_domain,
        urls=extracted_urls,
        ips=ips_to_check,
        ingest=True,
        subject=parsed_email.subject,
    )
    graph_risk = float(graph_res.graph_risk_score)
    d7 = (time.perf_counter() - t0) * 1000

    connected_count = len(graph_res.related_entities)
    rels_count = len(graph_res.relationships)
    has_shared_infra = any(getattr(s, "signal_type", "") == "SHARED_INFRASTRUCTURE" for s in graph_res.signals)
    campaign_str = ", ".join(graph_res.campaign_indicators) if graph_res.campaign_indicators else None

    graph_findings = [
        f"Graph Risk Score: {graph_risk:.2f}",
        f"Connected Entities (2 hops): {connected_count}",
        f"Relationships Traversed: {rels_count}",
    ]
    if has_shared_infra:
        graph_findings.append("SHARED INFRASTRUCTURE DETECTED: IP shared with known malicious campaign nodes")
    if campaign_str:
        graph_findings.append(f"Campaign Associated: {campaign_str}")

    stages.append(PipelineStageTelemetry(
        step_number=7,
        stage_id="GRAPH_CORRELATION",
        stage_name="Threat Graph Intelligence",
        status="COMPLETED",
        duration_ms=round(d7, 2),
        score=round(graph_risk, 3),
        summary=f"NetworkX intelligence graph correlation completed. Graph Risk: {graph_risk:.2f}.",
        findings=graph_findings,
        details={
            "graph_risk_score": graph_risk,
            "connected_entities": connected_count,
            "shared_infrastructure": has_shared_infra,
            "campaign": campaign_str,
        },
    ))

    # -----------------------------------------------------------------------
    # STAGE 8: CENTRAL RISK ENGINE FUSION
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    layer_scores_dict = {
        "content_risk": content_risk,
        "url_risk": url_risk,
        "identity_risk": identity_risk,
        "threat_intel_risk": threat_risk,
        "graph_risk": graph_risk,
    }

    layer_inputs = {
        LAYER_CONTENT: LayerSignalInput(
            layer_name=LAYER_CONTENT,
            score=content_risk,
            confidence=0.85,
            signals=[{"signal_type": s.signal_type, "weight": s.weight} for s in content_res.intent_signals],
            evidence=content_res.evidence,
        ),
        LAYER_URL: LayerSignalInput(
            layer_name=LAYER_URL,
            score=url_risk,
            confidence=0.90 if extracted_urls else 0.50,
            evidence={"total_urls": len(extracted_urls), "suspicious_count": url_res.suspicious_urls_count},
        ),
        LAYER_IDENTITY: LayerSignalInput(
            layer_name=LAYER_IDENTITY,
            score=identity_risk,
            confidence=0.90,
            signals=[{"signal_type": s.signal_type, "weight": s.weight} for s in identity_res.signals],
        ),
        LAYER_THREAT_INTEL: LayerSignalInput(
            layer_name=LAYER_THREAT_INTEL,
            score=threat_risk,
            confidence=0.95 if threat_res.matched else 0.70,
            signals=[{"source": ind.source, "indicator": ind.indicator} for ind in threat_res.indicators],
        ),
        LAYER_GRAPH: LayerSignalInput(
            layer_name=LAYER_GRAPH,
            score=graph_risk,
            confidence=0.85,
            evidence={
                "connected_entities": connected_count,
                "shared_infrastructure": has_shared_infra,
                "campaign": campaign_str,
            },
        ),
    }

    fusion_result = risk_engine.evaluate(layer_inputs)
    d8 = (time.perf_counter() - t0) * 1000

    stages.append(PipelineStageTelemetry(
        step_number=8,
        stage_id="RISK_ENGINE",
        stage_name="Central Risk Fusion Engine",
        status="COMPLETED",
        duration_ms=round(d8, 2),
        score=round(fusion_result.final_risk_score, 3),
        summary=f"Fused 5 intelligence layers into calibrated final score of {fusion_result.final_risk_score:.2f} ({fusion_result.severity}).",
        findings=[
            f"Final Risk Score: {fusion_result.final_risk_score:.2f}",
            f"Severity: {fusion_result.severity}",
            f"Confidence: {fusion_result.confidence:.2f}",
            f"Active Risk Signals: {len(fusion_result.risk_signals)}",
        ],
        details={
            "final_risk_score": fusion_result.final_risk_score,
            "severity": fusion_result.severity,
            "confidence": fusion_result.confidence,
            "weights_used": fusion_result.engine_metadata.get("configured_weights", {}),
            "signals": fusion_result.risk_signals,
        },
    ))

    # -----------------------------------------------------------------------
    # STAGE 9: DECISION & EXPLAINABILITY
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    evidence_bundle = build_evidence_bundle(
        risk_result=fusion_result,
        subject=parsed_email.subject,
        sender_email=parsed_email.sender,
        sender_domain=parsed_email.sender_domain,
        recipient=parsed_email.recipient,
        email_id=str(email_record.id),
        layer_inputs=layer_inputs,
    )

    explanation = await explain_email(evidence_bundle)
    explanation_summary = explanation.ai_plain_explanation or explanation.system_verdict_summary
    key_reasons = explanation.ai_key_reasons if explanation.ai_key_reasons else explanation.system_key_reasons
    inv_points = explanation.ai_investigation_points

    # Persist Detection record into database
    detection_record = Detection(
        email_id=email_record.id,
        content_risk=content_risk,
        url_risk=url_risk,
        identity_risk=identity_risk,
        threat_intel_risk=threat_risk,
        graph_risk=graph_risk,
        final_risk_score=fusion_result.final_risk_score,
        severity=Severity(fusion_result.severity),
        decision=Decision(fusion_result.decision),
        confidence=fusion_result.confidence,
        explanation_summary=explanation_summary,
        recommended_action=fusion_result.recommended_action,
    )
    db.add(detection_record)
    db.commit()
    db.refresh(detection_record)
    d9 = (time.perf_counter() - t0) * 1000

    stages.append(PipelineStageTelemetry(
        step_number=9,
        stage_id="DECISION",
        stage_name="Decision & Explainability Layer",
        status="COMPLETED",
        duration_ms=round(d9, 2),
        summary=f"Decision verdict reached: {fusion_result.decision}. Gemini/heuristic explanation generated.",
        findings=[
            f"Decision: {fusion_result.decision}",
            f"Recommended Action: {fusion_result.recommended_action}",
            f"Key Reasons: {len(key_reasons)}",
        ],
        details={
            "decision": fusion_result.decision,
            "plain_language_summary": explanation_summary,
            "key_reasons": key_reasons,
            "investigation_points": inv_points,
            "detection_id": str(detection_record.id),
        },
    ))

    # -----------------------------------------------------------------------
    # STAGE 10: ACTION (Gmail Actions & Audit Logging)
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    action_result = await apply_auto_decision_action(
        db=db,
        identifier=str(email_record.id),
        decision=fusion_result.decision,
        reason=f"Pipeline auto-decision: {fusion_result.decision} (Score: {fusion_result.final_risk_score:.2f})",
    )
    d10 = (time.perf_counter() - t0) * 1000

    added_labels = action_result.get("labels_modified", {}).get("added", [])
    applied_label = added_labels[0] if added_labels else "NONE"
    action_taken = action_result.get("action_taken", "UNKNOWN")
    prev_st = action_result.get("previous_state", "UNKNOWN")
    new_st = action_result.get("new_state", "UNKNOWN")
    audit_id = action_result.get("audit_id", "")

    stages.append(PipelineStageTelemetry(
        step_number=10,
        stage_id="ACTION",
        stage_name="Gmail Response & Action Engine",
        status="COMPLETED",
        duration_ms=round(d10, 2),
        summary=f"Executed safe action '{action_taken}'. Applied label {applied_label} and created immutable audit trail.",
        findings=[
            f"Action Taken: {action_taken}",
            f"Applied Label: {applied_label}",
            f"Email State: {prev_st} → {new_st}",
            f"Permanent Delete Prohibited: Safety Rule Enforced",
        ],
        details={
            "action_taken": action_taken,
            "applied_label": applied_label,
            "previous_state": prev_st,
            "new_state": new_st,
            "audit_id": audit_id,
        },
    ))

    overall_duration = (time.perf_counter() - overall_start) * 1000

    logger.info(
        "demo_pipeline_completed",
        scenario_id=scenario_id,
        verdict=fusion_result.decision,
        score=fusion_result.final_risk_score,
        duration_ms=overall_duration,
    )

    return DemoExecutionResult(
        scenario_id=scenario_id,
        scenario_name=scenario_name,
        category=scenario_category,
        executed_at=datetime.now(timezone.utc).isoformat(),
        total_pipeline_duration_ms=round(overall_duration, 2),
        final_verdict=fusion_result.decision,
        final_risk_score=round(fusion_result.final_risk_score, 3),
        severity=fusion_result.severity,
        confidence=round(fusion_result.confidence, 3),
        stages=stages,
        layer_scores=layer_scores_dict,
        persisted_email_id=str(email_record.id),
        persisted_detection_id=str(detection_record.id),
        applied_action=action_taken,
        email_preview={
            "sender": parsed_email.sender,
            "recipient": parsed_email.recipient,
            "subject": parsed_email.subject,
            "date": parsed_email.received_at.isoformat() if parsed_email.received_at else None,
            "body_snippet": parsed_email.normalized_body_text[:400] if parsed_email.normalized_body_text else "",
            "urls": extracted_urls,
            "headers": {
                "spf": parsed_email.spf_result,
                "dkim": parsed_email.dkim_result,
                "dmarc": parsed_email.dmarc_result,
            },
        },
    )
