"""
TRINETRA — Phase 13: Gmail Response and Action Engine Test Suite

Tests:
1. Label preparation: TRINETRA/SAFE, TRINETRA/WARN, TRINETRA/QUARANTINE, TRINETRA/REVIEW
2. Auto-decision actions: ALLOW, WARN, QUARANTINE
3. Analyst actions: quarantine, release, mark safe, review, reprocess
4. High-impact action confirmation requirements (quarantine/release require confirmed=True)
5. Safety enforcement: permanent deletion strictly prohibited (raises SafetyViolationError / HTTP 403)
6. Traceable audit logging: action, actor, timestamp, email, reason, prev_state, new_state
7. Action summary metrics for UI display
8. REST API endpoints integration testing
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.models import Email, EmailState, Decision, GmailAccount, User, ActionAudit
from app.services import gmail_action_service as action_svc
from app.core.exceptions import SafetyViolationError

# Setup SQLite test DB
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    # Create dummy user & gmail account
    user = User(
        email="test_analyst@trinetra.soc",
        hashed_password="hashed_secret",
        role="analyst",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    account = GmailAccount(
        user_id=user.id,
        email_address="target@trinetra.org",
    )
    db.add(account)
    db.commit()
    db.refresh(account)

    yield db

    db.close()
    Base.metadata.drop_all(bind=engine)


def _seed_test_email(db, message_id="msg_12345", recipient="target@trinetra.org") -> Email:
    account = db.query(GmailAccount).first()
    email = Email(
        gmail_account_id=account.id,
        message_id=message_id,
        sender="attacker@phish.com",
        sender_domain="phish.com",
        recipient=recipient,
        subject="Urgent Password Reset Required",
        received_at=datetime.now(timezone.utc),
        state=EmailState.RECEIVED,
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    return email


# ===========================================================================
# Unit Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_ensure_trinetra_labels():
    """Verify standard TRINETRA labels exist in label map."""
    labels = await action_svc.ensure_trinetra_labels(access_token=None)
    assert labels["TRINETRA/SAFE"] == "TRINETRA/SAFE"
    assert labels["TRINETRA/WARN"] == "TRINETRA/WARN"
    assert labels["TRINETRA/QUARANTINE"] == "TRINETRA/QUARANTINE"
    assert labels["TRINETRA/REVIEW"] == "TRINETRA/REVIEW"


@pytest.mark.asyncio
async def test_auto_apply_allow(setup_db):
    db = setup_db
    email = _seed_test_email(db, "msg_allow")

    res = await action_svc.apply_auto_decision_action(db, email.id, Decision.ALLOW)

    assert res["success"] is True
    assert res["action_taken"] == "AUTO_ALLOW"
    assert res["new_state"] == EmailState.SAFE.value

    # Verify DB update & audit record
    updated = db.query(Email).filter_by(id=email.id).first()
    assert updated.state == EmailState.SAFE

    audits = action_svc.get_audit_trail(db, str(email.id))
    assert len(audits) == 1
    assert audits[0]["action"] == "AUTO_ALLOW"
    assert audits[0]["actor"] == "SYSTEM"
    assert audits[0]["previous_state"] == "RECEIVED"
    assert audits[0]["new_state"] == EmailState.SAFE.value


@pytest.mark.asyncio
async def test_auto_apply_quarantine(setup_db):
    db = setup_db
    email = _seed_test_email(db, "msg_quarantine")

    res = await action_svc.apply_auto_decision_action(db, email.id, Decision.QUARANTINE, reason="High phish score")

    assert res["success"] is True
    assert res["action_taken"] == "AUTO_QUARANTINE"
    assert res["new_state"] == EmailState.QUARANTINED.value

    updated = db.query(Email).filter_by(id=email.id).first()
    assert updated.state == EmailState.QUARANTINED


@pytest.mark.asyncio
async def test_analyst_quarantine_requires_confirmation(setup_db):
    db = setup_db
    email = _seed_test_email(db, "msg_analyst_quar")

    # Unconfirmed attempt
    res = await action_svc.analyst_quarantine(db, str(email.id), confirmed=False)
    assert res["success"] is False
    assert res["confirmation_required"] is True

    # State must remain unchanged
    updated = db.query(Email).filter_by(id=email.id).first()
    assert updated.state == EmailState.RECEIVED

    # Confirmed attempt
    res2 = await action_svc.analyst_quarantine(db, str(email.id), confirmed=True, reason="Confirmed phishing credential harvest")
    assert res2["success"] is True
    assert res2["action_taken"] == "ANALYST_QUARANTINE"

    updated2 = db.query(Email).filter_by(id=email.id).first()
    assert updated2.state == EmailState.QUARANTINED


@pytest.mark.asyncio
async def test_analyst_release_requires_confirmation(setup_db):
    db = setup_db
    email = _seed_test_email(db, "msg_analyst_rel")
    email.state = EmailState.QUARANTINED
    db.commit()

    # Unconfirmed attempt
    res = await action_svc.analyst_release(db, str(email.id), confirmed=False)
    assert res["confirmation_required"] is True

    # Confirmed attempt
    res2 = await action_svc.analyst_release(db, str(email.id), confirmed=True, reason="False positive verified by IT admin")
    assert res2["success"] is True
    assert res2["action_taken"] == "ANALYST_RELEASE"

    updated = db.query(Email).filter_by(id=email.id).first()
    assert updated.state == EmailState.RELEASED


@pytest.mark.asyncio
async def test_analyst_mark_safe_and_review(setup_db):
    db = setup_db
    email = _seed_test_email(db, "msg_safe_rev")

    # Mark safe
    res_safe = await action_svc.analyst_mark_safe(db, str(email.id), reason="Internal newsletter")
    assert res_safe["success"] is True
    assert res_safe["new_state"] == EmailState.SAFE.value

    # Flag for review
    res_rev = await action_svc.analyst_flag_review(db, str(email.id), reason="Needs tier 2 inspection")
    assert res_rev["success"] is True
    assert res_rev["new_state"] == EmailState.REVIEW.value


@pytest.mark.asyncio
async def test_analyst_reprocess(setup_db):
    db = setup_db
    email = _seed_test_email(db, "msg_reprocess")

    res = await action_svc.analyst_reprocess(db, str(email.id), reason="Updated ruleset")
    assert res["success"] is True
    assert res["new_state"] == EmailState.ANALYZING.value


def test_delete_email_forbidden():
    """Verify permanent deletion raises SafetyViolationError."""
    with pytest.raises(SafetyViolationError) as excinfo:
        action_svc.delete_email_forbidden("msg_del_test")
    assert "strictly prohibited" in str(excinfo.value)


def test_action_summary_stats(setup_db):
    db = setup_db
    _seed_test_email(db, "m1")
    e2 = _seed_test_email(db, "m2")
    e2.state = EmailState.QUARANTINED
    e3 = _seed_test_email(db, "m3")
    e3.state = EmailState.RELEASED
    e4 = _seed_test_email(db, "m4")
    e4.state = EmailState.REVIEW
    db.commit()

    stats = action_svc.get_action_summary_stats(db)
    assert stats["total_emails"] == 4
    assert stats["quarantined"] == 1
    assert stats["released"] == 1
    assert stats["analyst_review"] == 1


# ===========================================================================
# API Endpoint Integration Tests
# ===========================================================================

def test_api_auto_apply(setup_db):
    db = setup_db
    email = _seed_test_email(db, "api_msg_auto")

    response = client.post(
        "/api/v1/actions/auto-apply",
        json={"email_id": str(email.id), "decision": "QUARANTINE", "reason": "API risk engine trigger"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["action_taken"] == "AUTO_QUARANTINE"


def test_api_quarantine_confirmation_flow(setup_db):
    db = setup_db
    email = _seed_test_email(db, "api_msg_quar")

    # Step 1: Unconfirmed request
    resp1 = client.post(
        "/api/v1/actions/quarantine",
        json={"email_id": str(email.id), "actor": "analyst@trinetra.soc", "reason": "Suspicious payload", "confirmed": False}
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["confirmation_required"] is True

    # Step 2: Confirmed request
    resp2 = client.post(
        "/api/v1/actions/quarantine",
        json={"email_id": str(email.id), "actor": "analyst@trinetra.soc", "reason": "Suspicious payload", "confirmed": True}
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["success"] is True
    assert data2["action_taken"] == "ANALYST_QUARANTINE"


def test_api_release_confirmation_flow(setup_db):
    db = setup_db
    email = _seed_test_email(db, "api_msg_rel")
    email.state = EmailState.QUARANTINED
    db.commit()

    resp = client.post(
        "/api/v1/actions/release",
        json={"email_id": str(email.id), "actor": "soc_lead@trinetra.soc", "reason": "Verified safe sender", "confirmed": True}
    )
    assert resp.status_code == 200
    assert resp.json()["action_taken"] == "ANALYST_RELEASE"


def test_api_mark_safe_and_review(setup_db):
    db = setup_db
    email = _seed_test_email(db, "api_msg_safe")

    resp_safe = client.post(
        "/api/v1/actions/mark-safe",
        json={"email_id": str(email.id), "reason": "Whitelisted domain"}
    )
    assert resp_safe.status_code == 200
    assert resp_safe.json()["new_state"] == EmailState.SAFE.value

    resp_rev = client.post(
        "/api/v1/actions/review",
        json={"email_id": str(email.id), "reason": "Second review requested"}
    )
    assert resp_rev.status_code == 200
    assert resp_rev.json()["new_state"] == EmailState.REVIEW.value


def test_api_delete_forbidden(setup_db):
    """Verify DELETE endpoint returns 403 Forbidden."""
    resp = client.delete("/api/v1/actions/delete/msg_attempt_del")
    assert resp.status_code == 403
    assert "strictly prohibited" in resp.json()["detail"]


def test_api_audit_logs_and_summary(setup_db):
    db = setup_db
    email = _seed_test_email(db, "api_audit_msg")

    # Generate an action
    client.post(
        "/api/v1/actions/mark-safe",
        json={"email_id": str(email.id), "reason": "Audit test"}
    )

    # Fetch audit
    audit_resp = client.get(f"/api/v1/actions/audit?email_id={email.id}")
    assert audit_resp.status_code == 200
    audits = audit_resp.json()
    assert len(audits) >= 1
    assert audits[0]["action"] == "ANALYST_MARK_SAFE"

    # Fetch summary
    summary_resp = client.get("/api/v1/actions/summary")
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert "action_taken" in summary
    assert "quarantined" in summary
