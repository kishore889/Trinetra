"""
TRINETRA — Phase 15: HITL Review Queue API Tests

Tests cover:
  - GET /review/queue         → returns pending items
  - GET /review/queue/{id}    → returns full detail
  - POST /review/{id}         → creates feedback + audit record
  - POST /review/{id}         → updates existing feedback
  - GET /review/history       → returns audit trail
  - GET /review/stats         → returns real statistics
  - GET /review/export        → exports JSON + CSV
  - Validation: invalid UUID, invalid classification, missing comments
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import (
    User,
    GmailAccount,
    Email,
    EmailState,
    Detection,
    Severity,
    Decision,
    Feedback,
    FeedbackClassification,
    ActionAudit,
)

# ---------------------------------------------------------------------------
# Test database fixture
# ---------------------------------------------------------------------------

SQLITE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLITE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_review_db():
    app.dependency_overrides[get_db] = override_get_db
    yield


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------

def _seed_detection(
    db,
    confidence: float = 0.45,
    decision: Decision = Decision.WARN,
    severity: Severity = Severity.MEDIUM,
    state: EmailState = EmailState.RECEIVED,
) -> tuple:
    """Creates user → gmail_account → email → detection chain."""
    user = db.query(User).first()
    if not user:
        user = User(
            email=f"test-{uuid.uuid4()}@trinetra.ai",
            hashed_password="x",
            full_name="Test Analyst",
            role="analyst",
            is_active=True,
        )
        db.add(user)
        db.flush()

    account = db.query(GmailAccount).first()
    if not account:
        account = GmailAccount(
            user_id=user.id,
            email_address="test@enterprise.com",
            is_active=True,
        )
        db.add(account)
        db.flush()

    email = Email(
        gmail_account_id=account.id,
        message_id=f"<test-{uuid.uuid4()}@mail.test>",
        sender="attacker@phish-domain.com",
        sender_domain="phish-domain.com",
        recipient="victim@enterprise.com",
        subject="Urgent: Verify your account",
        received_at=datetime.now(timezone.utc),
        state=state,
        spf_result="fail",
        dkim_result="none",
        dmarc_result="fail",
    )
    db.add(email)
    db.flush()

    detection = Detection(
        email_id=email.id,
        content_risk=0.55,
        url_risk=0.60,
        identity_risk=0.70,
        threat_intel_risk=0.30,
        graph_risk=0.20,
        final_risk_score=0.58,
        severity=severity,
        decision=decision,
        confidence=confidence,
        explanation_summary="Medium confidence phishing detection. Authentication failures observed.",
        recommended_action="Analyst review recommended.",
    )
    db.add(detection)
    db.commit()
    db.refresh(detection)
    db.refresh(email)
    return user, email, detection


# ---------------------------------------------------------------------------
# Review Queue Tests
# ---------------------------------------------------------------------------

class TestReviewQueue:
    def test_queue_returns_list(self):
        resp = client.get("/api/v1/review/queue")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_queue_contains_low_confidence_detection(self):
        db = TestingSessionLocal()
        try:
            _, _, det = _seed_detection(db, confidence=0.40)
        finally:
            db.close()

        resp = client.get("/api/v1/review/queue")
        assert resp.status_code == 200
        ids = [item["detection_id"] for item in resp.json()]
        assert str(det.id) in ids

    def test_queue_excludes_high_confidence_quarantine(self):
        """High-confidence quarantine detections do NOT appear in review queue."""
        db = TestingSessionLocal()
        try:
            _, _, det = _seed_detection(
                db,
                confidence=0.98,
                decision=Decision.QUARANTINE,
                severity=Severity.CRITICAL,
            )
        finally:
            db.close()

        resp = client.get("/api/v1/review/queue")
        assert resp.status_code == 200
        ids = [item["detection_id"] for item in resp.json()]
        # High-confidence quarantine should NOT be in the queue
        assert str(det.id) not in ids

    def test_queue_filter_by_severity(self):
        resp = client.get("/api/v1/review/queue?severity=MEDIUM")
        assert resp.status_code == 200
        for item in resp.json():
            assert item["severity"] == "MEDIUM"

    def test_queue_invalid_severity(self):
        resp = client.get("/api/v1/review/queue?severity=BOGUS")
        assert resp.status_code == 400


class TestReviewDetail:
    def test_detail_returns_full_context(self):
        db = TestingSessionLocal()
        try:
            _, _, det = _seed_detection(db, confidence=0.50)
        finally:
            db.close()

        resp = client.get(f"/api/v1/review/queue/{det.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["detection_id"] == str(det.id)
        assert "content_risk" in data
        assert "url_risk" in data
        assert "identity_risk" in data
        assert "risk_signals" in data
        assert "spf_result" in data

    def test_detail_not_found(self):
        resp = client.get(f"/api/v1/review/queue/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_detail_invalid_uuid(self):
        resp = client.get("/api/v1/review/queue/not-a-uuid")
        assert resp.status_code == 422

    def test_detail_includes_existing_feedback(self):
        """If detection already has feedback, it is returned in the detail."""
        db = TestingSessionLocal()
        try:
            user, _, det = _seed_detection(db, confidence=0.45)
            det_id = det.id
            fb = Feedback(
                detection_id=det_id,
                analyst_id=user.id,
                analyst_name="Test Analyst",
                classification=FeedbackClassification.TRUE_POSITIVE,
                comments="Confirmed phishing email.",
                review_source="REVIEW_QUEUE",
            )
            db.add(fb)
            db.commit()
        finally:
            db.close()

        resp = client.get(f"/api/v1/review/queue/{det_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["existing_feedback"] is not None
        assert data["existing_feedback"]["classification"] == "TRUE_POSITIVE"


class TestSubmitReview:
    def test_submit_true_positive(self):
        db = TestingSessionLocal()
        try:
            _, _, det = _seed_detection(db, confidence=0.48)
        finally:
            db.close()

        resp = client.post(
            f"/api/v1/review/{det.id}",
            json={
                "classification": "TRUE_POSITIVE",
                "comments": "Confirmed spear-phishing targeting finance team.",
                "analyst_name": "Alice Chen",
                "review_source": "REVIEW_QUEUE",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["classification"] == "TRUE_POSITIVE"
        assert data["analyst_name"] == "Alice Chen"
        assert "audit_ref" in data
        assert "feedback_id" in data

    def test_submit_false_positive(self):
        db = TestingSessionLocal()
        try:
            _, _, det = _seed_detection(db, confidence=0.50)
        finally:
            db.close()

        resp = client.post(
            f"/api/v1/review/{det.id}",
            json={
                "classification": "FALSE_POSITIVE",
                "comments": "Legitimate marketing email from known vendor.",
                "analyst_name": "Bob Singh",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["classification"] == "FALSE_POSITIVE"

    def test_submit_updates_existing_feedback(self):
        """Re-submitting a review updates the existing feedback record."""
        db = TestingSessionLocal()
        try:
            user, _, det = _seed_detection(db, confidence=0.42)
            det_id = det.id
            fb = Feedback(
                detection_id=det_id,
                analyst_id=user.id,
                analyst_name="Initial Analyst",
                classification=FeedbackClassification.TRUE_POSITIVE,
                comments="Initial review.",
                review_source="REVIEW_QUEUE",
            )
            db.add(fb)
            db.commit()
        finally:
            db.close()

        # Now re-review with a correction
        resp = client.post(
            f"/api/v1/review/{det_id}",
            json={
                "classification": "FALSE_POSITIVE",
                "comments": "Correction: this is a legitimate vendor email.",
                "analyst_name": "Senior Analyst",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["classification"] == "FALSE_POSITIVE"

    def test_submit_creates_audit_record(self):
        db = TestingSessionLocal()
        try:
            _, _, det = _seed_detection(db, confidence=0.55)
        finally:
            db.close()

        client.post(
            f"/api/v1/review/{det.id}",
            json={
                "classification": "TRUE_NEGATIVE",
                "comments": "Safe email from trusted partner.",
                "analyst_name": "SOC Tier-2",
            },
        )

        # Verify audit record was created
        db = TestingSessionLocal()
        try:
            audit = (
                db.query(ActionAudit)
                .filter(ActionAudit.email_id == det.email_id)
                .filter(ActionAudit.action.like("ANALYST_REVIEW_%"))
                .first()
            )
            assert audit is not None
            assert audit.actor == "SOC Tier-2"
            assert "TRUE_NEGATIVE" in audit.action
        finally:
            db.close()

    def test_submit_invalid_classification(self):
        db = TestingSessionLocal()
        try:
            _, _, det = _seed_detection(db, confidence=0.50)
        finally:
            db.close()

        resp = client.post(
            f"/api/v1/review/{det.id}",
            json={"classification": "DEFINITELY_PHISHING", "comments": "test"},
        )
        assert resp.status_code == 400

    def test_submit_not_found(self):
        resp = client.post(
            f"/api/v1/review/{uuid.uuid4()}",
            json={"classification": "TRUE_POSITIVE", "comments": "test"},
        )
        assert resp.status_code == 404

    def test_submit_invalid_uuid(self):
        resp = client.post(
            "/api/v1/review/not-a-uuid",
            json={"classification": "TRUE_POSITIVE", "comments": "test"},
        )
        assert resp.status_code == 422


class TestReviewHistory:
    def test_history_returns_list(self):
        resp = client.get("/api/v1/review/history")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_history_filter_by_classification(self):
        # Submit a known classification first
        db = TestingSessionLocal()
        try:
            _, _, det = _seed_detection(db, confidence=0.44)
        finally:
            db.close()

        client.post(
            f"/api/v1/review/{det.id}",
            json={
                "classification": "FALSE_NEGATIVE",
                "comments": "Phishing email missed by automated system.",
                "analyst_name": "QA Analyst",
            },
        )

        resp = client.get("/api/v1/review/history?classification=FALSE_NEGATIVE")
        assert resp.status_code == 200
        for item in resp.json():
            assert item["classification"] == "FALSE_NEGATIVE"

    def test_history_invalid_classification_filter(self):
        resp = client.get("/api/v1/review/history?classification=INVALID")
        assert resp.status_code == 400

    def test_history_audit_fields_present(self):
        resp = client.get("/api/v1/review/history")
        assert resp.status_code == 200
        for item in resp.json():
            # Verify all audit trail fields (who/what/when/why) are present
            assert "analyst_name" in item     # WHO
            assert "classification" in item   # WHAT
            assert "reviewed_at" in item      # WHEN
            assert "comments" in item         # WHY (nullable)
            assert "review_source" in item    # context


class TestReviewStats:
    def test_stats_returns_structure(self):
        resp = client.get("/api/v1/review/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "pending_reviews" in data
        assert "reviewed_today" in data
        assert "reviewed_total" in data
        assert "feedback_distribution" in data
        assert "false_positive_rate" in data
        assert "analyst_activity" in data
        assert "review_queue_by_severity" in data
        assert "avg_confidence_in_queue" in data

    def test_stats_false_positive_rate_between_0_and_1(self):
        resp = client.get("/api/v1/review/stats")
        assert resp.status_code == 200
        rate = resp.json()["false_positive_rate"]
        assert 0.0 <= rate <= 1.0

    def test_stats_distribution_has_all_keys(self):
        resp = client.get("/api/v1/review/stats")
        assert resp.status_code == 200
        dist = resp.json()["feedback_distribution"]
        for key in ["TRUE_POSITIVE", "FALSE_POSITIVE", "TRUE_NEGATIVE", "FALSE_NEGATIVE"]:
            assert key in dist


class TestReviewExport:
    def test_export_json(self):
        resp = client.get("/api/v1/review/export?format=json")
        assert resp.status_code == 200
        assert "application/json" in resp.headers["content-type"]
        data = resp.json()
        assert "export_metadata" in data
        assert "feedback_records" in data
        assert "safety_note" in data["export_metadata"]

    def test_export_csv(self):
        resp = client.get("/api/v1/review/export?format=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    def test_export_json_safety_note_present(self):
        """Verify export always includes the no-auto-retraining safety note."""
        resp = client.get("/api/v1/review/export?format=json")
        assert resp.status_code == 200
        data = resp.json()
        safety = data["export_metadata"]["safety_note"]
        assert "retraining" in safety.lower() or "retrain" in safety.lower()
