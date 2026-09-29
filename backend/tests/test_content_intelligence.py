"""
Tests for TRINETRA Content Intelligence: Intent extraction, TF-IDF + Logistic Regression,
and Content Analysis API endpoints.
"""

from fastapi.testclient import TestClient
from app.main import app
from app.services.intent_analyzer import extract_phishing_intents
from app.services.content_engine import content_engine

client = TestClient(app)


def test_intent_analyzer_credential_and_urgency():
    sample = "Urgent: Verify your account credentials within 24 hours to prevent permanent suspension."
    signals, score = extract_phishing_intents(sample)
    signal_types = [s.signal_type for s in signals]
    assert "CREDENTIAL_HARVESTING" in signal_types or "ACCOUNT_SUSPENSION_THREAT" in signal_types
    assert score > 0.6


def test_intent_analyzer_benign_text():
    sample = "Hi team, let us meet tomorrow at 10 AM to discuss our open sprint roadmap. Thanks."
    signals, score = extract_phishing_intents(sample)
    assert len(signals) == 0
    assert score == 0.0


def test_content_engine_inference_phishing():
    result = content_engine.analyze_content(
        subject="Action Required: Password change needed immediately",
        body_text="Your Microsoft 365 password expires today. Please submit your password to verify your identity.",
        sender_email="admin@micros0ft-update.com",
    )
    assert result.content_risk_score > 0.6
    assert result.phishing_probability > 0.5
    assert len(result.intent_signals) > 0
    assert "ml_model" in result.evidence


def test_content_engine_inference_legitimate():
    result = content_engine.analyze_content(
        subject="Weekly Engineering Tech Sync",
        body_text="Here are the notes and action items from yesterday's retrospective discussion with the design team.",
        sender_email="alex@internal-org.com",
    )
    assert result.content_risk_score < 0.4
    assert result.phishing_probability < 0.5


def test_content_analysis_endpoint():
    payload = {
        "subject": "Urgent Wire Transfer Request",
        "body_text": "Please initiate a wire transfer to update billing and remit payment immediately.",
        "sender_email": "ceo@corp-exec.com"
    }
    response = client.post("/api/v1/analyze/content", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "content_risk_score" in data
    assert "phishing_probability" in data
    assert "intent_signals" in data
    assert len(data["intent_signals"]) > 0


def test_model_status_endpoint():
    response = client.get("/api/v1/analyze/content/model")
    assert response.status_code == 200
    data = response.json()
    assert data["is_trained"] is True
    assert "metrics" in data
    assert data["metrics"]["f1"] > 0.8
