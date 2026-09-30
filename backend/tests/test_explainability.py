"""
TRINETRA — Phase 12: Explainability Service Tests

Tests:
  1. Deterministic fallback always runs (no Gemini required)
  2. Evidence bundle builds correctly from risk engine output
  3. System evidence is always present
  4. Gemini unavailability does NOT break the pipeline
  5. AI fields are None when Gemini is unavailable
  6. Status labelling: DETERMINISTIC vs AI_GENERATED
  7. Anti-hallucination contract: output never invents data
  8. API endpoint: /explain/status returns correct payload
  9. API endpoint: /explain/bundle works end-to-end
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.explainability_service import (
    EvidenceBundle,
    ExplainabilityStatus,
    PhishingExplanation,
    _build_deterministic_explanation,
    _build_gemini_prompt,
    build_evidence_bundle,
    explain_email,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_bundle(
    severity: str = "HIGH",
    decision: str = "QUARANTINE",
    score: int = 78,
    risk_score: float = 0.78,
    content_risk: float = 0.85,
    url_risk: float = 0.90,
    identity_risk: float = 0.72,
    threat_intel_risk: float = 0.60,
    graph_risk: float = 0.50,
) -> EvidenceBundle:
    return EvidenceBundle(
        email_id="test-email-001",
        subject="Urgent: Verify Your Account",
        sender_email="noreply@micros0ft-support.xyz",
        sender_domain="micros0ft-support.xyz",
        recipient="user@example.com",
        final_risk_score=risk_score,
        final_score_100=score,
        severity=severity,
        decision=decision,
        confidence=0.91,
        recommended_action="Quarantine email immediately.",
        content_risk_score=content_risk,
        url_risk_score=url_risk,
        identity_risk_score=identity_risk,
        threat_intel_risk_score=threat_intel_risk,
        graph_risk_score=graph_risk,
        signal_contributions={
            "Content Risk": 21,
            "URL Risk": 27,
            "Identity Risk": 14,
            "Threat Intelligence": 9,
            "Graph": 5,
        },
        intent_signals=["credential harvesting", "urgency language"],
        suspicious_urls=["https://micros0ft-support.xyz/verify"],
        url_signals=["lookalike domain", "suspicious TLD"],
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
        identity_signals=["brand impersonation detected"],
        threat_indicators=[
            {
                "indicator": "micros0ft-support.xyz",
                "indicator_type": "DOMAIN",
                "source": "TRINETRA Local TI Database",
                "severity": "HIGH",
                "confidence": 0.95,
            }
        ],
        graph_signals=["shared infrastructure with known malicious campaign"],
        evidence_summary=[
            "credential harvesting / phishing intent detected in email body",
            "suspicious URL / deceptive domain structure identified",
            "sender/brand mismatch or failed email authentication (SPF/DKIM/DMARC)",
        ],
    )


def _make_low_bundle() -> EvidenceBundle:
    return EvidenceBundle(
        email_id="test-email-clean-001",
        subject="Meeting scheduled for Tuesday",
        sender_email="alice@company.com",
        sender_domain="company.com",
        final_risk_score=0.10,
        final_score_100=10,
        severity="LOW",
        decision="ALLOW",
        confidence=0.88,
        recommended_action="Deliver normally.",
        content_risk_score=0.10,
        url_risk_score=0.05,
        identity_risk_score=0.08,
        threat_intel_risk_score=0.00,
        graph_risk_score=0.02,
        evidence_summary=["clean authentication and no suspicious indicators across all evaluated layers"],
    )


# ---------------------------------------------------------------------------
# Mock risk result for build_evidence_bundle
# ---------------------------------------------------------------------------

class _MockLayerBreakdown:
    def __init__(self, layer_name: str, raw_score: Optional[float]):
        self.layer_name = layer_name
        self.raw_score  = raw_score


class _MockRiskResult:
    def __init__(self):
        self.final_risk_score = 0.82
        self.final_score_100  = 82
        self.severity         = "HIGH"
        self.decision         = "QUARANTINE"
        self.confidence       = 0.90
        self.recommended_action = "Quarantine email."
        self.signal_contributions = {
            "Content Risk": 20,
            "URL Risk": 24,
            "Identity Risk": 16,
            "Threat Intelligence": 12,
            "Graph": 8,
        }
        self.layer_breakdown = [
            _MockLayerBreakdown("content_risk",      0.80),
            _MockLayerBreakdown("url_risk",          0.85),
            _MockLayerBreakdown("identity_risk",     0.75),
            _MockLayerBreakdown("threat_intel_risk", 0.70),
            _MockLayerBreakdown("graph_risk",        0.60),
        ]
        self.evidence_summary = [
            "credential harvesting detected",
            "suspicious URL identified",
        ]


# ===========================================================================
# 1. Deterministic Fallback Tests
# ===========================================================================

class TestDeterministicFallback:

    def test_high_risk_verdict_summary(self):
        bundle = _make_bundle()
        result = _build_deterministic_explanation(bundle)
        assert "78/100" in result.system_verdict_summary
        assert "HIGH" in result.system_verdict_summary
        assert "QUARANTINE" in result.system_verdict_summary

    def test_status_is_deterministic(self):
        bundle = _make_bundle()
        result = _build_deterministic_explanation(bundle)
        assert result.status == ExplainabilityStatus.DETERMINISTIC
        assert result.gemini_available is False

    def test_ai_fields_are_none(self):
        bundle = _make_bundle()
        result = _build_deterministic_explanation(bundle)
        assert result.ai_plain_explanation is None
        assert result.ai_key_reasons is None
        assert result.ai_risk_summary is None
        assert result.ai_analyst_summary is None
        assert result.ai_investigation_points is None

    def test_system_key_reasons_populated(self):
        bundle = _make_bundle()
        result = _build_deterministic_explanation(bundle)
        assert len(result.system_key_reasons) > 0

    def test_content_signals_in_reasons(self):
        bundle = _make_bundle(content_risk=0.90)
        result = _build_deterministic_explanation(bundle)
        combined = " ".join(result.system_key_reasons).lower()
        assert "content" in combined

    def test_url_signals_in_reasons(self):
        bundle = _make_bundle(url_risk=0.90)
        result = _build_deterministic_explanation(bundle)
        combined = " ".join(result.system_key_reasons).lower()
        assert "url" in combined or "suspicious" in combined

    def test_identity_auth_failure_in_reasons(self):
        bundle = _make_bundle(identity_risk=0.80)
        result = _build_deterministic_explanation(bundle)
        combined = " ".join(result.system_key_reasons).lower()
        assert "spf" in combined or "dkim" in combined or "dmarc" in combined or "identity" in combined

    def test_threat_intel_indicator_in_reasons(self):
        bundle = _make_bundle(threat_intel_risk=0.75)
        result = _build_deterministic_explanation(bundle)
        combined = " ".join(result.system_key_reasons).lower()
        assert "threat intel" in combined or "micros0ft-support.xyz" in combined

    def test_graph_signal_in_reasons(self):
        bundle = _make_bundle(graph_risk=0.70)
        result = _build_deterministic_explanation(bundle)
        combined = " ".join(result.system_key_reasons).lower()
        assert "graph" in combined or "infrastructure" in combined

    def test_low_risk_allow_message(self):
        bundle = _make_low_bundle()
        result = _build_deterministic_explanation(bundle)
        assert result.system_key_reasons  # not empty
        assert "10/100" in result.system_verdict_summary
        assert "ALLOW" in result.system_verdict_summary

    def test_risk_breakdown_contains_layer_scores(self):
        bundle = _make_bundle()
        result = _build_deterministic_explanation(bundle)
        breakdown = result.system_risk_breakdown
        assert "layer_scores" in breakdown
        assert "content_risk" in breakdown["layer_scores"]
        assert "url_risk" in breakdown["layer_scores"]

    def test_recommended_action_propagated(self):
        bundle = _make_bundle()
        result = _build_deterministic_explanation(bundle)
        assert result.recommended_action == bundle.recommended_action

    def test_no_low_risk_signals_gives_fallback_message(self):
        """Empty evidence_summary + below-threshold scores → generic fallback."""
        bundle = EvidenceBundle(
            final_risk_score=0.55,
            final_score_100=55,
            severity="MEDIUM",
            decision="WARN",
            confidence=0.60,
            recommended_action="Warn user.",
            evidence_summary=[],
        )
        result = _build_deterministic_explanation(bundle)
        assert len(result.system_key_reasons) > 0


# ===========================================================================
# 2. Evidence Bundle Building
# ===========================================================================

class TestEvidenceBundleBuilding:

    def test_build_from_risk_result(self):
        risk = _MockRiskResult()
        bundle = build_evidence_bundle(
            risk_result=risk,
            subject="Test email",
            sender_email="attacker@evil.com",
            sender_domain="evil.com",
        )
        assert bundle.final_risk_score == 0.82
        assert bundle.final_score_100 == 82
        assert bundle.severity == "HIGH"
        assert bundle.decision == "QUARANTINE"
        assert bundle.subject == "Test email"
        assert bundle.sender_email == "attacker@evil.com"

    def test_layer_scores_extracted(self):
        risk = _MockRiskResult()
        bundle = build_evidence_bundle(risk_result=risk)
        assert bundle.content_risk_score == 0.80
        assert bundle.url_risk_score == 0.85
        assert bundle.identity_risk_score == 0.75
        assert bundle.threat_intel_risk_score == 0.70
        assert bundle.graph_risk_score == 0.60

    def test_evidence_summary_from_risk(self):
        risk = _MockRiskResult()
        bundle = build_evidence_bundle(risk_result=risk)
        assert "credential harvesting detected" in bundle.evidence_summary

    def test_layer_inputs_evidence_extraction(self):
        risk = _MockRiskResult()
        layer_inputs = {
            "content_risk": MagicMock(
                evidence={
                    "intent_signals": ["credential harvesting", "urgency"],
                }
            ),
            "url_risk": MagicMock(
                evidence={
                    "url_signals": ["suspicious TLD"],
                    "suspicious_urls": ["https://evil.com/phish"],
                }
            ),
            "identity_risk": MagicMock(
                evidence={
                    "spf_result":       "fail",
                    "dkim_result":      "pass",
                    "dmarc_result":     "fail",
                    "identity_signals": ["brand impersonation"],
                }
            ),
            "threat_intel_risk": MagicMock(evidence={}),
            "graph_risk": MagicMock(evidence={}),
        }
        bundle = build_evidence_bundle(risk_result=risk, layer_inputs=layer_inputs)
        assert "credential harvesting" in bundle.intent_signals
        assert "https://evil.com/phish" in bundle.suspicious_urls
        assert bundle.spf_result == "fail"
        assert bundle.dkim_result == "pass"

    def test_timestamp_auto_filled(self):
        risk = _MockRiskResult()
        bundle = build_evidence_bundle(risk_result=risk)
        assert bundle.timestamp is not None
        assert "T" in bundle.timestamp  # ISO format


# ===========================================================================
# 3. explain_email — Gemini Unavailable
# ===========================================================================

class TestExplainEmailDeterministicOnly:

    def test_deterministic_returned_when_gemini_not_configured(self):
        bundle = _make_bundle()
        with patch("app.services.explainability_service.settings") as mock_settings:
            mock_settings.gemini_configured = False
            result = asyncio.get_event_loop().run_until_complete(explain_email(bundle))
        assert result.status == ExplainabilityStatus.DETERMINISTIC
        assert result.gemini_available is False
        assert result.ai_plain_explanation is None

    def test_deterministic_returned_when_gemini_call_fails(self):
        bundle = _make_bundle()
        with patch("app.services.explainability_service.settings") as mock_settings:
            mock_settings.gemini_configured = True
            mock_settings.GEMINI_API_KEY = "fake_key"
            with patch(
                "app.services.explainability_service._call_gemini",
                new_callable=AsyncMock,
                return_value=None,
            ):
                result = asyncio.get_event_loop().run_until_complete(
                    explain_email(bundle)
                )
        assert result.status == ExplainabilityStatus.DETERMINISTIC
        assert result.ai_plain_explanation is None

    def test_system_evidence_always_present(self):
        bundle = _make_bundle()
        with patch("app.services.explainability_service.settings") as mock_settings:
            mock_settings.gemini_configured = False
            result = asyncio.get_event_loop().run_until_complete(explain_email(bundle))
        assert result.system_verdict_summary != ""
        assert len(result.system_key_reasons) > 0
        assert result.system_risk_breakdown is not None


# ===========================================================================
# 4. explain_email — Gemini Available
# ===========================================================================

MOCK_GEMINI_RESPONSE = {
    "plain_explanation": (
        "This email was flagged because the sender domain micros0ft-support.xyz "
        "impersonates Microsoft. SPF, DKIM, and DMARC all failed."
    ),
    "key_reasons": [
        "Sender domain micros0ft-support.xyz is a lookalike of microsoft.com",
        "SPF/DKIM/DMARC authentication all failed",
        "TRINETRA Local TI Database matched the sender domain",
    ],
    "risk_summary": (
        "CRITICAL risk: sender domain impersonates Microsoft with failed authentication."
    ),
    "analyst_summary": (
        "Verify whether the recipient interacted with the URL "
        "https://micros0ft-support.xyz/verify."
    ),
    "investigation_points": [
        "Check email gateway logs for delivery status",
        "Verify whether recipient clicked the suspicious URL",
    ],
}


class TestExplainEmailGemini:

    def test_ai_generated_status_when_gemini_succeeds(self):
        bundle = _make_bundle()
        with patch("app.services.explainability_service.settings") as mock_settings:
            mock_settings.gemini_configured = True
            mock_settings.GEMINI_API_KEY = "fake_key"
            with patch(
                "app.services.explainability_service._call_gemini",
                new_callable=AsyncMock,
                return_value=MOCK_GEMINI_RESPONSE,
            ):
                result = asyncio.get_event_loop().run_until_complete(
                    explain_email(bundle)
                )

        assert result.status == ExplainabilityStatus.AI_GENERATED
        assert result.gemini_available is True

    def test_ai_fields_populated_from_gemini(self):
        bundle = _make_bundle()
        with patch("app.services.explainability_service.settings") as mock_settings:
            mock_settings.gemini_configured = True
            mock_settings.GEMINI_API_KEY = "fake_key"
            with patch(
                "app.services.explainability_service._call_gemini",
                new_callable=AsyncMock,
                return_value=MOCK_GEMINI_RESPONSE,
            ):
                result = asyncio.get_event_loop().run_until_complete(
                    explain_email(bundle)
                )

        assert result.ai_plain_explanation is not None
        assert "micros0ft-support.xyz" in result.ai_plain_explanation
        assert isinstance(result.ai_key_reasons, list)
        assert len(result.ai_key_reasons) > 0
        assert result.ai_risk_summary is not None
        assert result.ai_analyst_summary is not None
        assert isinstance(result.ai_investigation_points, list)

    def test_system_evidence_still_present_with_gemini(self):
        """System evidence must always be present even when Gemini succeeds."""
        bundle = _make_bundle()
        with patch("app.services.explainability_service.settings") as mock_settings:
            mock_settings.gemini_configured = True
            mock_settings.GEMINI_API_KEY = "fake_key"
            with patch(
                "app.services.explainability_service._call_gemini",
                new_callable=AsyncMock,
                return_value=MOCK_GEMINI_RESPONSE,
            ):
                result = asyncio.get_event_loop().run_until_complete(
                    explain_email(bundle)
                )

        # System evidence is always authoritative
        assert result.system_verdict_summary != ""
        assert len(result.system_key_reasons) > 0
        assert result.system_risk_breakdown is not None

    def test_ai_disclaimer_present(self):
        bundle = _make_bundle()
        with patch("app.services.explainability_service.settings") as mock_settings:
            mock_settings.gemini_configured = True
            mock_settings.GEMINI_API_KEY = "fake_key"
            with patch(
                "app.services.explainability_service._call_gemini",
                new_callable=AsyncMock,
                return_value=MOCK_GEMINI_RESPONSE,
            ):
                result = asyncio.get_event_loop().run_until_complete(
                    explain_email(bundle)
                )

        assert "does not perform independent classification" in result.ai_disclaimer


# ===========================================================================
# 5. Prompt Anti-Hallucination Properties
# ===========================================================================

class TestPromptAntiHallucination:

    def test_prompt_contains_evidence_bundle(self):
        bundle = _make_bundle()
        prompt = _build_gemini_prompt(bundle)
        assert "micros0ft-support.xyz" in prompt
        assert "credential harvesting" in prompt

    def test_prompt_contains_prohibition(self):
        bundle = _make_bundle()
        prompt = _build_gemini_prompt(bundle)
        # Check for prohibition language
        assert "ABSOLUTE PROHIBITION" in prompt
        assert "NEVER" in prompt

    def test_prompt_contains_evidence_bundle_json(self):
        bundle = _make_bundle()
        prompt = _build_gemini_prompt(bundle)
        assert "EVIDENCE BUNDLE" in prompt
        assert "risk_assessment" in prompt
        assert "layer_scores" in prompt

    def test_prompt_requests_json_output(self):
        bundle = _build_deterministic_explanation(_make_bundle())
        bundle_obj = _make_bundle()
        prompt = _build_gemini_prompt(bundle_obj)
        assert "plain_explanation" in prompt
        assert "key_reasons" in prompt
        assert "investigation_points" in prompt

    def test_prompt_instruction_is_explainer_not_classifier(self):
        bundle = _make_bundle()
        prompt = _build_gemini_prompt(bundle)
        assert "explainer" in prompt.lower() or "NOT a classifier" in prompt


# ===========================================================================
# 6. PhishingExplanation Model Validation
# ===========================================================================

class TestPhishingExplanationModel:

    def test_model_has_disclaimer(self):
        bundle = _make_bundle()
        result = _build_deterministic_explanation(bundle)
        assert len(result.ai_disclaimer) > 50

    def test_model_has_generated_at(self):
        bundle = _make_bundle()
        result = _build_deterministic_explanation(bundle)
        assert result.generated_at is not None
        assert "T" in result.generated_at

    def test_risk_breakdown_structure(self):
        bundle = _make_bundle()
        result = _build_deterministic_explanation(bundle)
        rb = result.system_risk_breakdown
        assert "final_score_100" in rb
        assert "severity" in rb
        assert "decision" in rb
        assert "signal_contributions" in rb
        assert "layer_scores" in rb


# ===========================================================================
# 7. API Endpoint Tests
# ===========================================================================

@pytest.fixture
def test_client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


class TestExplainabilityEndpoints:

    def test_status_endpoint_returns_200(self, test_client):
        resp = test_client.get("/api/v1/explain/status")
        assert resp.status_code == 200

    def test_status_endpoint_structure(self, test_client):
        resp = test_client.get("/api/v1/explain/status")
        data = resp.json()
        assert "gemini_configured" in data
        assert "fallback_available" in data
        assert data["fallback_available"] is True
        assert "description" in data

    def test_explain_bundle_endpoint(self, test_client):
        """POST /explain/bundle with a valid EvidenceBundle."""
        bundle_payload = {
            "bundle": {
                "email_id": "api-test-001",
                "subject": "Urgent: Verify your account",
                "sender_email": "attacker@phish.xyz",
                "sender_domain": "phish.xyz",
                "final_risk_score": 0.88,
                "final_score_100": 88,
                "severity": "HIGH",
                "decision": "QUARANTINE",
                "confidence": 0.92,
                "recommended_action": "Quarantine email.",
                "content_risk_score": 0.85,
                "url_risk_score": 0.90,
                "identity_risk_score": 0.75,
                "threat_intel_risk_score": 0.60,
                "graph_risk_score": 0.45,
                "signal_contributions": {
                    "Content Risk": 21,
                    "URL Risk": 27,
                },
                "intent_signals": ["credential harvesting"],
                "suspicious_urls": ["https://phish.xyz/login"],
                "spf_result": "fail",
                "dkim_result": "fail",
                "dmarc_result": "fail",
                "evidence_summary": [
                    "credential harvesting intent detected",
                    "suspicious URL identified",
                ],
            }
        }
        resp = test_client.post("/api/v1/explain/bundle", json=bundle_payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert data["status"] in ("AI_GENERATED", "DETERMINISTIC")
        assert "system_verdict_summary" in data
        assert "system_key_reasons" in data
        assert len(data["system_key_reasons"]) > 0
        assert "recommended_action" in data
        assert "ai_disclaimer" in data

    def test_explain_bundle_endpoint_system_evidence_always_present(self, test_client):
        bundle_payload = {
            "bundle": {
                "final_risk_score": 0.20,
                "final_score_100": 20,
                "severity": "LOW",
                "decision": "ALLOW",
                "confidence": 0.85,
                "recommended_action": "Deliver normally.",
                "evidence_summary": ["clean authentication and no suspicious indicators"],
            }
        }
        resp = test_client.post("/api/v1/explain/bundle", json=bundle_payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["system_verdict_summary"] != ""
        assert len(data["system_key_reasons"]) > 0
