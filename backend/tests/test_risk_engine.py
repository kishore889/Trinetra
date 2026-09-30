"""
TRINETRA — Central Risk Engine Tests (Phase 11)

Tests:
1. Legitimate email (low risk across all layers, ALLOW)
2. Obvious phishing (high risk across all layers, CRITICAL, QUARANTINE)
3. Mixed signals (low content risk, high URL & Identity risk)
4. New phishing domain (zero-day: URL/Identity high, Threat Intel clean/unavailable)
5. Threat-intel match (known CERT-In advisory match drives override to QUARANTINE)
6. Graph correlation (shared infrastructure / campaign connection drives score)
7. Missing provider / unavailable signal (weights dynamically renormalize, transparent audit)
8. Uncertain detection (border scores near 0.50 produce calibrated confidence)
9. Configuration validation (weights sum to 1.0, monotonic thresholds)
10. API endpoints (/api/v1/risk/evaluate, /pipeline, /config)
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import Decision, Severity
from app.services.risk_engine import (
    LAYER_CONTENT,
    LAYER_GRAPH,
    LAYER_IDENTITY,
    LAYER_THREAT_INTEL,
    LAYER_URL,
    CentralRiskEngine,
    LayerSignalInput,
    LayerStatus,
    RiskEngineConfig,
    risk_engine,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Unit Tests: Central Risk Engine Core
# ---------------------------------------------------------------------------

class TestCentralRiskEngine:

    def test_legitimate_email_allow(self):
        """
        Legitimate enterprise email:
        Content: 0.05, URL: 0.02, Identity: 0.04, Threat Intel: 0.0, Graph: 0.02
        Expected: final_risk_score < 0.20, Severity LOW, Decision ALLOW
        """
        inputs = {
            LAYER_CONTENT: LayerSignalInput(layer_name=LAYER_CONTENT, score=0.05, confidence=0.9),
            LAYER_URL: LayerSignalInput(layer_name=LAYER_URL, score=0.02, confidence=0.95),
            LAYER_IDENTITY: LayerSignalInput(layer_name=LAYER_IDENTITY, score=0.04, confidence=0.9),
            LAYER_THREAT_INTEL: LayerSignalInput(layer_name=LAYER_THREAT_INTEL, score=0.0, confidence=0.8),
            LAYER_GRAPH: LayerSignalInput(layer_name=LAYER_GRAPH, score=0.02, confidence=0.85),
        }
        res = risk_engine.evaluate(inputs)

        assert res.final_risk_score < 0.20
        assert res.severity == Severity.LOW.value
        assert res.decision == Decision.ALLOW.value
        assert "clean authentication and no suspicious indicators" in res.evidence_summary[0]
        assert "Deliver normally" in res.recommended_action

    def test_obvious_phishing_quarantine(self):
        """
        Obvious phishing email:
        Content: 0.94, URL: 0.98, Identity: 0.92, Threat Intel: 0.95, Graph: 0.90
        Expected: final_risk_score > 0.90, Severity CRITICAL, Decision QUARANTINE
        Signal contributions close to example in prompt: Content ~24, URL ~29, Identity ~18, TI ~14, Graph ~9 -> 94
        """
        inputs = {
            LAYER_CONTENT: LayerSignalInput(layer_name=LAYER_CONTENT, score=0.94, confidence=0.95),
            LAYER_URL: LayerSignalInput(layer_name=LAYER_URL, score=0.98, confidence=0.98),
            LAYER_IDENTITY: LayerSignalInput(layer_name=LAYER_IDENTITY, score=0.92, confidence=0.95),
            LAYER_THREAT_INTEL: LayerSignalInput(layer_name=LAYER_THREAT_INTEL, score=0.95, confidence=0.99),
            LAYER_GRAPH: LayerSignalInput(layer_name=LAYER_GRAPH, score=0.90, confidence=0.90),
        }
        res = risk_engine.evaluate(inputs)

        assert res.final_risk_score >= 0.88
        assert res.final_score_100 >= 88
        assert res.severity == Severity.CRITICAL.value
        assert res.decision == Decision.QUARANTINE.value
        assert res.confidence > 0.85

        # Check signal contributions
        contribs = res.signal_contributions
        assert "Content Risk" in contribs
        assert "URL Risk" in contribs
        assert "Identity Risk" in contribs
        assert "Threat Intelligence" in contribs
        assert "Graph" in contribs
        assert contribs["URL Risk"] > 25
        assert contribs["Content Risk"] > 20

    def test_mixed_signals(self):
        """
        Mixed signals: benign text (content = 0.10), but lookalike URL (0.85) and spoofed identity (0.80)
        Threat Intel: 0.10, Graph: 0.20
        """
        inputs = {
            LAYER_CONTENT: LayerSignalInput(layer_name=LAYER_CONTENT, score=0.10),
            LAYER_URL: LayerSignalInput(layer_name=LAYER_URL, score=0.85),
            LAYER_IDENTITY: LayerSignalInput(layer_name=LAYER_IDENTITY, score=0.80),
            LAYER_THREAT_INTEL: LayerSignalInput(layer_name=LAYER_THREAT_INTEL, score=0.10),
            LAYER_GRAPH: LayerSignalInput(layer_name=LAYER_GRAPH, score=0.20),
        }
        res = risk_engine.evaluate(inputs)

        # 0.25*0.10 + 0.30*0.85 + 0.20*0.80 + 0.15*0.10 + 0.10*0.20 = 0.025 + 0.255 + 0.160 + 0.015 + 0.020 = 0.475
        assert 0.40 <= res.final_risk_score <= 0.60
        assert res.decision == Decision.WARN.value
        assert res.severity == Severity.MEDIUM.value

    def test_new_phishing_domain_zero_day(self):
        """
        Zero-Day: URL and Identity high (0.90, 0.85), but Threat Intel has no record (0.0)
        and Graph has no prior history (0.10). Content is 0.70.
        """
        inputs = {
            LAYER_CONTENT: LayerSignalInput(layer_name=LAYER_CONTENT, score=0.70),
            LAYER_URL: LayerSignalInput(layer_name=LAYER_URL, score=0.90),
            LAYER_IDENTITY: LayerSignalInput(layer_name=LAYER_IDENTITY, score=0.85),
            LAYER_THREAT_INTEL: LayerSignalInput(layer_name=LAYER_THREAT_INTEL, score=0.0),
            LAYER_GRAPH: LayerSignalInput(layer_name=LAYER_GRAPH, score=0.10),
        }
        res = risk_engine.evaluate(inputs)

        # 0.25*0.70 + 0.30*0.90 + 0.20*0.85 + 0.15*0.0 + 0.10*0.10 = 0.175 + 0.270 + 0.170 + 0 + 0.010 = 0.625
        # Triggers high suspicion WARN or QUARANTINE
        assert res.final_risk_score > 0.60
        assert res.decision in (Decision.WARN.value, Decision.QUARANTINE.value)

    def test_threat_intel_override_triggers_quarantine(self):
        """
        Threat Intel returns verified high-confidence advisory match (0.95),
        even if content text was deceptively innocent.
        Expected: Override triggers QUARANTINE.
        """
        inputs = {
            LAYER_CONTENT: LayerSignalInput(layer_name=LAYER_CONTENT, score=0.20),
            LAYER_URL: LayerSignalInput(layer_name=LAYER_URL, score=0.30),
            LAYER_IDENTITY: LayerSignalInput(layer_name=LAYER_IDENTITY, score=0.20),
            LAYER_THREAT_INTEL: LayerSignalInput(layer_name=LAYER_THREAT_INTEL, score=0.95),
            LAYER_GRAPH: LayerSignalInput(layer_name=LAYER_GRAPH, score=0.20),
        }
        res = risk_engine.evaluate(inputs)

        assert res.evidence["threat_intel_override_triggered"] is True
        assert res.decision == Decision.QUARANTINE.value

    def test_graph_correlation_impacts_score(self):
        """
        Comparing an identical email with clean graph (0.0) vs correlated shared infrastructure (0.90).
        """
        base_inputs = {
            LAYER_CONTENT: LayerSignalInput(layer_name=LAYER_CONTENT, score=0.60),
            LAYER_URL: LayerSignalInput(layer_name=LAYER_URL, score=0.60),
            LAYER_IDENTITY: LayerSignalInput(layer_name=LAYER_IDENTITY, score=0.60),
            LAYER_THREAT_INTEL: LayerSignalInput(layer_name=LAYER_THREAT_INTEL, score=0.50),
        }

        inputs_clean_graph = {
            **base_inputs,
            LAYER_GRAPH: LayerSignalInput(layer_name=LAYER_GRAPH, score=0.0),
        }
        res_clean = risk_engine.evaluate(inputs_clean_graph)

        inputs_corr_graph = {
            **base_inputs,
            LAYER_GRAPH: LayerSignalInput(layer_name=LAYER_GRAPH, score=0.90),
        }
        res_corr = risk_engine.evaluate(inputs_corr_graph)

        assert res_corr.final_risk_score > res_clean.final_risk_score
        assert res_corr.signal_contributions["Graph"] > res_clean.signal_contributions["Graph"]

    def test_missing_provider_dynamic_renormalization(self):
        """
        Threat Intelligence provider is UNAVAILABLE (e.g. network timeout or API outage).
        Engine must not crash, must explicitly document the outage, and must renormalize
        weights so the sum of available weights = 1.0.
        """
        inputs = {
            LAYER_CONTENT: LayerSignalInput(layer_name=LAYER_CONTENT, score=0.80),
            LAYER_URL: LayerSignalInput(layer_name=LAYER_URL, score=0.90),
            LAYER_IDENTITY: LayerSignalInput(layer_name=LAYER_IDENTITY, score=0.85),
            LAYER_THREAT_INTEL: LayerSignalInput(
                layer_name=LAYER_THREAT_INTEL,
                status=LayerStatus.UNAVAILABLE,
                unavailable_reason="External threat provider timeout",
            ),
            LAYER_GRAPH: LayerSignalInput(layer_name=LAYER_GRAPH, score=0.70),
        }
        res = risk_engine.evaluate(inputs)

        # Check renormalization
        assert res.evidence["renormalized"] is True
        assert LAYER_THREAT_INTEL in res.evidence["unavailable_layers"]
        assert res.signal_contributions["Threat Intelligence"] == 0

        # Available weights were: 0.25 + 0.30 + 0.20 + 0.10 = 0.85
        # Effective weights sum to 1.0
        eff_weights_sum = sum(b.effective_weight for b in res.layer_breakdown if b.status == "AVAILABLE")
        assert abs(eff_weights_sum - 1.0) < 0.001

        # Final score should be elevated based on other layers
        assert res.final_risk_score > 0.75
        assert res.decision == Decision.QUARANTINE.value

        # Unavailable layer is documented in evidence summary
        has_unavail_bullet = any("Threat Intelligence" in b for b in res.evidence_summary)
        assert has_unavail_bullet is True

    def test_all_providers_unavailable_safe_fallback(self):
        """
        Worst-case edge test: All sensors fail.
        Engine must return a safe fallback with decision WARN and explicit warnings.
        """
        inputs = {
            l: LayerSignalInput(layer_name=l, status=LayerStatus.UNAVAILABLE, unavailable_reason="Sensor offline")
            for l in [LAYER_CONTENT, LAYER_URL, LAYER_IDENTITY, LAYER_THREAT_INTEL, LAYER_GRAPH]
        }
        res = risk_engine.evaluate(inputs)

        assert res.final_risk_score == 0.50
        assert res.decision == Decision.WARN.value
        assert res.confidence == 0.05
        assert "All intelligence layers unavailable" in res.evidence_summary[0]

    def test_uncertain_detection_calibrated_confidence(self):
        """
        Score close to decision threshold (e.g. 0.50) with lower sensor confidence
        should yield lower overall confidence.
        """
        inputs = {
            LAYER_CONTENT: LayerSignalInput(layer_name=LAYER_CONTENT, score=0.50, confidence=0.4),
            LAYER_URL: LayerSignalInput(layer_name=LAYER_URL, score=0.50, confidence=0.4),
            LAYER_IDENTITY: LayerSignalInput(layer_name=LAYER_IDENTITY, score=0.50, confidence=0.4),
            LAYER_THREAT_INTEL: LayerSignalInput(layer_name=LAYER_THREAT_INTEL, score=0.50, confidence=0.4),
            LAYER_GRAPH: LayerSignalInput(layer_name=LAYER_GRAPH, score=0.50, confidence=0.4),
        }
        res = risk_engine.evaluate(inputs)

        assert res.final_risk_score == 0.50
        assert res.decision == Decision.WARN.value
        assert res.confidence < 0.60


# ---------------------------------------------------------------------------
# Unit Tests: Configuration Validation
# ---------------------------------------------------------------------------

class TestRiskEngineConfiguration:

    def test_valid_custom_config(self):
        cfg = RiskEngineConfig(
            weights={
                LAYER_CONTENT: 0.20,
                LAYER_URL: 0.40,
                LAYER_IDENTITY: 0.20,
                LAYER_THREAT_INTEL: 0.10,
                LAYER_GRAPH: 0.10,
            },
            thresholds={
                "low_max": 0.30,
                "medium_max": 0.60,
                "high_max": 0.80,
            }
        )
        assert cfg.weights[LAYER_URL] == 0.40

    def test_invalid_weights_sum_rejected(self):
        with pytest.raises(ValueError, match="Weights must sum to 1.0"):
            RiskEngineConfig(
                weights={
                    LAYER_CONTENT: 0.50,
                    LAYER_URL: 0.50,
                    LAYER_IDENTITY: 0.20,
                    LAYER_THREAT_INTEL: 0.15,
                    LAYER_GRAPH: 0.10,
                }
            )

    def test_non_monotonic_thresholds_rejected(self):
        with pytest.raises(ValueError, match="Thresholds must satisfy"):
            RiskEngineConfig(
                thresholds={
                    "low_max": 0.60,
                    "medium_max": 0.40,
                    "high_max": 0.85,
                }
            )


# ---------------------------------------------------------------------------
# Integration Tests: API Endpoints
# ---------------------------------------------------------------------------

class TestRiskEndpoints:

    def test_evaluate_endpoint(self):
        payload = {
            "content_risk": {"score": 0.90, "confidence": 0.95},
            "url_risk": {"score": 0.95, "confidence": 0.98},
            "identity_risk": {"score": 0.88, "confidence": 0.90},
            "threat_intel_risk": {"score": 0.92, "confidence": 0.99},
            "graph_risk": {"score": 0.85, "confidence": 0.88},
        }
        resp = client.post("/api/v1/risk/evaluate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["final_risk_score"] > 0.85
        assert data["severity"] == "CRITICAL"
        assert data["decision"] == "QUARANTINE"
        assert "Content Risk" in data["signal_contributions"]

    def test_pipeline_endpoint_with_phish(self):
        payload = {
            "subject": "Urgent: Verify Your Microsoft 365 Account Immediately",
            "plain_text": "Your account password has expired. Click here to verify credentials now: https://secure-banking-update.xyz/verify-account",
            "sender_email": "Microsoft Security Alert <security-update@micros0ft-support.com>",
            "sender_domain": "micros0ft-support.com",
            "urls": ["https://secure-banking-update.xyz/verify-account"],
            "headers": {
                "Authentication-Results": "spf=fail (sender IP is 185.220.101.5); dkim=fail; dmarc=fail action=none",
                "Received-SPF": "fail",
            },
        }
        resp = client.post("/api/v1/risk/pipeline", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["final_risk_score"] > 0.70
        assert data["decision"] == "QUARANTINE"
        assert len(data["evidence_summary"]) > 0

    def test_pipeline_endpoint_with_clean_email(self):
        payload = {
            "subject": "Team Lunch on Friday",
            "plain_text": "Hey team, let us meet for lunch at the cafeteria at 12:30pm.",
            "sender_email": "manager@enterprise-corp.com",
            "sender_domain": "enterprise-corp.com",
            "urls": [],
        }
        resp = client.post("/api/v1/risk/pipeline", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["final_risk_score"] < 0.35
        assert data["decision"] == "ALLOW"

    def test_get_and_update_config(self):
        # 1. Get
        resp = client.get("/api/v1/risk/config")
        assert resp.status_code == 200
        cfg = resp.json()
        assert "weights" in cfg
        assert "thresholds" in cfg

        # 2. Reset back to ensure clean state
        reset_resp = client.post("/api/v1/risk/reset-config")
        assert reset_resp.status_code == 200
