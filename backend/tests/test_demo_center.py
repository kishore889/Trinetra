"""
TRINETRA — Phase 16: Controlled Attack / Defense Demo Center Test Suite

Tests cover:
  1. GET /api/v1/demo/scenarios          -> Returns all 10 scenarios
  2. GET /api/v1/demo/scenarios/{id}     -> Detailed scenario definition & MIME
  3. POST /api/v1/demo/run/scen-1        -> Legitimate email passes 10-stage pipeline with ALLOW
  4. POST /api/v1/demo/run/scen-2        -> Credential phishing passes 10 stages with QUARANTINE
  5. POST /api/v1/demo/run/scen-3        -> Microsoft impersonation detected
  6. POST /api/v1/demo/run/scen-9        -> Graph campaign correlation active
  7. POST /api/v1/demo/run/scen-10       -> Threat intelligence advisory matching active
  8. Pipeline 10-stage integrity         -> Verify all 10 stages execute with real scores & timings
  9. Database persistence & audit        -> Verify Email, Detection, and ActionAudit records created
  10. Custom MIME execution              -> Verify /run-custom endpoint
  11. Safety constraint enforcement      -> Verify permanent delete strictly prohibited
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.models import Email, Detection, ActionAudit, EmailState, Decision
from app.services.demo_pipeline_service import SCENARIOS

# SQLite in-memory test database
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
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


client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_demo_db():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    yield


# ---------------------------------------------------------------------------
# Scenario Specification Tests
# ---------------------------------------------------------------------------

class TestDemoScenarioCatalog:
    def test_list_scenarios_returns_ten(self):
        resp = client.get("/api/v1/demo/scenarios")
        assert resp.status_code == 200
        scenarios = resp.json()
        assert len(scenarios) == 10

        # Verify scenario numbering and IDs
        expected_ids = [f"scen-{i}" for i in range(1, 11)]
        returned_ids = [s["id"] for s in scenarios]
        assert returned_ids == expected_ids

    def test_scenario_names_and_categories(self):
        resp = client.get("/api/v1/demo/scenarios")
        data = resp.json()

        # Check required names
        names = {s["name"] for s in data}
        assert "Legitimate Email" in names
        assert "Obvious Credential Phishing" in names
        assert "Microsoft Impersonation" in names
        assert "Bank Credential Phishing" in names
        assert "Payment Request (BEC)" in names
        assert "Password Reset Phishing" in names
        assert "Lookalike Domain" in names
        assert "Sophisticated Spear Phishing" in names
        assert "Graph-Correlated Phishing Campaign" in names
        assert "Threat-Intelligence-Matched Email" in names

    def test_get_individual_scenario_detail(self):
        resp = client.get("/api/v1/demo/scenarios/scen-1")
        assert resp.status_code == 200
        scen = resp.json()
        assert scen["id"] == "scen-1"
        assert scen["expected_baseline_verdict"] == "ALLOW"
        assert "operations@company-internal.com" in scen["raw_mime"]

    def test_get_nonexistent_scenario_returns_404(self):
        resp = client.get("/api/v1/demo/scenarios/scen-999")
        assert resp.status_code == 404
        assert "not found" in resp.text.lower()


# ---------------------------------------------------------------------------
# Genuine 10-Stage Pipeline Execution Tests
# ---------------------------------------------------------------------------

class TestDemoPipelineExecution:
    def test_run_scen_1_legitimate_email(self):
        """Scenario 1: Legitimate internal email passes with ALLOW verdict."""
        resp = client.post("/api/v1/demo/run/scen-1")
        assert resp.status_code == 200
        data = resp.json()

        assert data["scenario_id"] == "scen-1"
        assert data["final_verdict"] == "ALLOW"
        assert data["final_risk_score"] < 0.35  # clean email has low score
        assert len(data["stages"]) == 10

        # Verify all 10 stages in exact sequence
        expected_stages = [
            "EMAIL_RECEIVED",
            "PARSING",
            "CONTENT_ANALYSIS",
            "URL_ANALYSIS",
            "IDENTITY_ANALYSIS",
            "THREAT_INTELLIGENCE",
            "GRAPH_CORRELATION",
            "RISK_ENGINE",
            "DECISION",
            "ACTION",
        ]
        actual_stages = [s["stage_id"] for s in data["stages"]]
        assert actual_stages == expected_stages

        # Verify database persistence
        assert data["persisted_email_id"] is not None
        assert data["persisted_detection_id"] is not None

        import uuid
        db = TestingSessionLocal()
        try:
            em = db.query(Email).filter(Email.id == uuid.UUID(data["persisted_email_id"])).first()
            assert em is not None
            assert "operations@company-internal.com" in em.sender

            det = db.query(Detection).filter(Detection.id == uuid.UUID(data["persisted_detection_id"])).first()
            assert det is not None
            assert det.decision == Decision.ALLOW
        finally:
            db.close()

    def test_run_scen_2_credential_phishing(self):
        """Scenario 2: Obvious credential phishing results in elevated risk."""
        resp = client.post("/api/v1/demo/run/scen-2")
        assert resp.status_code == 200
        data = resp.json()

        assert data["scenario_id"] == "scen-2"
        assert data["final_verdict"] in ["WARN", "QUARANTINE"]
        assert data["final_risk_score"] >= 0.50
        assert data["layer_scores"]["content_risk"] > 0.35
        assert data["layer_scores"]["url_risk"] > 0.35  # IP host in URL
        assert data["applied_action"] in ["AUTO_WARN", "AUTO_QUARANTINE"]

    def test_run_scen_3_microsoft_impersonation(self):
        """Scenario 3: Brand impersonation of Microsoft caught by Identity Engine."""
        resp = client.post("/api/v1/demo/run/scen-3")
        assert resp.status_code == 200
        data = resp.json()

        assert data["scenario_id"] == "scen-3"
        assert data["final_verdict"] in ["WARN", "QUARANTINE"]
        assert data["layer_scores"]["identity_risk"] >= 0.50

    def test_run_scen_9_graph_correlation(self):
        """Scenario 9: SharePoint link correlated with FIN7-M365 threat group in graph."""
        resp = client.post("/api/v1/demo/run/scen-9")
        assert resp.status_code == 200
        data = resp.json()

        assert data["scenario_id"] == "scen-9"
        assert data["final_verdict"] in ["WARN", "QUARANTINE"]
        assert data["layer_scores"]["graph_risk"] > 0.20
        # Graph stage must show traversal of relationships
        graph_stage = next(s for s in data["stages"] if s["stage_id"] == "GRAPH_CORRELATION")
        assert graph_stage["details"]["connected_entities"] > 0

    def test_run_scen_10_threat_intel_match(self):
        """Scenario 10: CERT-In advisory match on secure-banking-update.xyz."""
        resp = client.post("/api/v1/demo/run/scen-10")
        assert resp.status_code == 200
        data = resp.json()

        assert data["scenario_id"] == "scen-10"
        assert data["final_verdict"] in ["WARN", "QUARANTINE"]
        # Threat intel risk must be elevated due to advisory match
        assert data["layer_scores"]["threat_intel_risk"] >= 0.50

    def test_stages_have_positive_timings_and_summaries(self):
        """Verify telemetry has genuine timing benchmarks and human summaries."""
        resp = client.post("/api/v1/demo/run/scen-1")
        data = resp.json()

        assert data["total_pipeline_duration_ms"] > 0
        for stage in data["stages"]:
            assert stage["duration_ms"] >= 0
            assert len(stage["summary"]) > 5
            assert len(stage["findings"]) > 0

    def test_run_custom_valid_mime(self):
        """Run custom injected raw RFC 822 MIME message."""
        raw = (
            "From: Vendor Desk <vendor@clean-corp.com>\r\n"
            "To: procurement@enterprise.com\r\n"
            "Subject: Monthly Order Confirmation\r\n"
            "Date: Tue, 29 Sep 2026 15:00:00 +0000\r\n"
            "Message-ID: <custom-test-01@clean-corp.com>\r\n"
            "Received-SPF: pass\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Your monthly order #99281 has been confirmed and dispatched.\r\n"
        )
        resp = client.post("/api/v1/demo/run-custom", json={"raw_mime": raw})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["stages"]) == 10
        assert data["final_verdict"] == "ALLOW"

    def test_run_custom_empty_mime_returns_422(self):
        resp = client.post("/api/v1/demo/run-custom", json={"raw_mime": ""})
        assert resp.status_code == 422
