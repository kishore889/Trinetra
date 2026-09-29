"""
Tests model imports, relationships, and metadata validation.
"""

from app.db.base import Base
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
)


def test_models_registration():
    expected_tables = {
        "users",
        "gmail_accounts",
        "emails",
        "email_urls",
        "domains",
        "detections",
        "risk_signals",
        "threat_indicators",
        "graph_entities",
        "graph_relationships",
        "feedbacks",
        "incidents",
    }
    registered_tables = set(Base.metadata.tables.keys())
    assert expected_tables.issubset(registered_tables)


def test_enum_definitions():
    assert EmailState.RECEIVED.value == "RECEIVED"
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Decision.QUARANTINE.value == "QUARANTINE"
