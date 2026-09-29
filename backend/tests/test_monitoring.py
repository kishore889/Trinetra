"""
Tests for Gmail Monitoring: Pub/Sub Webhook parsing, Watch expiration tracking,
and status endpoint.
"""

import base64
import json
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db

client = TestClient(app)


def test_monitoring_status_endpoint():
    class MockDb:
        def query(self, model):
            mock_query = MagicMock()
            mock_query.filter.return_value.first.return_value = None
            mock_query.count.return_value = 5
            return mock_query

    def override_db():
        yield MockDb()

    app.dependency_overrides[get_db] = override_db
    try:
        response = client.get("/api/v1/monitor/status")
        assert response.status_code == 200
        data = response.json()
        assert "monitoring_active" in data
        assert "watch_status" in data
        assert data["messages_processed"] == 5
    finally:
        app.dependency_overrides.clear()


def test_pubsub_webhook_event_decoding():
    raw_payload = {"emailAddress": "test@domain.com", "historyId": "987654"}
    b64_data = base64.b64encode(json.dumps(raw_payload).encode("utf-8")).decode("utf-8")

    class MockDb:
        def query(self, model):
            mock_query = MagicMock()
            mock_query.filter.return_value.first.return_value = None
            return mock_query

    def override_db():
        yield MockDb()

    app.dependency_overrides[get_db] = override_db
    try:
        webhook_body = {
            "message": {
                "data": b64_data,
                "messageId": "pubsub-msg-101",
                "publishTime": "2026-09-29T12:00:00Z"
            }
        }
        response = client.post("/api/v1/monitor/webhook", json=webhook_body)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["acknowledged", "synced"]
    finally:
        app.dependency_overrides.clear()
