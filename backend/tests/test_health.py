"""
Tests for TRINETRA Health endpoint and FastAPI app.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import get_db

client = TestClient(app)


def test_health_endpoint():
    class MockDb:
        def execute(self, query):
            return True

    def override_get_db():
        yield MockDb()

    app.dependency_overrides[get_db] = override_get_db
    try:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "TRINETRA"
        assert data["status"] == "healthy"
        assert data["database_connected"] is True
        assert len(data["active_layers"]) == 7
    finally:
        app.dependency_overrides.clear()
