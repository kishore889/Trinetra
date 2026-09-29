"""
Tests for Gmail OAuth helper utilities and endpoints.
"""

from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.core.token_crypto import encrypt_token, decrypt_token
from app.db.session import get_db

client = TestClient(app)


def test_token_encryption_decryption():
    raw_token = "ya29.a0AfH6SMD_test_token_sample_value"
    encrypted = encrypt_token(raw_token)
    assert encrypted != raw_token
    decrypted = decrypt_token(encrypted)
    assert decrypted == raw_token


def test_oauth_status_endpoint_disconnected():
    class MockDb:
        def query(self, model):
            mock_query = MagicMock()
            mock_query.filter.return_value.first.return_value = None
            return mock_query

    def override_db():
        yield MockDb()

    app.dependency_overrides[get_db] = override_db
    try:
        response = client.get("/api/v1/auth/google/status")
        assert response.status_code == 200
        data = response.json()
        assert data["is_connected"] is False
        assert data["email_address"] is None
        # Ensures no secret fields leaked
        assert "access_token" not in data
        assert "refresh_token" not in data
    finally:
        app.dependency_overrides.clear()
