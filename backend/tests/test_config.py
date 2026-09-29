"""
Tests for TRINETRA configuration and settings loader.
"""

from app.core.config import Settings, get_settings


def test_settings_initialization():
    settings = get_settings()
    assert settings.APP_NAME == "TRINETRA"
    assert "TRINETRA" in settings.APP_FULL_NAME
    assert settings.API_V1_PREFIX == "/api/v1"
    assert sum(settings.risk_weights.values()) == 1.0


def test_cors_origin_parsing():
    settings = Settings(ALLOWED_ORIGINS="http://localhost:5173,http://example.com")
    assert "http://localhost:5173" in settings.ALLOWED_ORIGINS
    assert "http://example.com" in settings.ALLOWED_ORIGINS
