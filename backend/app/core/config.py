"""
TRINETRA — Application Configuration

Uses Pydantic Settings for type-safe, environment-variable-driven configuration.
All secrets must be provided via environment variables or .env file.
No secrets are hard-coded.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_BASE_DIR = Path(__file__).resolve().parent.parent.parent  # backend/
_ROOT_DIR = _BASE_DIR.parent  # TRINETRA/
_ENV_FILES = [
    str(_BASE_DIR / ".env"),
    str(_ROOT_DIR / ".env"),
    ".env",
]


class Settings(BaseSettings):
    """
    TRINETRA application settings.
    Values are loaded from environment variables / .env file.
    """

    model_config = SettingsConfigDict(
        env_file=_ENV_FILES,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --------------------------------------------------
    # Application Identity
    # --------------------------------------------------
    APP_NAME: str = "TRINETRA"
    APP_FULL_NAME: str = "TRINETRA — AI-Powered Real-Time Phishing Detection & Threat Intelligence System"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = False

    # --------------------------------------------------
    # API Configuration
    # --------------------------------------------------
    API_V1_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
    ]

    # --------------------------------------------------
    # Database
    # --------------------------------------------------
    DATABASE_URL: str = "postgresql://trinetra:trinetra_dev@localhost:5432/trinetra"
    TEST_DATABASE_URL: str = "postgresql://trinetra:trinetra_dev@localhost:5432/trinetra_test"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_POOL_TIMEOUT: int = 30

    # --------------------------------------------------
    # Security
    # --------------------------------------------------
    SECRET_KEY: str = secrets.token_hex(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    RATE_LIMIT_PER_MINUTE: int = 60

    # --------------------------------------------------
    # Google OAuth 2.0
    # --------------------------------------------------
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/google/callback"

    # --------------------------------------------------
    # Google Cloud (Gmail Watch + Pub/Sub)
    # Production: Gmail Watch + Pub/Sub + History API
    # Development fallback: local polling
    # --------------------------------------------------
    GOOGLE_CLOUD_PROJECT: str = ""
    GOOGLE_PUBSUB_TOPIC: str = ""

    # --------------------------------------------------
    # Gemini API
    # Used for explainability / NL explanation only.
    # NOT the sole phishing classifier.
    # --------------------------------------------------
    GEMINI_API_KEY: str = ""

    # --------------------------------------------------
    # Threat Intelligence Providers (all optional)
    # TRINETRA functions without these.
    # --------------------------------------------------
    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""

    # --------------------------------------------------
    # Risk Engine — Layer Weights (must sum to 1.0)
    # --------------------------------------------------
    RISK_WEIGHT_CONTENT: float = 0.25
    RISK_WEIGHT_URL: float = 0.30
    RISK_WEIGHT_IDENTITY: float = 0.20
    RISK_WEIGHT_THREAT_INTEL: float = 0.15
    RISK_WEIGHT_GRAPH: float = 0.10

    # --------------------------------------------------
    # Risk Engine — Decision Thresholds
    # Below WARN_THRESHOLD  → ALLOW
    # Below QUARANTINE      → WARN
    # Above QUARANTINE      → QUARANTINE
    # --------------------------------------------------
    RISK_THRESHOLD_WARN: float = 0.40
    RISK_THRESHOLD_QUARANTINE: float = 0.70

    # --------------------------------------------------
    # Logging
    # --------------------------------------------------
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json | console

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | List[str]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def risk_weights(self) -> dict:
        return {
            "content": self.RISK_WEIGHT_CONTENT,
            "url": self.RISK_WEIGHT_URL,
            "identity": self.RISK_WEIGHT_IDENTITY,
            "threat_intel": self.RISK_WEIGHT_THREAT_INTEL,
            "graph": self.RISK_WEIGHT_GRAPH,
        }

    @property
    def google_oauth_configured(self) -> bool:
        return bool(self.GOOGLE_CLIENT_ID and self.GOOGLE_CLIENT_SECRET)

    @property
    def gemini_configured(self) -> bool:
        return bool(self.GEMINI_API_KEY)

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.VIRUSTOTAL_API_KEY)

    @property
    def safe_browsing_configured(self) -> bool:
        return bool(self.GOOGLE_SAFE_BROWSING_API_KEY)

    @property
    def pubsub_configured(self) -> bool:
        return bool(self.GOOGLE_CLOUD_PROJECT and self.GOOGLE_PUBSUB_TOPIC)


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


# Module-level singleton for convenience
settings = get_settings()
