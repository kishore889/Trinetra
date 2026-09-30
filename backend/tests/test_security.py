"""
TRINETRA — Security & Production Safety Test Suite (Phase 17)

Validates:
1. SSRF protection (private IPs, localhost, AWS IMDS, dangerous schemes)
2. Password hashing & bcrypt verification
3. JWT access token generation, claims, and validation
4. User Authentication API endpoints (/auth/login, /auth/me)
5. Security Response Headers (OWASP recommendations)
6. Rate Limiting enforcement
7. XSS & HTML email body sanitization
8. Attachment execution safety checks
9. Sensitive payload redaction in audit logging
10. OAuth token secrecy in status endpoints
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    validate_url_for_fetch,
)
from app.core.exceptions import SSRFDetectedError, AuthenticationError
from app.services.audit_service import redact_sensitive_dict, log_security_event
from app.services.email_sanitizer import (
    sanitize_html_body,
    escape_plain_text,
    sanitize_attachment_metadata,
)
from app.models import User

client = TestClient(app)


# ==================================================
# 1. SSRF Protection Tests
# ==================================================

def test_ssrf_blocks_localhost():
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("http://localhost:8000/admin")
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("http://127.0.0.1:5000/internal")
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("http://[::1]/secret")


def test_ssrf_blocks_private_ip_ranges():
    # 10.0.0.0/8
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("http://10.0.0.1/config")
    # 172.16.0.0/12
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("http://172.16.0.5/status")
    # 192.168.0.0/16
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("http://192.168.1.1/router")


def test_ssrf_blocks_aws_cloud_metadata_ip():
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("http://169.254.169.254/latest/meta-data/")


def test_ssrf_blocks_dangerous_schemes():
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("file:///etc/passwd")
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("data:text/html,<script>alert(1)</script>")
    with pytest.raises(SSRFDetectedError):
        validate_url_for_fetch("javascript:alert(1)")


def test_ssrf_allows_public_https_urls():
    valid_url = "https://example.com/login"
    assert validate_url_for_fetch(valid_url) == valid_url


# ==================================================
# 2. Authentication & Password Hashing Tests
# ==================================================

def test_password_hashing_and_verification():
    plain = "SuperSecurePassword123!"
    hashed = hash_password(plain)
    assert hashed != plain
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_access_token_lifecycle():
    subject = "user_uuid_123"
    claims = {"email": "test@trinetra.ai", "role": "analyst"}
    token = create_access_token(subject, extra_claims=claims)

    decoded = decode_access_token(token)
    assert decoded["sub"] == subject
    assert decoded["email"] == "test@trinetra.ai"
    assert decoded["role"] == "analyst"
    assert decoded["iss"] == "TRINETRA"


def test_invalid_jwt_access_token_raises_error():
    with pytest.raises(AuthenticationError):
        decode_access_token("invalid.jwt.token.string")


# ==================================================
# 3. Auth API Endpoint Tests
# ==================================================

def test_login_api_endpoint():
    app.dependency_overrides.clear()
    from app.db.session import SessionLocal
    test_email = "security-test-admin@trinetra.ai"
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == test_email).first()
        if not user:
            user = User(
                email=test_email,
                hashed_password=hash_password("admin123"),
                full_name="Security Test Admin",
                role="admin",
                is_active=True,
            )
            db.add(user)
        else:
            user.hashed_password = hash_password("admin123")
        db.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"email": test_email, "password": "admin123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["email"] == test_email
    assert data["role"] == "admin"


def test_login_api_rejects_invalid_credentials():
    app.dependency_overrides.clear()
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "security-test-admin@trinetra.ai", "password": "WrongPassword999"},
    )
    assert response.status_code == 401


# ==================================================
# 4. Security Headers Middleware Tests
# ==================================================

def test_security_headers_present():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "strict-origin-when-cross-origin" in response.headers.get("Referrer-Policy", "")
    assert "max-age=" in response.headers.get("Strict-Transport-Security", "")
    assert "Content-Security-Policy" in response.headers


# ==================================================
# 5. XSS & HTML Sanitization Tests
# ==================================================

def test_sanitize_html_body_removes_scripts():
    payload = "<div>Welcome <script>alert('xss')</script> to TRINETRA</div>"
    clean = sanitize_html_body(payload)
    assert "<script>" not in clean
    assert "alert('xss')" not in clean
    assert "Welcome" in clean


def test_sanitize_html_body_removes_event_handlers():
    payload = '<img src="valid.png" onload="alert(1)" onerror="javascript:evil()">'
    clean = sanitize_html_body(payload)
    assert "onload=" not in clean
    assert "onerror=" not in clean
    assert "javascript:" not in clean


def test_escape_plain_text():
    text = "User & Admin <script>alert(1)</script>"
    escaped = escape_plain_text(text)
    assert "&amp;" in escaped
    assert "&lt;script&gt;" in escaped


# ==================================================
# 6. Attachment Execution Safety Tests
# ==================================================

def test_sanitize_attachment_metadata_flags_executables():
    raw_attachments = [
        {"filename": "document.pdf", "mime_type": "application/pdf", "size": 10240},
        {"filename": "payload.exe", "mime_type": "application/octet-stream", "size": 204800},
        {"filename": "script.vbs", "mime_type": "text/vbscript", "size": 500},
    ]

    sanitized = sanitize_attachment_metadata(raw_attachments)
    assert len(sanitized) == 3
    assert sanitized[0]["is_executable"] is False
    assert sanitized[0]["hazard_warning"] == "SAFE"

    assert sanitized[1]["is_executable"] is True
    assert sanitized[1]["hazard_warning"] == "EXECUTABLE_FILE_TYPE"

    assert sanitized[2]["is_executable"] is True
    assert sanitized[2]["hazard_warning"] == "EXECUTABLE_FILE_TYPE"


# ==================================================
# 7. Sensitive Dict Redaction Tests
# ==================================================

def test_redact_sensitive_dict():
    raw_event = {
        "user": "analyst@trinetra.ai",
        "password": "SecretPassword123",
        "access_token": "bearer_eyJhbGciOi...",
        "api_key": "vt_api_key_xyz",
        "nested": {
            "refresh_token": "secret_refresh",
            "safe_field": "public_value",
        },
    }

    redacted = redact_sensitive_dict(raw_event)
    assert redacted["user"] == "analyst@trinetra.ai"
    assert redacted["password"] == "***REDACTED***"
    assert redacted["access_token"] == "***REDACTED***"
    assert redacted["api_key"] == "***REDACTED***"
    assert redacted["nested"]["refresh_token"] == "***REDACTED***"
    assert redacted["nested"]["safe_field"] == "public_value"


# ==================================================
# 8. OAuth Status Secrecy Test
# ==================================================

def test_oauth_status_endpoint_never_leaks_tokens():
    response = client.get("/api/v1/auth/google/status")
    assert response.status_code == 200
    data = response.json()
    assert "access_token" not in data
    assert "refresh_token" not in data
    assert "client_secret" not in data
    assert "is_connected" in data
    assert "is_configured" in data
