"""
TRINETRA — Security Utilities

Password hashing, JWT token creation/verification, and security helpers.
OAuth tokens are handled by the Gmail integration layer, not here.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.core.exceptions import AuthenticationError, SSRFDetectedError

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Private IP ranges blocked for SSRF protection
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
]

_BLOCKED_SCHEMES = {"file", "ftp", "data", "javascript", "vbscript"}


# ==================================================
# Password Utilities
# ==================================================

def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ==================================================
# JWT Token Utilities
# ==================================================

def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[dict] = None,
) -> str:
    """
    Create a signed JWT access token.

    Args:
        subject: Token subject (typically user ID as string)
        expires_delta: Custom expiry duration; defaults to settings value
        extra_claims: Additional claims to include in the token payload

    Returns:
        Signed JWT token string
    """
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": "TRINETRA",
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT access token.

    Args:
        token: JWT token string

    Returns:
        Decoded payload dict

    Raises:
        AuthenticationError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        return payload
    except JWTError as exc:
        raise AuthenticationError(f"Invalid or expired token: {exc}") from exc


# ==================================================
# SSRF Protection
# ==================================================

def validate_url_for_fetch(url: str) -> str:
    """
    Validate a URL before fetching it (SSRF protection).

    Blocks:
    - Private/internal IP ranges
    - Disallowed URI schemes (file://, data://, etc.)
    - Localhost / loopback addresses

    Args:
        url: URL to validate

    Returns:
        The original URL if safe

    Raises:
        SSRFDetectedError: If the URL targets an internal resource
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise SSRFDetectedError(url)

    # Block dangerous schemes
    if parsed.scheme.lower() in _BLOCKED_SCHEMES:
        raise SSRFDetectedError(url)

    # Only allow http/https
    if parsed.scheme.lower() not in {"http", "https"}:
        raise SSRFDetectedError(url)

    hostname = parsed.hostname or ""

    # Block localhost by name
    if hostname.lower() in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        raise SSRFDetectedError(url)

    # Block private IP ranges
    try:
        addr = ipaddress.ip_address(hostname)
        for network in _PRIVATE_NETWORKS:
            if addr in network:
                raise SSRFDetectedError(url)
    except ValueError:
        # hostname is a domain name, not a raw IP — allowed
        pass

    return url


def sanitize_log_value(value: str, max_length: int = 100) -> str:
    """
    Sanitize a value for safe logging (truncate + strip newlines).
    Prevents log injection.
    """
    if not value:
        return ""
    sanitized = value.replace("\n", " ").replace("\r", " ").strip()
    return sanitized[:max_length] + ("..." if len(sanitized) > max_length else "")
