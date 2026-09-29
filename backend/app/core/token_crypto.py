"""
TRINETRA — Secure Token Encryption Helper

Encrypts sensitive OAuth tokens (access_token, refresh_token) at rest
using AES-256 (via cryptography.fernet) keyed from the app SECRET_KEY.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet
from app.core.config import settings


def _get_fernet_key() -> bytes:
    # Derive a 32-byte urlsafe base64 key deterministically from SECRET_KEY
    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_token(plain_token: str) -> str:
    """Encrypt a plain token string."""
    if not plain_token:
        return ""
    fernet = Fernet(_get_fernet_key())
    return fernet.encrypt(plain_token.encode()).decode()


def decrypt_token(encrypted_token: str) -> Optional[str]:
    """Decrypt an encrypted token string."""
    if not encrypted_token:
        return None
    try:
        fernet = Fernet(_get_fernet_key())
        return fernet.decrypt(encrypted_token.encode()).decode()
    except Exception:
        return None
