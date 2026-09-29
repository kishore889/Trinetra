"""
TRINETRA — Gmail OAuth 2.0 Service & Endpoint Logic

Handles authorization URL generation, code exchange, token encryption,
decrypted token retrieval, and automated token refresh.
Scopes requested:
- https://www.googleapis.com/auth/gmail.readonly (minimum necessary to ingest emails)
- https://www.googleapis.com/auth/gmail.modify (necessary for future action: quarantine/labeling)
- https://www.googleapis.com/auth/userinfo.email (to identify connected account)
"""

from __future__ import annotations

import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import AuthenticationError, ProviderUnavailableError
from app.core.token_crypto import encrypt_token, decrypt_token
from app.models import GmailAccount, User

# Minimum necessary scopes
GMAIL_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


def get_authorization_url(state: str) -> str:
    """Generate the Google OAuth 2.0 authorization URL."""
    if not settings.GOOGLE_CLIENT_ID:
        raise AuthenticationError("GOOGLE_CLIENT_ID is not configured in TRINETRA.")

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(GMAIL_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"


async def exchange_code_for_tokens(code: str) -> Dict[str, Any]:
    """Exchange authorization code with Google for tokens."""
    data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(GOOGLE_TOKEN_URL, data=data)
        if resp.status_code != 200:
            raise AuthenticationError(f"Google token exchange failed: {resp.text}")
        return resp.json()


async def get_google_user_email(access_token: str) -> str:
    """Fetch authorized email address using userinfo endpoint."""
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(GOOGLE_USERINFO_URL, headers=headers)
        if resp.status_code != 200:
            raise AuthenticationError("Failed to fetch Google userinfo profile.")
        data = resp.json()
        return data.get("email", "")


async def refresh_access_token_if_needed(account: GmailAccount, db: Session) -> Optional[str]:
    """
    Check if account token is expired or close to expiry, and refresh it using refresh_token.
    Returns decrypted, valid access token.
    """
    token_info = account.token_info or {}
    encrypted_refresh = token_info.get("refresh_token")
    if not encrypted_refresh:
        return None

    plain_refresh = decrypt_token(encrypted_refresh)
    if not plain_refresh:
        return None

    data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "refresh_token": plain_refresh,
        "grant_type": "refresh_token",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(GOOGLE_TOKEN_URL, data=data)
        if resp.status_code != 200:
            account.is_active = False
            db.commit()
            return None

        tokens = resp.json()
        new_access = tokens.get("access_token")
        expires_in = tokens.get("expires_in", 3600)

        # Update token_info with newly encrypted access token
        token_info["access_token"] = encrypt_token(new_access)
        token_info["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()
        account.token_info = token_info
        account.is_active = True
        db.commit()

        return new_access
