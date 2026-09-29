"""
TRINETRA — Gmail OAuth Endpoints

GET /api/v1/auth/google/url       -> Returns OAuth authorization URL
GET /api/v1/auth/google/callback  -> Receives OAuth code, stores encrypted tokens
GET /api/v1/auth/google/status    -> Reports current connection status (never leaking secrets)
POST /api/v1/auth/google/disconnect -> Disconnects and purges token metadata
"""

from __future__ import annotations

import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import AuthenticationError, ResourceNotFoundError
from app.core.token_crypto import encrypt_token
from app.db.session import get_db
from app.models import GmailAccount, User
from app.services.gmail_oauth import (
    get_authorization_url,
    exchange_code_for_tokens,
    get_google_user_email,
)

router = APIRouter()


class OAuthURLResponse(BaseModel):
    authorization_url: str


class GmailConnectionStatusResponse(BaseModel):
    is_connected: bool
    email_address: Optional[str] = None
    account_id: Optional[str] = None
    watch_active: bool = False
    is_configured: bool = False


def _get_or_create_default_user(db: Session) -> User:
    """Helper to retrieve or seed default SOC analyst user for initial OAuth linking."""
    user = db.query(User).filter(User.email == "analyst@trinetra.ai").first()
    if not user:
        user = User(
            email="analyst@trinetra.ai",
            hashed_password="hashed_placeholder_for_phase1",
            full_name="SOC Lead Analyst",
            is_active=True,
            role="analyst",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


@router.get("/google/url", response_model=OAuthURLResponse)
def get_google_oauth_url() -> OAuthURLResponse:
    """Provides authorization URL for Google OAuth consent screen."""
    state = str(uuid.uuid4())
    url = get_authorization_url(state=state)
    return OAuthURLResponse(authorization_url=url)


@router.get("/google/callback")
async def google_oauth_callback(
    code: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Handles Google OAuth redirect with authorization code.
    Exchanges code for tokens, retrieves user email, encrypts tokens, and stores them in DB.
    Redirects back to frontend Gmail Connection page.
    """
    frontend_redirect_base = "http://localhost:5173/gmail"

    if error or not code:
        return RedirectResponse(url=f"{frontend_redirect_base}?status=error&message={error or 'no_code'}")

    try:
        token_payload = await exchange_code_for_tokens(code)
        access_token = token_payload.get("access_token")
        refresh_token = token_payload.get("refresh_token")

        if not access_token:
            return RedirectResponse(url=f"{frontend_redirect_base}?status=error&message=token_exchange_failed")

        user_email = await get_google_user_email(access_token)
        if not user_email:
            return RedirectResponse(url=f"{frontend_redirect_base}?status=error&message=email_retrieval_failed")

        user = _get_or_create_default_user(db)

        # Upsert GmailAccount
        account = db.query(GmailAccount).filter(GmailAccount.email_address == user_email).first()
        if not account:
            account = GmailAccount(
                user_id=user.id,
                email_address=user_email,
            )
            db.add(account)

        # Encrypt tokens before storing
        token_info = {
            "access_token": encrypt_token(access_token),
            "token_type": token_payload.get("token_type", "Bearer"),
        }
        if refresh_token:
            token_info["refresh_token"] = encrypt_token(refresh_token)

        account.token_info = token_info
        account.is_active = True
        db.commit()

        return RedirectResponse(url=f"{frontend_redirect_base}?status=connected&email={user_email}")
    except Exception as exc:
        return RedirectResponse(url=f"{frontend_redirect_base}?status=error&message=exception")


@router.get("/google/status", response_model=GmailConnectionStatusResponse)
def get_connection_status(db: Session = Depends(get_db)) -> GmailConnectionStatusResponse:
    """
    Returns public Gmail connection state without leaking secrets, tokens, or credentials.
    """
    is_configured = settings.google_oauth_configured
    account = db.query(GmailAccount).filter(GmailAccount.is_active == True).first()

    if not account:
        return GmailConnectionStatusResponse(
            is_connected=False,
            is_configured=is_configured,
        )

    return GmailConnectionStatusResponse(
        is_connected=True,
        email_address=account.email_address,
        account_id=str(account.id),
        watch_active=bool(account.watch_expiration),
        is_configured=is_configured,
    )


@router.post("/google/disconnect", status_code=status.HTTP_200_OK)
def disconnect_gmail(db: Session = Depends(get_db)):
    """
    Revokes local account tokens and sets status to disconnected.
    """
    accounts = db.query(GmailAccount).filter(GmailAccount.is_active == True).all()
    for acc in accounts:
        acc.is_active = False
        acc.token_info = None
        acc.history_id = None
        acc.watch_expiration = None
    db.commit()
    return {"status": "disconnected", "message": "Gmail account disconnected successfully."}
