"""
TRINETRA — Authentication & User Management Endpoints

Handles user login, JWT issuance, profile retrieval, and user registration.
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_db, require_roles
from app.core.security import create_access_token, hash_password, verify_password
from app.models import User
from app.services.audit_service import log_security_event

router = APIRouter()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    email: str
    role: str
    full_name: Optional[str] = None


class UserProfileResponse(BaseModel):
    user_id: str
    email: str
    role: str
    full_name: Optional[str] = None
    is_active: bool
    is_superuser: bool


class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str
    role: str = "analyst"


@router.post("/token", response_model=TokenResponse)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """OAuth2 password form login endpoint returning signed JWT access token."""
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        log_security_event(
            db=db,
            event_type="AUTH_FAILED",
            actor=form_data.username,
            target=form_data.username,
            reason="Invalid credentials",
            new_state="REJECTED",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is deactivated.",
        )

    token = create_access_token(
        subject=str(user.id),
        extra_claims={"email": user.email, "role": user.role},
    )

    log_security_event(
        db=db,
        event_type="AUTH_SUCCESS",
        actor=user.email,
        target=str(user.id),
        reason="Successful authentication",
        new_state="AUTHENTICATED",
    )

    return TokenResponse(
        access_token=token,
        user_id=str(user.id),
        email=user.email,
        role=user.role,
        full_name=user.full_name,
    )


@router.post("/login", response_model=TokenResponse)
def login_json(
    req: LoginRequest,
    db: Session = Depends(get_db),
):
    """JSON payload login endpoint returning signed JWT access token."""
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.hashed_password):
        log_security_event(
            db=db,
            event_type="AUTH_FAILED",
            actor=req.email,
            target=req.email,
            reason="Invalid credentials",
            new_state="REJECTED",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is deactivated.",
        )

    token = create_access_token(
        subject=str(user.id),
        extra_claims={"email": user.email, "role": user.role},
    )

    log_security_event(
        db=db,
        event_type="AUTH_SUCCESS",
        actor=user.email,
        target=str(user.id),
        reason="Successful authentication",
        new_state="AUTHENTICATED",
    )

    return TokenResponse(
        access_token=token,
        user_id=str(user.id),
        email=user.email,
        role=user.role,
        full_name=user.full_name,
    )


@router.get("/me", response_model=UserProfileResponse)
def get_me(current_user: User = Depends(get_current_active_user)):
    """Retrieve current authenticated user profile."""
    return UserProfileResponse(
        user_id=str(current_user.id),
        email=current_user.email,
        role=current_user.role,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        is_superuser=current_user.is_superuser,
    )


@router.post("/register", response_model=UserProfileResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    req: UserRegisterRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_roles(["admin"])),
):
    """Admin-only user registration endpoint."""
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User with email {req.email} already exists.",
        )

    new_user = User(
        email=req.email,
        hashed_password=hash_password(req.password),
        full_name=req.full_name,
        role=req.role.lower(),
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_security_event(
        db=db,
        event_type="USER_REGISTERED",
        actor=admin_user.email,
        target=new_user.email,
        reason=f"Created new user with role {new_user.role}",
        new_state="CREATED",
    )

    return UserProfileResponse(
        user_id=str(new_user.id),
        email=new_user.email,
        role=new_user.role,
        full_name=new_user.full_name,
        is_active=new_user.is_active,
        is_superuser=new_user.is_superuser,
    )
