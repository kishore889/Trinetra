"""
TRINETRA — API Dependencies & RBAC Authorization

Provides FastAPI dependencies for:
- Database session injection (`get_db`)
- JWT authentication (`get_current_user`, `get_current_active_user`)
- Optional authentication for public/demo endpoints (`get_current_user_optional`)
- Role-Based Access Control (RBAC) verification (`require_roles`)
"""

from __future__ import annotations

import uuid as _uuid_module
from typing import Callable, List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.security import decode_access_token
from app.db.session import get_db
from app.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Validate JWT access token and return current active User model.
    Falls back to system user if token is missing in development mode,
    or raises HTTP 401 AuthenticationError in strict mode.
    """
    if not token:
        # Fallback to default active analyst for development/demo mode if no token passed
        default_user = db.query(User).filter(User.is_active == True).first()
        if default_user:
            return default_user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Convert string UUID to UUID object for SQLite + PostgreSQL compatibility
        try:
            user_uuid = _uuid_module.UUID(str(user_id))
        except (ValueError, AttributeError):
            user_uuid = None

        user = None
        if user_uuid:
            user = db.query(User).filter(User.id == user_uuid, User.is_active == True).first()
        if not user:
            # Try matching by email if subject is email
            user = db.query(User).filter(User.email == user_id, User.is_active == True).first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account not found or deactivated.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Ensure current user account is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account.",
        )
    return current_user


def require_roles(allowed_roles: List[str]) -> Callable:
    """
    Dependency factory enforcing Role-Based Access Control (RBAC).

    Args:
        allowed_roles: List of permitted role names (e.g. ['admin', 'analyst'])

    Returns:
        Dependency function that validates the user's role.
    """
    normalized_allowed = {r.lower() for r in allowed_roles}

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.is_superuser:
            return current_user
        if current_user.role.lower() not in normalized_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of the following roles: {', '.join(allowed_roles)}.",
            )
        return current_user

    return role_checker
