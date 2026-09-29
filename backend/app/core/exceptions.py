"""
TRINETRA — Exception Definitions & Global Exception Handlers

Defines all application-level exceptions and FastAPI exception handlers
that convert them to structured JSON error responses.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse


# ==================================================
# Base Exception
# ==================================================

class TRINETRAException(Exception):
    """Base exception for all TRINETRA-specific errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "TRINETRA_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    ) -> None:
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(message)


# ==================================================
# Resource Exceptions
# ==================================================

class ResourceNotFoundError(TRINETRAException):
    """Raised when a requested resource does not exist."""

    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(
            message=f"{resource} with identifier '{identifier}' not found.",
            error_code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ResourceAlreadyExistsError(TRINETRAException):
    """Raised when a resource with the same unique key already exists."""

    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(
            message=f"{resource} '{identifier}' already exists.",
            error_code="RESOURCE_ALREADY_EXISTS",
            status_code=status.HTTP_409_CONFLICT,
        )


# ==================================================
# Authentication & Authorization
# ==================================================

class AuthenticationError(TRINETRAException):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed.") -> None:
        super().__init__(
            message=message,
            error_code="AUTHENTICATION_FAILED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class AuthorizationError(TRINETRAException):
    """Raised when the user lacks permission for an action."""

    def __init__(self, message: str = "Insufficient permissions.") -> None:
        super().__init__(
            message=message,
            error_code="AUTHORIZATION_FAILED",
            status_code=status.HTTP_403_FORBIDDEN,
        )


# ==================================================
# Validation
# ==================================================

class ValidationError(TRINETRAException):
    """Raised on input validation failures not caught by Pydantic."""

    def __init__(self, message: str) -> None:
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )


# ==================================================
# External Provider Exceptions
# ==================================================

class ProviderUnavailableError(TRINETRAException):
    """
    Raised when an external provider (VirusTotal, Safe Browsing, etc.) is unreachable.
    TRINETRA must continue functioning without external providers.
    """

    def __init__(self, provider: str) -> None:
        super().__init__(
            message=f"Threat intelligence provider '{provider}' is currently unavailable.",
            error_code="PROVIDER_UNAVAILABLE",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class ProviderResponseError(TRINETRAException):
    """Raised when an external provider returns an unexpected or invalid response."""

    def __init__(self, provider: str, detail: str) -> None:
        super().__init__(
            message=f"Provider '{provider}' returned an invalid response: {detail}",
            error_code="PROVIDER_RESPONSE_ERROR",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


# ==================================================
# Email Processing Exceptions
# ==================================================

class EmailProcessingError(TRINETRAException):
    """Raised when email parsing or processing fails."""

    def __init__(self, email_id: str, detail: str) -> None:
        super().__init__(
            message=f"Failed to process email '{email_id}': {detail}",
            error_code="EMAIL_PROCESSING_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class EmailStateTransitionError(TRINETRAException):
    """Raised when an invalid email state transition is attempted."""

    def __init__(self, email_id: str, current: str, target: str) -> None:
        super().__init__(
            message=f"Email '{email_id}' cannot transition from '{current}' to '{target}'.",
            error_code="INVALID_STATE_TRANSITION",
            status_code=status.HTTP_409_CONFLICT,
        )


# ==================================================
# Database Exceptions
# ==================================================

class DatabaseError(TRINETRAException):
    """Raised on unrecoverable database errors."""

    def __init__(self, detail: str = "Database operation failed.") -> None:
        super().__init__(
            message=detail,
            error_code="DATABASE_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# ==================================================
# Security Exceptions
# ==================================================

class SSRFDetectedError(TRINETRAException):
    """Raised when a URL analysis request targets a private/internal resource (SSRF protection)."""

    def __init__(self, url: str) -> None:
        super().__init__(
            message=f"SSRF attempt blocked: URL targets an internal or disallowed resource.",
            error_code="SSRF_DETECTED",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class RateLimitExceededError(TRINETRAException):
    """Raised when rate limits are exceeded."""

    def __init__(self) -> None:
        super().__init__(
            message="Rate limit exceeded. Please slow down.",
            error_code="RATE_LIMIT_EXCEEDED",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )


# ==================================================
# Exception Handlers Registration
# ==================================================

def register_exception_handlers(app: FastAPI) -> None:
    """Register all custom exception handlers on the FastAPI app."""

    @app.exception_handler(TRINETRAException)
    async def trinetra_exception_handler(
        request: Request, exc: TRINETRAException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": True,
                "error_code": exc.error_code,
                "message": exc.message,
                "service": "TRINETRA",
            },
        )

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "error": True,
                "error_code": "NOT_FOUND",
                "message": f"Endpoint '{request.url.path}' not found.",
                "service": "TRINETRA",
            },
        )

    @app.exception_handler(405)
    async def method_not_allowed_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            content={
                "error": True,
                "error_code": "METHOD_NOT_ALLOWED",
                "message": f"Method '{request.method}' not allowed on '{request.url.path}'.",
                "service": "TRINETRA",
            },
        )
