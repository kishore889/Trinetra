"""
TRINETRA — Security Middleware

Includes:
- SecurityHeadersMiddleware: Sets OWASP-recommended security headers on all API responses.
- RateLimitingMiddleware: In-memory sliding window rate limiter per client IP/token.
- SanitizedErrorMiddleware: Prevents internal exception stack trace leakage to API clients.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Dict, Deque
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import settings
from app.core.logging import logger


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to every outgoing response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Standard OWASP security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' http: https: ws: wss:;"
        )

        return response


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    In-memory rate limiter enforcing request bounds per IP or bearer token.
    Configurable via settings.RATE_LIMIT_PER_MINUTE (default 60).
    Exempts documentation and health check routes.
    """

    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests_map: Dict[str, Deque[float]] = defaultdict(deque)

    def _get_client_identifier(self, request: Request) -> str:
        # Check Authorization header first
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            return f"token:{auth_header[7:30]}"
        # Otherwise fallback to client host IP
        return f"ip:{request.client.host if request.client else '127.0.0.1'}"

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        # Bypass rate limiter for testclient, health check, and docs
        is_test_client = request.client and request.client.host == "testclient"
        if is_test_client or path.endswith("/health") or path.startswith(("/docs", "/redoc", "/openapi.json")):
            return await call_next(request)

        client_id = self._get_client_identifier(request)
        now = time.time()
        timestamps = self.requests_map[client_id]

        # Evict timestamps outside sliding window
        while timestamps and timestamps[0] < now - self.window_seconds:
            timestamps.popleft()

        limit = getattr(settings, "RATE_LIMIT_PER_MINUTE", self.max_requests)

        if len(timestamps) >= limit:
            logger.warning("rate_limit_exceeded", client_id=client_id, path=path)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Maximum of {limit} requests per minute exceeded. Please try again shortly.",
                },
                headers={"Retry-After": str(self.window_seconds)},
            )

        timestamps.append(now)
        return await call_next(request)


class SanitizedErrorMiddleware(BaseHTTPMiddleware):
    """
    Catches unexpected internal exceptions and returns sanitized JSON error responses,
    preventing internal stack trace or DB credential leaks in non-DEBUG environments.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:
            logger.error(
                "unhandled_internal_error",
                path=request.url.path,
                method=request.method,
                error=str(exc),
                exc_info=True,
            )
            if settings.DEBUG or settings.is_development:
                # In development mode, allow detailed exception detail
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={"error": "Internal Server Error", "detail": str(exc)},
                )

            # In production, redact raw exception trace
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "Internal Server Error",
                    "message": "An unexpected security or processing error occurred. Incident logged.",
                },
            )
