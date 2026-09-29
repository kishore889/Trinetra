"""
TRINETRA — API v1 Router Registration
"""

from fastapi import APIRouter
from app.api.v1.endpoints import health, gmail_auth

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(gmail_auth.router, prefix="/auth", tags=["Gmail OAuth"])
