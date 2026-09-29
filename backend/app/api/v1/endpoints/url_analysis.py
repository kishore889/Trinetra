"""
TRINETRA — URL & Domain Intelligence API Endpoints

POST /api/v1/analyze/url         -> Analyzes a single URL
POST /api/v1/analyze/urls-batch  -> Analyzes multiple URLs
GET  /api/v1/analyze/url/providers -> Status of configured TI providers
"""

from __future__ import annotations

from typing import List
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.url_engine import (
    MultiURLAnalysisResult,
    URLAnalysisResult,
    analyze_single_url,
    analyze_urls_list,
)
from app.services.threat_providers import (
    GoogleSafeBrowsingProvider,
    LocalReputationProvider,
    VirusTotalProvider,
)

router = APIRouter()


class SingleURLRequest(BaseModel):
    url: str


class MultiURLRequest(BaseModel):
    urls: List[str]


@router.post("", response_model=URLAnalysisResult, status_code=status.HTTP_200_OK)
def analyze_url(payload: SingleURLRequest) -> URLAnalysisResult:
    """
    Performs static feature extraction, lookalike detection, and risk scoring on a URL.
    Zero network requests are performed (SSRF safe).
    """
    return analyze_single_url(payload.url)


@router.post("/batch", response_model=MultiURLAnalysisResult, status_code=status.HTTP_200_OK)
def analyze_batch_urls(payload: MultiURLRequest) -> MultiURLAnalysisResult:
    """Batch analysis of URLs extracted from an email."""
    return analyze_urls_list(payload.urls)


@router.get("/providers")
def get_provider_status():
    """Lists status of threat intelligence reputation providers."""
    local_p = LocalReputationProvider()
    gsb_p = GoogleSafeBrowsingProvider()
    vt_p = VirusTotalProvider()

    return {
        "providers": [
            {"name": local_p.name, "type": "INTERNAL", "available": local_p.is_available()},
            {"name": gsb_p.name, "type": "EXTERNAL", "available": gsb_p.is_available()},
            {"name": vt_p.name, "type": "EXTERNAL", "available": vt_p.is_available()},
        ]
    }
