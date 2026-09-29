"""
TRINETRA — Identity / Spoofing Intelligence API Endpoints

POST /api/v1/analyze/identity        -> Full sender identity analysis
POST /api/v1/analyze/identity/batch  -> Batch analysis of multiple senders
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set
from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app.services.identity_engine import (
    IdentityAnalysisResult,
    analyze_sender_identity,
)

router = APIRouter()


class IdentityAnalysisRequest(BaseModel):
    from_header: str = Field(..., description="Raw 'From' header value (e.g. 'John Doe <john@example.com>')")
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Full email headers dict. Include Authentication-Results, Received-SPF, DKIM-Signature if available.",
    )
    reply_to_header: Optional[str] = Field(None, description="Raw 'Reply-To' header value")
    return_path_header: Optional[str] = Field(None, description="Raw 'Return-Path' header value")
    known_sender_domains: Optional[List[str]] = Field(
        None,
        description="List of previously-seen sender domains for this Gmail account",
    )
    known_sender_emails: Optional[List[str]] = Field(
        None,
        description="List of previously-seen sender email addresses",
    )


class BatchIdentityRequest(BaseModel):
    emails: List[IdentityAnalysisRequest]


class BatchIdentityResult(BaseModel):
    total_analyzed: int
    high_risk_count: int
    max_identity_risk_score: float
    results: List[IdentityAnalysisResult]


@router.post("", response_model=IdentityAnalysisResult, status_code=status.HTTP_200_OK)
def analyze_identity(payload: IdentityAnalysisRequest) -> IdentityAnalysisResult:
    """
    Analyzes sender identity for spoofing, authentication failures, and
    display name deception. Zero network requests — SSRF safe.
    """
    return analyze_sender_identity(
        from_header=payload.from_header,
        headers=payload.headers,
        reply_to_header=payload.reply_to_header,
        return_path_header=payload.return_path_header,
        known_sender_domains=set(payload.known_sender_domains or []),
        known_sender_emails=set(payload.known_sender_emails or []),
    )


@router.post("/batch", response_model=BatchIdentityResult, status_code=status.HTTP_200_OK)
def analyze_identity_batch(payload: BatchIdentityRequest) -> BatchIdentityResult:
    """
    Batch identity analysis for a collection of emails.
    Returns individual results plus aggregate risk summary.
    """
    results: List[IdentityAnalysisResult] = []

    for item in payload.emails:
        result = analyze_sender_identity(
            from_header=item.from_header,
            headers=item.headers,
            reply_to_header=item.reply_to_header,
            return_path_header=item.return_path_header,
            known_sender_domains=set(item.known_sender_domains or []),
            known_sender_emails=set(item.known_sender_emails or []),
        )
        results.append(result)

    scores = [r.identity_risk_score for r in results]
    high_risk_count = sum(1 for s in scores if s >= 0.6)

    return BatchIdentityResult(
        total_analyzed=len(results),
        high_risk_count=high_risk_count,
        max_identity_risk_score=round(max(scores), 4) if scores else 0.0,
        results=results,
    )
