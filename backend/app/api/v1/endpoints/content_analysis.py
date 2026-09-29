"""
TRINETRA — Content Intelligence API Endpoints

POST /api/v1/analyze/content       -> Analyzes text/subject for phishing signals and ML risk
POST /api/v1/analyze/content/train -> Triggers re-training of the TF-IDF Logistic Regression pipeline
GET  /api/v1/analyze/content/model -> Reports model status, architecture, and evaluation metrics
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from app.services.content_engine import (
    ContentAnalysisResult,
    ModelEvaluationMetrics,
    content_engine,
)

router = APIRouter()


class ContentAnalysisRequest(BaseModel):
    subject: str
    body_text: str
    sender_email: Optional[str] = None


class ModelStatusResponse(BaseModel):
    model_name: str = "TRINETRA Content Intelligence Baseline"
    algorithm: str = "TF-IDF (1-2 ngrams) + Logistic Regression (L2)"
    is_trained: bool
    metrics: Optional[ModelEvaluationMetrics] = None


@router.post("", response_model=ContentAnalysisResult, status_code=status.HTTP_200_OK)
def analyze_email_content(payload: ContentAnalysisRequest) -> ContentAnalysisResult:
    """
    Evaluates email subject and body text through Content Intelligence Layer.
    Returns content_risk_score, phishing_probability, intent_signals, confidence, and evidence.
    """
    return content_engine.analyze_content(
        subject=payload.subject,
        body_text=payload.body_text,
        sender_email=payload.sender_email,
    )


@router.get("/model", response_model=ModelStatusResponse)
def get_model_status() -> ModelStatusResponse:
    """Reports status, architecture parameters, and evaluation metrics of the model."""
    return ModelStatusResponse(
        is_trained=content_engine.pipeline is not None,
        metrics=content_engine.metrics,
    )


@router.post("/train", response_model=ModelEvaluationMetrics, status_code=status.HTTP_200_OK)
def retrain_model() -> ModelEvaluationMetrics:
    """Retrains the TF-IDF + Logistic Regression model and re-evaluates test metrics."""
    return content_engine.train_pipeline()
