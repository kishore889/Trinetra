"""
TRINETRA — Central Risk Engine API Endpoints (Phase 11)

POST /api/v1/risk/evaluate      → Multi-signal risk fusion from layer scores
POST /api/v1/risk/pipeline      → End-to-end 5-layer pipeline evaluation from raw email
GET  /api/v1/risk/config        → Get current risk engine configuration (weights, thresholds)
PUT  /api/v1/risk/config        → Update risk engine configuration with validation
POST /api/v1/risk/reset-config  → Reset configuration to factory defaults
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.services.risk_engine import (
    ALL_LAYERS,
    LAYER_CONTENT,
    LAYER_GRAPH,
    LAYER_IDENTITY,
    LAYER_THREAT_INTEL,
    LAYER_URL,
    LayerSignalInput,
    LayerStatus,
    RiskEngineConfig,
    RiskEvaluationResult,
    evaluate_email_pipeline,
    risk_config,
    risk_engine,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------------------------

class LayerScoreInput(BaseModel):
    score: Optional[float] = Field(None, ge=0.0, le=1.0)
    status: LayerStatus = LayerStatus.AVAILABLE
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    unavailable_reason: Optional[str] = None
    signals: List[Dict[str, Any]] = []
    evidence: Dict[str, Any] = {}


class RiskEvaluationRequest(BaseModel):
    content_risk: Optional[LayerScoreInput] = None
    url_risk: Optional[LayerScoreInput] = None
    identity_risk: Optional[LayerScoreInput] = None
    threat_intel_risk: Optional[LayerScoreInput] = None
    graph_risk: Optional[LayerScoreInput] = None


class FullPipelineRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    plain_text: str = Field("", description="Extracted plain text or HTML text")
    sender_email: Optional[str] = None
    sender_domain: Optional[str] = None
    urls: List[str] = []
    ips: List[str] = []
    headers: Dict[str, str] = {}
    email_id: Optional[str] = None


class UpdateRiskConfigRequest(BaseModel):
    weights: Optional[Dict[str, float]] = None
    thresholds: Optional[Dict[str, float]] = None
    threat_intel_override_threshold: Optional[float] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/evaluate", response_model=RiskEvaluationResult)
async def evaluate_risk(req: RiskEvaluationRequest):
    """
    Fuses provided layer scores using the Central Risk Engine.
    Handles unavailable or missing layers via dynamic weight renormalization.
    """
    inputs: Dict[str, LayerSignalInput] = {}

    layer_mapping = {
        LAYER_CONTENT: req.content_risk,
        LAYER_URL: req.url_risk,
        LAYER_IDENTITY: req.identity_risk,
        LAYER_THREAT_INTEL: req.threat_intel_risk,
        LAYER_GRAPH: req.graph_risk,
    }

    for layer, inp in layer_mapping.items():
        if inp is not None:
            inputs[layer] = LayerSignalInput(
                layer_name=layer,
                score=inp.score,
                status=inp.status,
                confidence=inp.confidence,
                unavailable_reason=inp.unavailable_reason,
                signals=inp.signals,
                evidence=inp.evidence,
            )
        else:
            inputs[layer] = LayerSignalInput(
                layer_name=layer,
                status=LayerStatus.UNAVAILABLE,
                unavailable_reason="Layer signal not supplied in request",
            )

    return risk_engine.evaluate(inputs)


@router.post("/pipeline", response_model=RiskEvaluationResult)
async def run_full_pipeline(req: FullPipelineRequest):
    """
    Executes all 5 detection layers concurrently against raw email data
    and returns the fused risk assessment, signal contributions, and SOC recommendations.
    """
    return await evaluate_email_pipeline(
        subject=req.subject,
        plain_text=req.plain_text,
        sender_email=req.sender_email,
        sender_domain=req.sender_domain,
        urls=req.urls,
        ips=req.ips,
        headers=req.headers,
        email_id=req.email_id,
    )


@router.get("/config", response_model=RiskEngineConfig)
async def get_risk_config():
    """
    Returns current active weights, decision thresholds, and version.
    """
    return risk_engine.config


@router.put("/config", response_model=RiskEngineConfig)
async def update_risk_config(req: UpdateRiskConfigRequest):
    """
    Updates risk engine weights and thresholds with strict validation.
    """
    current = risk_engine.config

    new_weights = req.weights or current.weights
    new_thresholds = req.thresholds or current.thresholds
    new_ti_override = (
        req.threat_intel_override_threshold
        if req.threat_intel_override_threshold is not None
        else current.threat_intel_override_threshold
    )

    try:
        updated_config = RiskEngineConfig(
            version=f"{current.version}.mod",
            weights=new_weights,
            thresholds=new_thresholds,
            threat_intel_override_threshold=new_ti_override,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid risk engine configuration: {str(e)}",
        )

    risk_engine.config = updated_config
    return risk_engine.config


@router.post("/reset-config", response_model=RiskEngineConfig)
async def reset_risk_config():
    """
    Resets risk engine configuration back to factory default baseline.
    """
    risk_engine.config = RiskEngineConfig()
    return risk_engine.config
