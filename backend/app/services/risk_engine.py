"""
TRINETRA — Central Multi-Signal Risk Engine (Layer 6)

Core Risk-Fusion System.
Fuses signals across all 5 detection layers:
  1. Content Intelligence (content_risk)
  2. URL & Domain Intelligence (url_risk)
  3. Identity & Spoofing Intelligence (identity_risk)
  4. Threat Intelligence (threat_intel_risk)
  5. Graph Intelligence (graph_risk)

Design Principles:
- Configurable Weighted Fusion: Explicitly documented, adjustable weights & thresholds.
- Robust Failure Handling: Unavailable layers never crash the engine. Weights of available
  layers are dynamically renormalized with full transparent audit documentation.
- Granular Signal Contributions: Each layer reports its exact contribution to the 100-point score.
- Dynamic Confidence: Accounts for layer confidence, sensor coverage ratio, and boundary clarity.
- SOC-Grade Explainability: Generates human-understandable evidence bullets and recommended actions.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, model_validator

from app.core.logging import logger
from app.models import Decision, Severity


# ---------------------------------------------------------------------------
# Layer Status & Constants
# ---------------------------------------------------------------------------

class LayerStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


LAYER_CONTENT = "content_risk"
LAYER_URL = "url_risk"
LAYER_IDENTITY = "identity_risk"
LAYER_THREAT_INTEL = "threat_intel_risk"
LAYER_GRAPH = "graph_risk"

ALL_LAYERS = [
    LAYER_CONTENT,
    LAYER_URL,
    LAYER_IDENTITY,
    LAYER_THREAT_INTEL,
    LAYER_GRAPH,
]

LAYER_DISPLAY_NAMES = {
    LAYER_CONTENT: "Content Risk",
    LAYER_URL: "URL Risk",
    LAYER_IDENTITY: "Identity Risk",
    LAYER_THREAT_INTEL: "Threat Intelligence",
    LAYER_GRAPH: "Graph",
}


# ---------------------------------------------------------------------------
# Configuration Model
# ---------------------------------------------------------------------------

class RiskEngineConfig(BaseModel):
    """
    Configurable weights, thresholds, and operational rules for the Risk Engine.
    All weights must sum to 1.0 (within 0.001 tolerance).
    Thresholds must be strictly monotonic: low_max < medium_max < high_max.
    """
    version: str = "1.0.0"
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Configured layer weights (Rationale: URL & Content are primary payload indicators,
    # Identity flags impersonation, Threat Intel and Graph provide correlated external context)
    weights: Dict[str, float] = {
        LAYER_CONTENT: 0.25,
        LAYER_URL: 0.30,
        LAYER_IDENTITY: 0.20,
        LAYER_THREAT_INTEL: 0.15,
        LAYER_GRAPH: 0.10,
    }

    # Decision thresholds
    # Score in [0.00, low_max)       -> LOW      / ALLOW
    # Score in [low_max, medium_max) -> MEDIUM   / WARN
    # Score in [medium_max, high_max)-> HIGH     / QUARANTINE
    # Score in [high_max, 1.00]      -> CRITICAL / QUARANTINE
    thresholds: Dict[str, float] = {
        "low_max": 0.35,
        "medium_max": 0.65,
        "high_max": 0.85,
    }

    # Decision Mapping
    decision_mapping: Dict[str, str] = {
        Severity.LOW.value: Decision.ALLOW.value,
        Severity.MEDIUM.value: Decision.WARN.value,
        Severity.HIGH.value: Decision.QUARANTINE.value,
        Severity.CRITICAL.value: Decision.QUARANTINE.value,
    }

    # Override: Direct malicious threat advisory match elevates severity to at least HIGH
    threat_intel_override_threshold: float = 0.90

    @model_validator(mode="after")
    def validate_weights_and_thresholds(self) -> RiskEngineConfig:
        # Check weights sum
        for layer in ALL_LAYERS:
            if layer not in self.weights:
                raise ValueError(f"Missing weight definition for required layer '{layer}'")
            if self.weights[layer] < 0.0:
                raise ValueError(f"Weight for '{layer}' cannot be negative")

        total_weight = sum(self.weights.values())
        if abs(total_weight - 1.0) > 0.005:
            raise ValueError(f"Weights must sum to 1.0, current sum: {total_weight:.4f}")

        # Check thresholds
        low = self.thresholds.get("low_max", 0.35)
        med = self.thresholds.get("medium_max", 0.65)
        high = self.thresholds.get("high_max", 0.85)
        if not (0.0 < low < med < high < 1.0):
            raise ValueError(
                f"Thresholds must satisfy 0.0 < low_max ({low}) < medium_max ({med}) < high_max ({high}) < 1.0"
            )

        return self


# Global singleton configuration instance
risk_config = RiskEngineConfig()


# ---------------------------------------------------------------------------
# Signal Input / Output Models
# ---------------------------------------------------------------------------

class LayerSignalInput(BaseModel):
    layer_name: str
    score: Optional[float] = None
    status: LayerStatus = LayerStatus.AVAILABLE
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    unavailable_reason: Optional[str] = None
    signals: List[Dict[str, Any]] = []
    evidence: Dict[str, Any] = {}


class LayerContribution(BaseModel):
    layer_name: str
    display_name: str
    raw_score: Optional[float] = None
    configured_weight: float
    effective_weight: float
    contribution_points: int
    status: str
    unavailable_reason: Optional[str] = None


class RiskEvaluationResult(BaseModel):
    final_risk_score: float = Field(ge=0.0, le=1.0)
    final_score_100: int = Field(ge=0, le=100)
    severity: str
    decision: str
    confidence: float = Field(ge=0.0, le=1.0)
    signal_contributions: Dict[str, int]
    layer_breakdown: List[LayerContribution]
    risk_signals: List[Dict[str, Any]]
    evidence: Dict[str, Any]
    evidence_summary: List[str]
    recommended_action: str
    engine_metadata: Dict[str, Any]


# ---------------------------------------------------------------------------
# Central Risk Fusion Engine
# ---------------------------------------------------------------------------

class CentralRiskEngine:
    """
    Evaluates multi-layer signals, performs dynamic renormalization when
    layers are unavailable, maps decisions, and outputs explainable SOC evidence.
    """

    def __init__(self, config: Optional[RiskEngineConfig] = None) -> None:
        self.config = config or risk_config

    def evaluate(self, layer_inputs: Dict[str, LayerSignalInput]) -> RiskEvaluationResult:
        """
        Main fusion algorithm.
        Inputs: Dict of layer_name -> LayerSignalInput
        Output: RiskEvaluationResult
        """
        weights = self.config.weights
        thresholds = self.config.thresholds

        # 1. Separate available and unavailable layers
        available_layers: Dict[str, LayerSignalInput] = {}
        unavailable_layers: Dict[str, LayerSignalInput] = {}

        for layer in ALL_LAYERS:
            inp = layer_inputs.get(layer)
            if (
                inp is not None
                and inp.status == LayerStatus.AVAILABLE
                and inp.score is not None
            ):
                available_layers[layer] = inp
            else:
                reason = inp.unavailable_reason if inp else "Signal not provided"
                status_val = inp.status.value if inp else LayerStatus.UNAVAILABLE.value
                unavailable_layers[layer] = (
                    inp
                    if inp
                    else LayerSignalInput(
                        layer_name=layer,
                        status=LayerStatus.UNAVAILABLE,
                        unavailable_reason=reason,
                    )
                )

        # 2. Dynamic Renormalization
        # Sum weights of available layers
        avail_weight_sum = sum(weights[l] for l in available_layers.keys())

        # Degraded fallback: If NO layers are available
        if avail_weight_sum <= 0.0 or len(available_layers) == 0:
            logger.warning("risk_engine_all_layers_unavailable")
            return RiskEvaluationResult(
                final_risk_score=0.50,
                final_score_100=50,
                severity=Severity.MEDIUM.value,
                decision=Decision.WARN.value,
                confidence=0.05,
                signal_contributions={LAYER_DISPLAY_NAMES[l]: 0 for l in ALL_LAYERS},
                layer_breakdown=[
                    LayerContribution(
                        layer_name=l,
                        display_name=LAYER_DISPLAY_NAMES[l],
                        raw_score=None,
                        configured_weight=weights[l],
                        effective_weight=0.0,
                        contribution_points=0,
                        status=LayerStatus.UNAVAILABLE.value,
                        unavailable_reason="Signal unavailable / sensor failure",
                    )
                    for l in ALL_LAYERS
                ],
                risk_signals=[],
                evidence={"warning": "All intelligence layers unavailable; fallback decision applied."},
                evidence_summary=["All intelligence layers unavailable — manual analyst review recommended"],
                recommended_action="Hold email in staging queue. Verify security sensor connectivity.",
                engine_metadata={
                    "version": self.config.version,
                    "available_layer_count": 0,
                    "total_layer_count": len(ALL_LAYERS),
                    "renormalization_applied": False,
                },
            )

        # 3. Weighted Fusion Calculation
        final_risk = 0.0
        signal_contributions: Dict[str, int] = {}
        layer_breakdown: List[LayerContribution] = []
        all_risk_signals: List[Dict[str, Any]] = []
        layer_confidences: List[float] = []

        for layer in ALL_LAYERS:
            cfg_weight = weights[layer]
            if layer in available_layers:
                inp = available_layers[layer]
                eff_weight = cfg_weight / avail_weight_sum
                raw_score = max(0.0, min(1.0, float(inp.score or 0.0)))
                layer_risk_contrib = eff_weight * raw_score
                final_risk += layer_risk_contrib

                points = int(round(layer_risk_contrib * 100))
                display_name = LAYER_DISPLAY_NAMES[layer]
                signal_contributions[display_name] = points

                layer_breakdown.append(LayerContribution(
                    layer_name=layer,
                    display_name=display_name,
                    raw_score=round(raw_score, 4),
                    configured_weight=round(cfg_weight, 4),
                    effective_weight=round(eff_weight, 4),
                    contribution_points=points,
                    status=inp.status.value,
                    unavailable_reason=None,
                ))

                layer_confidences.append(inp.confidence)
                for sig in inp.signals:
                    sig_dict = dict(sig) if isinstance(sig, dict) else sig.model_dump()
                    sig_dict["layer"] = layer
                    all_risk_signals.append(sig_dict)

            else:
                inp = unavailable_layers[layer]
                display_name = LAYER_DISPLAY_NAMES[layer]
                signal_contributions[display_name] = 0

                layer_breakdown.append(LayerContribution(
                    layer_name=layer,
                    display_name=display_name,
                    raw_score=None,
                    configured_weight=round(cfg_weight, 4),
                    effective_weight=0.0,
                    contribution_points=0,
                    status=inp.status.value,
                    unavailable_reason=inp.unavailable_reason,
                ))

        # 4. Critical Threat-Intel / Zero-Day Override
        ti_input = available_layers.get(LAYER_THREAT_INTEL)
        has_ti_override = False
        if (
            ti_input
            and ti_input.score is not None
            and ti_input.score >= self.config.threat_intel_override_threshold
        ):
            has_ti_override = True
            final_risk = max(final_risk, 0.88)

        final_risk = round(min(1.0, max(0.0, final_risk)), 4)
        final_score_100 = int(round(final_risk * 100))

        # 5. Severity & Decision Resolution
        low_max = thresholds["low_max"]
        med_max = thresholds["medium_max"]
        high_max = thresholds["high_max"]

        if final_risk < low_max:
            severity = Severity.LOW.value
            decision = Decision.ALLOW.value
        elif final_risk < med_max:
            severity = Severity.MEDIUM.value
            decision = Decision.WARN.value
        elif final_risk < high_max:
            severity = Severity.HIGH.value
            decision = Decision.QUARANTINE.value
        else:
            severity = Severity.CRITICAL.value
            decision = Decision.QUARANTINE.value

        # Enforce Threat-Intel override minimum severity
        if has_ti_override and severity in (Severity.LOW.value, Severity.MEDIUM.value):
            severity = Severity.HIGH.value
            decision = Decision.QUARANTINE.value

        # 6. Overall Confidence Calculation
        avg_layer_conf = (
            sum(layer_confidences) / len(layer_confidences) if layer_confidences else 0.5
        )
        coverage_ratio = len(available_layers) / len(ALL_LAYERS)
        boundary_distance = min(1.0, 2.0 * abs(final_risk - 0.50))
        computed_conf = (
            (0.40 * avg_layer_conf)
            + (0.30 * coverage_ratio)
            + (0.30 * boundary_distance)
        )
        confidence = round(min(0.99, max(0.10, computed_conf)), 4)

        # 7. Synthesize Evidence Bullets
        evidence_summary: List[str] = []

        # Content bullets
        content_inp = available_layers.get(LAYER_CONTENT)
        if content_inp and (content_inp.score or 0) >= 0.50:
            evidence_summary.append("credential harvesting / phishing intent detected in email body")

        # URL bullets
        url_inp = available_layers.get(LAYER_URL)
        if url_inp and (url_inp.score or 0) >= 0.50:
            evidence_summary.append("suspicious URL / deceptive domain structure identified")

        # Identity bullets
        id_inp = available_layers.get(LAYER_IDENTITY)
        if id_inp and (id_inp.score or 0) >= 0.50:
            evidence_summary.append("sender/brand mismatch or failed email authentication (SPF/DKIM/DMARC)")

        # Threat Intel bullets
        if ti_input and (ti_input.score or 0) >= 0.50:
            evidence_summary.append("threat-intelligence match in published advisory or local IOC database")

        # Graph bullets
        graph_inp = available_layers.get(LAYER_GRAPH)
        if graph_inp and (graph_inp.score or 0) >= 0.50:
            evidence_summary.append("related malicious infrastructure / coordinated campaign correlation")

        # If no severe bullets, indicate clean baseline
        if not evidence_summary:
            if decision == Decision.ALLOW.value:
                evidence_summary.append("clean authentication and no suspicious indicators across all evaluated layers")
            else:
                evidence_summary.append("moderate aggregate suspicion across evaluated signals")

        # Mention unavailable layers if any
        if unavailable_layers:
            unavail_names = [LAYER_DISPLAY_NAMES[l] for l in unavailable_layers.keys()]
            evidence_summary.append(
                f"signal sensor(s) unavailable [{', '.join(unavail_names)}] — weights renormalized across active layers"
            )

        # 8. SOC Recommended Action
        if decision == Decision.QUARANTINE.value:
            if severity == Severity.CRITICAL.value:
                recommended_action = (
                    "Quarantine email immediately. Block sender and associated domains at mail gateway. "
                    "Invalidate user credentials if clicked and isolate destination endpoints."
                )
            else:
                recommended_action = (
                    "Quarantine email. Restrict access and notify SOC for analyst verification."
                )
        elif decision == Decision.WARN.value:
            recommended_action = (
                "Deliver with prominent warning banner. Disable external links and attachments until confirmed."
            )
        else:
            recommended_action = (
                "Deliver normally. Standard baseline telemetry logged."
            )

        # 9. Evidence Metadata Package
        evidence_dict = {
            "version": self.config.version,
            "final_risk_score": final_risk,
            "final_score_100": final_score_100,
            "severity": severity,
            "decision": decision,
            "confidence": confidence,
            "signal_contributions": signal_contributions,
            "available_layers": list(available_layers.keys()),
            "unavailable_layers": {
                l: unavailable_layers[l].unavailable_reason for l in unavailable_layers.keys()
            },
            "renormalized": len(unavailable_layers) > 0,
            "threat_intel_override_triggered": has_ti_override,
            "layer_evidence": {
                l: inp.evidence for l, inp in available_layers.items()
            },
        }

        return RiskEvaluationResult(
            final_risk_score=final_risk,
            final_score_100=final_score_100,
            severity=severity,
            decision=decision,
            confidence=confidence,
            signal_contributions=signal_contributions,
            layer_breakdown=layer_breakdown,
            risk_signals=all_risk_signals,
            evidence=evidence_dict,
            evidence_summary=evidence_summary,
            recommended_action=recommended_action,
            engine_metadata={
                "engine_version": self.config.version,
                "configured_weights": weights,
                "configured_thresholds": thresholds,
                "renormalization_factor": round(1.0 / avail_weight_sum, 4) if avail_weight_sum > 0 else 1.0,
            },
        )


# Singleton Risk Engine
risk_engine = CentralRiskEngine()


# ---------------------------------------------------------------------------
# End-to-End Multi-Layer Pipeline Orchestration
# ---------------------------------------------------------------------------

async def evaluate_email_pipeline(
    subject: str,
    plain_text: str = "",
    sender_email: Optional[str] = None,
    sender_domain: Optional[str] = None,
    urls: Optional[List[str]] = None,
    ips: Optional[List[str]] = None,
    headers: Optional[Dict[str, str]] = None,
    email_id: Optional[str] = None,
) -> RiskEvaluationResult:
    """
    Executes all 5 intelligence layers concurrently and fuses the results:
      1. Content Intelligence (ML + intent heuristics)
      2. URL & Domain Intelligence
      3. Identity & Spoofing Intelligence
      4. Threat Intelligence (CERT-In + Local DB + external)
      5. Graph Intelligence (NetworkX multi-entity correlation)

    Resilience: If any individual layer throws an exception, it is caught and
    recorded as UNAVAILABLE, allowing the pipeline to finish cleanly.
    """
    urls = urls or []
    ips = ips or []
    headers = headers or {}
    email_id = email_id or f"msg-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    # Lazy imports to prevent circular dependencies
    from app.services.content_engine import content_engine
    from app.services.url_engine import analyze_urls_list
    from app.services.identity_engine import analyze_sender_identity
    from app.services.threat_intel_service import run_threat_intel_matching
    from app.services.graph_engine import calculate_graph_risk

    layer_inputs: Dict[str, LayerSignalInput] = {}

    # Define tasks
    async def run_content():
        try:
            res = content_engine.analyze_content(
                subject=subject,
                body_text=plain_text,
                sender_email=sender_email,
            )
            return LayerSignalInput(
                layer_name=LAYER_CONTENT,
                score=res.content_risk_score,
                status=LayerStatus.AVAILABLE,
                confidence=res.model_confidence,
                signals=[s.model_dump() for s in res.intent_signals],
                evidence=res.evidence,
            )
        except Exception as e:
            logger.warning("pipeline_content_layer_failed", error=str(e))
            return LayerSignalInput(
                layer_name=LAYER_CONTENT,
                status=LayerStatus.UNAVAILABLE,
                unavailable_reason=f"Content engine error: {str(e)}",
            )

    async def run_url():
        try:
            if not urls:
                return LayerSignalInput(
                    layer_name=LAYER_URL,
                    score=0.0,
                    status=LayerStatus.AVAILABLE,
                    confidence=0.8,
                    evidence={"note": "No URLs extracted from email; neutral score applied."},
                )
            res = analyze_urls_list(urls)
            return LayerSignalInput(
                layer_name=LAYER_URL,
                score=res.max_url_risk_score,
                status=LayerStatus.AVAILABLE,
                confidence=0.9,
                signals=[
                    s.model_dump()
                    for r in res.analyzed_urls
                    for s in r.signals
                ],
                evidence={
                    "total_urls": res.total_urls_analyzed,
                    "suspicious_count": res.suspicious_urls_count,
                    "max_url_risk": res.max_url_risk_score,
                },
            )
        except Exception as e:
            logger.warning("pipeline_url_layer_failed", error=str(e))
            return LayerSignalInput(
                layer_name=LAYER_URL,
                status=LayerStatus.UNAVAILABLE,
                unavailable_reason=f"URL engine error: {str(e)}",
            )

    async def run_identity():
        try:
            res = analyze_sender_identity(
                from_header=sender_email or "",
                headers=headers,
                reply_to_header=headers.get("reply-to"),
            )
            return LayerSignalInput(
                layer_name=LAYER_IDENTITY,
                score=res.identity_risk_score,
                status=LayerStatus.AVAILABLE,
                confidence=0.9,
                signals=[s.model_dump() for s in res.signals],
                evidence=res.evidence,
            )
        except Exception as e:
            logger.warning("pipeline_identity_layer_failed", error=str(e))
            return LayerSignalInput(
                layer_name=LAYER_IDENTITY,
                status=LayerStatus.UNAVAILABLE,
                unavailable_reason=f"Identity engine error: {str(e)}",
            )

    async def run_threat_intel():
        try:
            res = await run_threat_intel_matching(
                sender_email=sender_email,
                sender_domain=sender_domain,
                urls=urls,
                subject=subject,
            )
            return LayerSignalInput(
                layer_name=LAYER_THREAT_INTEL,
                score=res.threat_intel_risk,
                status=LayerStatus.AVAILABLE,
                confidence=0.95 if res.matched else 0.80,
                signals=[ind.model_dump() for ind in res.indicators],
                evidence=res.evidence,
            )
        except Exception as e:
            logger.warning("pipeline_threat_intel_layer_failed", error=str(e))
            return LayerSignalInput(
                layer_name=LAYER_THREAT_INTEL,
                status=LayerStatus.UNAVAILABLE,
                unavailable_reason=f"Threat intel provider error: {str(e)}",
            )

    async def run_graph():
        try:
            res = calculate_graph_risk(
                email_id=email_id,
                sender_email=sender_email,
                sender_domain=sender_domain,
                urls=urls,
                ips=ips,
                ingest=False,
                subject=subject,
            )
            return LayerSignalInput(
                layer_name=LAYER_GRAPH,
                score=res.graph_risk_score,
                status=LayerStatus.AVAILABLE,
                confidence=0.85,
                signals=[s.model_dump() for s in res.signals],
                evidence=res.graph_evidence,
            )
        except Exception as e:
            logger.warning("pipeline_graph_layer_failed", error=str(e))
            return LayerSignalInput(
                layer_name=LAYER_GRAPH,
                status=LayerStatus.UNAVAILABLE,
                unavailable_reason=f"Graph engine error: {str(e)}",
            )

    # Execute all 5 layers concurrently
    results = await asyncio.gather(
        run_content(),
        run_url(),
        run_identity(),
        run_threat_intel(),
        run_graph(),
    )

    layer_inputs[LAYER_CONTENT] = results[0]
    layer_inputs[LAYER_URL] = results[1]
    layer_inputs[LAYER_IDENTITY] = results[2]
    layer_inputs[LAYER_THREAT_INTEL] = results[3]
    layer_inputs[LAYER_GRAPH] = results[4]

    # Perform multi-signal risk fusion
    return risk_engine.evaluate(layer_inputs)
