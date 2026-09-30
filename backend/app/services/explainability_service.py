"""
TRINETRA — Explainable AI Service (Phase 12)

Architecture:
  ┌─────────────────────────────────────────────────────┐
  │               TRINETRA Detection System              │
  │  Content → URL → Identity → Threat Intel → Graph     │
  │                     ↓                                │
  │              Central Risk Engine                     │
  │                     ↓                                │
  │           Evidence Bundle (this module)              │
  │                     ↓                                │
  │       Gemini (optional, explanation only)            │
  │            ↓                  ↓                      │
  │   AI Explanation         Deterministic               │
  │   (when available)       Fallback (always)           │
  └─────────────────────────────────────────────────────┘

Critical Rules:
  - Gemini is NOT the phishing classifier. It is a language explainer only.
  - Gemini NEVER invents domains, URLs, IPs, TI matches, graph relationships,
    risk signals, or any evidence. It only summarises what is supplied.
  - If Gemini is unavailable / fails / times-out, the deterministic fallback
    runs transparently without disrupting the detection pipeline.
  - All outputs are labelled: system-generated evidence vs. AI explanation.
"""

from __future__ import annotations

import asyncio
import json
import re
import textwrap
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logging import logger


# ---------------------------------------------------------------------------
# Explanation Status
# ---------------------------------------------------------------------------

class ExplainabilityStatus(str, Enum):
    AI_GENERATED  = "AI_GENERATED"    # Gemini produced the explanation
    DETERMINISTIC = "DETERMINISTIC"   # Fallback rule-based explanation
    UNAVAILABLE   = "UNAVAILABLE"     # Neither succeeded (shouldn't happen)


# ---------------------------------------------------------------------------
# Evidence Bundle
# ---------------------------------------------------------------------------

class EvidenceBundle(BaseModel):
    """
    Immutable, system-generated evidence snapshot fed to the explainer.
    All fields are produced by TRINETRA's detection layers — Gemini reads
    this bundle and must NOT add facts that are not present here.
    """

    # Email Metadata
    email_id:        Optional[str] = None
    subject:         Optional[str] = None
    sender_email:    Optional[str] = None
    sender_domain:   Optional[str] = None
    recipient:       Optional[str] = None
    timestamp:       Optional[str] = None

    # Final Risk Assessment (from Central Risk Engine)
    final_risk_score:   float = Field(ge=0.0, le=1.0, default=0.0)
    final_score_100:    int   = Field(ge=0, le=100, default=0)
    severity:           str   = "UNKNOWN"
    decision:           str   = "UNKNOWN"
    confidence:         float = Field(ge=0.0, le=1.0, default=0.5)
    recommended_action: str   = ""

    # Layer Scores (0.0–1.0 each)
    content_risk_score:      Optional[float] = None
    url_risk_score:          Optional[float] = None
    identity_risk_score:     Optional[float] = None
    threat_intel_risk_score: Optional[float] = None
    graph_risk_score:        Optional[float] = None

    # Signal Contribution Points (from fusion engine)
    signal_contributions: Dict[str, int] = {}

    # Intent / Content Signals
    intent_signals:   List[str]       = []
    content_evidence: Dict[str, Any]  = {}

    # URL / Domain Signals
    url_signals:    List[str]      = []
    suspicious_urls: List[str]     = []
    url_evidence:   Dict[str, Any] = {}

    # Identity Signals
    spf_result:        Optional[str]  = None
    dkim_result:       Optional[str]  = None
    dmarc_result:      Optional[str]  = None
    identity_signals:  List[str]      = []
    identity_evidence: Dict[str, Any] = {}

    # Threat Intelligence Matches
    threat_indicators:      List[Dict[str, Any]] = []
    threat_intel_evidence:  Dict[str, Any]       = {}

    # Graph Intelligence
    graph_signals:  List[str]      = []
    graph_evidence: Dict[str, Any] = {}

    # System-generated evidence bullets (from risk engine)
    evidence_summary: List[str] = []


# ---------------------------------------------------------------------------
# Explanation Output
# ---------------------------------------------------------------------------

class PhishingExplanation(BaseModel):
    """
    Complete explanation package returned to the API layer.
    Clearly distinguishes system-generated evidence from AI-generated text.
    """

    status:           ExplainabilityStatus
    gemini_available: bool = False
    generated_at:     str  = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # ── System-generated (always present, always authoritative) ──────────
    system_verdict_summary: str
    system_key_reasons:     List[str]
    system_risk_breakdown:  Dict[str, Any]
    recommended_action:     str

    # ── AI-generated (Gemini, only when available) ────────────────────────
    # These summarise system evidence in natural language.
    # They do NOT constitute independent proof.
    ai_plain_explanation:    Optional[str]       = None
    ai_key_reasons:          Optional[List[str]] = None
    ai_risk_summary:         Optional[str]       = None
    ai_analyst_summary:      Optional[str]       = None
    ai_investigation_points: Optional[List[str]] = None

    # Disclaimer displayed in the UI alongside Gemini text
    ai_disclaimer: str = (
        "This explanation was generated by Gemini to summarise the evidence above. "
        "It does not perform independent classification. "
        "All detection decisions are made exclusively by TRINETRA's multi-signal detection engine."
    )


# ---------------------------------------------------------------------------
# Deterministic Fallback Engine
# ---------------------------------------------------------------------------

def _build_deterministic_explanation(bundle: EvidenceBundle) -> PhishingExplanation:
    """
    Produces a rule-based explanation from the evidence bundle.
    Always available, no external dependency.
    """

    score    = bundle.final_score_100
    severity = bundle.severity.upper()
    decision = bundle.decision.upper()

    verdict_summary = (
        f"TRINETRA's multi-signal detection engine assigned a risk score of "
        f"{score}/100 (severity: {severity}), resulting in decision: {decision}."
    )

    key_reasons: List[str] = list(bundle.evidence_summary)

    if bundle.content_risk_score is not None and bundle.content_risk_score >= 0.50:
        for sig in bundle.intent_signals[:3]:
            entry = f"[Content] {sig}"
            if entry not in key_reasons:
                key_reasons.append(entry)

    if bundle.url_risk_score is not None and bundle.url_risk_score >= 0.50:
        for sig in bundle.url_signals[:3]:
            entry = f"[URL] {sig}"
            if entry not in key_reasons:
                key_reasons.append(entry)
        for url in bundle.suspicious_urls[:2]:
            key_reasons.append(f"[URL] Suspicious URL detected: {url}")

    if bundle.identity_risk_score is not None and bundle.identity_risk_score >= 0.50:
        auth_failures = [
            auth
            for auth, result in [
                ("SPF",   bundle.spf_result),
                ("DKIM",  bundle.dkim_result),
                ("DMARC", bundle.dmarc_result),
            ]
            if result and result.upper() in (
                "FAIL", "NONE", "SOFTFAIL", "TEMPERROR", "PERMERROR"
            )
        ]
        if auth_failures:
            key_reasons.append(
                f"[Identity] Email authentication failed: {', '.join(auth_failures)}"
            )
        for sig in bundle.identity_signals[:2]:
            entry = f"[Identity] {sig}"
            if entry not in key_reasons:
                key_reasons.append(entry)

    if (
        bundle.threat_intel_risk_score is not None
        and bundle.threat_intel_risk_score >= 0.50
    ):
        for ind in bundle.threat_indicators[:3]:
            ioc    = ind.get("indicator", "")
            source = ind.get("source", "Threat Intelligence")
            sev_ti = ind.get("severity", "")
            if ioc:
                key_reasons.append(
                    f"[Threat Intel] {ioc} matched {source} (severity: {sev_ti})"
                )

    if bundle.graph_risk_score is not None and bundle.graph_risk_score >= 0.50:
        for sig in bundle.graph_signals[:2]:
            entry = f"[Graph] {sig}"
            if entry not in key_reasons:
                key_reasons.append(entry)

    if not key_reasons:
        if decision == "ALLOW":
            key_reasons = [
                "No significant threat indicators detected across evaluated layers."
            ]
        else:
            key_reasons = [
                "Moderate aggregate suspicion detected across evaluated signals. "
                "Manual review recommended."
            ]

    risk_breakdown: Dict[str, Any] = {
        "final_score_100":      bundle.final_score_100,
        "final_risk_score":     bundle.final_risk_score,
        "severity":             bundle.severity,
        "decision":             bundle.decision,
        "confidence":           bundle.confidence,
        "signal_contributions": bundle.signal_contributions,
        "layer_scores": {
            "content_risk":      bundle.content_risk_score,
            "url_risk":          bundle.url_risk_score,
            "identity_risk":     bundle.identity_risk_score,
            "threat_intel_risk": bundle.threat_intel_risk_score,
            "graph_risk":        bundle.graph_risk_score,
        },
    }

    return PhishingExplanation(
        status=ExplainabilityStatus.DETERMINISTIC,
        gemini_available=False,
        system_verdict_summary=verdict_summary,
        system_key_reasons=key_reasons,
        system_risk_breakdown=risk_breakdown,
        recommended_action=bundle.recommended_action,
    )


# ---------------------------------------------------------------------------
# Anti-hallucination Prompt Builder
# ---------------------------------------------------------------------------

def _build_gemini_prompt(bundle: EvidenceBundle) -> str:
    """
    Constructs a strictly scoped prompt for Gemini.
    Gemini receives only the evidence bundle and is prohibited from
    adding any facts not present in it.
    """

    bundle_json = json.dumps(
        {
            "email": {
                "subject":        bundle.subject,
                "sender":         bundle.sender_email,
                "sender_domain":  bundle.sender_domain,
                "recipient":      bundle.recipient,
                "timestamp":      bundle.timestamp,
            },
            "risk_assessment": {
                "final_score_100":    bundle.final_score_100,
                "severity":           bundle.severity,
                "decision":           bundle.decision,
                "confidence_pct":     round(bundle.confidence * 100, 1),
                "recommended_action": bundle.recommended_action,
            },
            "layer_scores": {
                "content_risk":      bundle.content_risk_score,
                "url_risk":          bundle.url_risk_score,
                "identity_risk":     bundle.identity_risk_score,
                "threat_intel_risk": bundle.threat_intel_risk_score,
                "graph_risk":        bundle.graph_risk_score,
            },
            "signal_contributions":  bundle.signal_contributions,
            "content_signals":       bundle.intent_signals,
            "url_signals":           bundle.url_signals,
            "suspicious_urls":       bundle.suspicious_urls,
            "auth_results": {
                "spf":   bundle.spf_result,
                "dkim":  bundle.dkim_result,
                "dmarc": bundle.dmarc_result,
            },
            "identity_signals":     bundle.identity_signals,
            "threat_intel_matches": bundle.threat_indicators,
            "graph_signals":        bundle.graph_signals,
            "evidence_summary":     bundle.evidence_summary,
        },
        indent=2,
        default=str,
    )

    prompt = textwrap.dedent(f"""
        You are a cybersecurity analyst assistant integrated into TRINETRA, an
        AI-powered phishing detection system.

        TRINETRA's automated detection engine has already analysed this email
        across 5 intelligence layers (Content, URL, Identity, Threat Intel, Graph)
        and produced the evidence bundle below.

        YOUR ROLE:
        - Explain the evidence in plain language for a SOC analyst.
        - You are an explainer, NOT a classifier. The detection verdict is final and
          was made by TRINETRA's engine, not by you.

        ABSOLUTE PROHIBITION — you must NEVER:
        - Invent or add any domain, URL, IP address, threat indicator,
          advisory ID, CERT-In match, graph relationship, or risk signal
          that does not appear in the evidence bundle below.
        - Speculate or add external knowledge about threats.
        - Mention any entity (domain, URL, IP, organisation) not present in the bundle.
        - Add qualifications like "this could be" or "might indicate" about facts
          outside the supplied evidence.
        - If a field is null or empty, do not mention it.

        EVIDENCE BUNDLE (system-generated, authoritative):
        {bundle_json}

        TASK:
        Return ONLY valid JSON (no markdown fences, no extra text) with exactly these keys:

        {{
          "plain_explanation": "<2-3 sentence plain-language explanation of why this email was flagged, citing only facts from the bundle>",
          "key_reasons": ["<reason 1 from bundle>", "<reason 2 from bundle>"],
          "risk_summary": "<1 sentence summarising the overall risk level and the single most critical signal>",
          "analyst_summary": "<1 sentence for an analyst about what to verify first>",
          "investigation_points": ["<concrete investigation action 1>", "<concrete investigation action 2>"]
        }}

        All values must cite only facts present in the evidence bundle above.
    """).strip()

    return prompt


# ---------------------------------------------------------------------------
# Gemini Client
# ---------------------------------------------------------------------------

async def _call_gemini(prompt: str, timeout_seconds: int = 15) -> Optional[Dict[str, Any]]:
    """
    Calls Gemini API asynchronously.
    Returns parsed JSON dict on success, None on any failure.
    Never raises — all exceptions are caught and logged.
    """
    if not settings.gemini_configured:
        logger.info("explainability_gemini_not_configured")
        return None

    try:
        import google.generativeai as genai  # type: ignore

        genai.configure(api_key=settings.GEMINI_API_KEY)
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config={
                "temperature":        0.1,
                "top_p":              0.8,
                "max_output_tokens":  1024,
                "response_mime_type": "application/json",
            },
        )

        loop = asyncio.get_event_loop()

        def _sync_call() -> str:
            response = model.generate_content(prompt)
            return response.text

        raw_text: str = await asyncio.wait_for(
            loop.run_in_executor(None, _sync_call),
            timeout=timeout_seconds,
        )

        # Strip any accidental markdown wrapping
        raw_text = raw_text.strip()
        if raw_text.startswith("```"):
            parts = raw_text.split("```")
            raw_text = parts[1] if len(parts) > 1 else ""
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        parsed = json.loads(raw_text)

        required = {
            "plain_explanation", "key_reasons",
            "risk_summary", "analyst_summary", "investigation_points",
        }
        if not required.issubset(parsed.keys()):
            logger.warning(
                "explainability_gemini_missing_keys",
                present=list(parsed.keys()),
            )
            return None

        logger.info("explainability_gemini_success")
        return parsed

    except asyncio.TimeoutError:
        logger.warning(
            "explainability_gemini_timeout", timeout_seconds=timeout_seconds
        )
        return None
    except json.JSONDecodeError as e:
        logger.warning("explainability_gemini_json_error", error=str(e))
        return None
    except Exception as e:
        logger.warning("explainability_gemini_error", error=str(e))
        return None


# ---------------------------------------------------------------------------
# Main Explainability Service
# ---------------------------------------------------------------------------

async def explain_email(bundle: EvidenceBundle) -> PhishingExplanation:
    """
    Primary entry point.
    Attempts Gemini explanation; falls back to deterministic if unavailable.

    Args:
        bundle: System-generated evidence from the detection engine.

    Returns:
        PhishingExplanation with system evidence + optional AI summary.
    """

    # Always build deterministic explanation first (instant, no external dependency)
    deterministic = _build_deterministic_explanation(bundle)
    risk_breakdown = deterministic.system_risk_breakdown

    # Attempt Gemini if configured
    if settings.gemini_configured:
        try:
            prompt = _build_gemini_prompt(bundle)
            parsed = await _call_gemini(prompt)

            if parsed:
                key_reasons_raw = parsed.get("key_reasons", [])
                inv_points_raw  = parsed.get("investigation_points", [])

                return PhishingExplanation(
                    status=ExplainabilityStatus.AI_GENERATED,
                    gemini_available=True,
                    system_verdict_summary=deterministic.system_verdict_summary,
                    system_key_reasons=deterministic.system_key_reasons,
                    system_risk_breakdown=risk_breakdown,
                    recommended_action=bundle.recommended_action,
                    ai_plain_explanation=str(parsed.get("plain_explanation", "")),
                    ai_key_reasons=(
                        key_reasons_raw
                        if isinstance(key_reasons_raw, list)
                        else [str(key_reasons_raw)]
                    ),
                    ai_risk_summary=str(parsed.get("risk_summary", "")),
                    ai_analyst_summary=str(parsed.get("analyst_summary", "")),
                    ai_investigation_points=(
                        inv_points_raw
                        if isinstance(inv_points_raw, list)
                        else [str(inv_points_raw)]
                    ),
                )
        except Exception as e:
            logger.warning("explainability_unexpected_error", error=str(e))

    # Return deterministic explanation
    return deterministic


# ---------------------------------------------------------------------------
# Convenience: build EvidenceBundle from risk engine + layer outputs
# ---------------------------------------------------------------------------

def build_evidence_bundle(
    risk_result: Any,
    subject:       Optional[str]        = None,
    sender_email:  Optional[str]        = None,
    sender_domain: Optional[str]        = None,
    recipient:     Optional[str]        = None,
    timestamp:     Optional[str]        = None,
    email_id:      Optional[str]        = None,
    layer_inputs:  Optional[Dict[str, Any]] = None,
) -> EvidenceBundle:
    """
    Builds an EvidenceBundle from the risk engine's RiskEvaluationResult
    and optional per-layer LayerSignalInput objects.
    """

    layer_inputs = layer_inputs or {}

    # Extract layer scores from the risk engine's layer_breakdown list
    layer_scores: Dict[str, Optional[float]] = {}
    for lb in getattr(risk_result, "layer_breakdown", []):
        layer_scores[lb.layer_name] = lb.raw_score

    def _ev(inp: Any) -> Dict[str, Any]:
        """Extract evidence dict from a LayerSignalInput or plain dict."""
        if inp is None:
            return {}
        if isinstance(inp, dict):
            return inp
        return getattr(inp, "evidence", {}) or {}

    content_ev  = _ev(layer_inputs.get("content_risk"))
    url_ev      = _ev(layer_inputs.get("url_risk"))
    id_ev       = _ev(layer_inputs.get("identity_risk"))
    ti_ev       = _ev(layer_inputs.get("threat_intel_risk"))
    graph_ev    = _ev(layer_inputs.get("graph_risk"))

    def _safe_list(val: Any) -> List[str]:
        if isinstance(val, list):
            return [str(v) for v in val]
        return []

    # Threat indicator dicts
    raw_indicators = ti_ev.get("indicators", [])
    threat_indicators: List[Dict[str, Any]] = []
    for ind in raw_indicators if isinstance(raw_indicators, list) else []:
        if isinstance(ind, dict):
            threat_indicators.append(ind)
        else:
            try:
                threat_indicators.append(ind.model_dump())
            except Exception:
                threat_indicators.append({"indicator": str(ind)})

    return EvidenceBundle(
        email_id=email_id,
        subject=subject,
        sender_email=sender_email,
        sender_domain=sender_domain,
        recipient=recipient,
        timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
        final_risk_score=risk_result.final_risk_score,
        final_score_100=risk_result.final_score_100,
        severity=risk_result.severity,
        decision=risk_result.decision,
        confidence=risk_result.confidence,
        recommended_action=risk_result.recommended_action,
        content_risk_score=layer_scores.get("content_risk"),
        url_risk_score=layer_scores.get("url_risk"),
        identity_risk_score=layer_scores.get("identity_risk"),
        threat_intel_risk_score=layer_scores.get("threat_intel_risk"),
        graph_risk_score=layer_scores.get("graph_risk"),
        signal_contributions=risk_result.signal_contributions,
        intent_signals=_safe_list(content_ev.get("intent_signals")),
        content_evidence=content_ev,
        url_signals=_safe_list(url_ev.get("url_signals")),
        suspicious_urls=_safe_list(url_ev.get("suspicious_urls")),
        url_evidence=url_ev,
        spf_result=str(id_ev.get("spf_result")) if id_ev.get("spf_result") else None,
        dkim_result=str(id_ev.get("dkim_result")) if id_ev.get("dkim_result") else None,
        dmarc_result=str(id_ev.get("dmarc_result")) if id_ev.get("dmarc_result") else None,
        identity_signals=_safe_list(id_ev.get("identity_signals")),
        identity_evidence=id_ev,
        threat_indicators=threat_indicators,
        threat_intel_evidence=ti_ev,
        graph_signals=_safe_list(graph_ev.get("graph_signals")),
        graph_evidence=graph_ev,
        evidence_summary=list(risk_result.evidence_summary),
    )
