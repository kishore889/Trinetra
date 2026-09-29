"""
TRINETRA — Threat Intelligence Matching Engine (Phase 9)

Matches email entities (sender, sender domain, URLs, domains, IPs)
against all configured threat intelligence providers and produces:
  - A consolidated ThreatMatchResult with matched indicators
  - A threat_intel_risk score (0.0–1.0) for the Risk Engine
  - Full evidence payload for explainability

Design rules:
  - Every external indicator match is weighted by its source confidence.
  - No provider match is treated as absolute truth without source/context.
  - Failure of any single provider does not abort the pipeline.
  - Async — all provider lookups run concurrently.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.services.threat_providers import (
    NormalizedIndicator,
    ThreatMatchResult,
    IndicatorType,
    provider_registry,
)


# ---------------------------------------------------------------------------
# Entity Extraction Helpers
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _extract_domain_from_url(url: str) -> Optional[str]:
    """Extracts the registrable domain from a URL string."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        # Strip port
        host = host.split(":")[0]
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return None


def _extract_domain_from_email(email: str) -> Optional[str]:
    """Extracts the domain part of an email address."""
    if "@" in email:
        return email.rsplit("@", 1)[-1].strip().lower()
    return None


def _find_ips_in_text(text: str) -> List[str]:
    return _IP_RE.findall(text)


# ---------------------------------------------------------------------------
# Risk Weight per Provider Source
# ---------------------------------------------------------------------------

_SOURCE_WEIGHTS: Dict[str, float] = {
    "TRINETRA Local TI Database": 1.00,   # Highest trust — analyst-curated local DB
    "CERT-In Advisory": 0.75,              # High trust — official advisory, contextual
    "Google Safe Browsing": 0.90,          # High trust — real-time Google TI
    "VirusTotal": 0.85,                    # High trust — multi-engine consensus
}

_SEVERITY_SCORES: Dict[str, float] = {
    "CRITICAL": 1.00,
    "HIGH": 0.75,
    "MEDIUM": 0.50,
    "LOW": 0.25,
}


def _indicator_risk_contribution(indicator: NormalizedIndicator) -> float:
    """
    Computes the risk contribution of a single matched indicator.
    = confidence × source_weight × severity_score
    Capped at 0.80 per indicator so a single match cannot dominate.
    """
    source_weight = _SOURCE_WEIGHTS.get(indicator.source, 0.70)
    sev_score = _SEVERITY_SCORES.get(indicator.severity.upper(), 0.50)
    raw = indicator.confidence * source_weight * sev_score
    return round(min(0.80, raw), 4)


# ---------------------------------------------------------------------------
# Main Matching Engine
# ---------------------------------------------------------------------------


async def run_threat_intel_matching(
    *,
    sender_email: Optional[str] = None,
    sender_domain: Optional[str] = None,
    urls: Optional[List[str]] = None,
    subject: Optional[str] = None,
    db: Optional[Session] = None,
) -> ThreatMatchResult:
    """
    Matches all extractable email entities against configured TI providers.

    Entities queried:
      - sender email address (EMAIL)
      - sender domain (DOMAIN)
      - each URL (URL)
      - domain extracted from each URL (DOMAIN)
      - IP addresses found in URLs (IP)

    Returns:
        ThreatMatchResult with consolidated indicators, risk score, and evidence.
    """
    entities: List[tuple[str, str]] = []  # (indicator_type, value)
    queried_providers = [p.name for p in provider_registry.available_providers()]

    # Build entity list from email metadata
    if sender_email and "@" in sender_email:
        entities.append((IndicatorType.EMAIL, sender_email.lower().strip()))

    if sender_domain:
        entities.append((IndicatorType.DOMAIN, sender_domain.lower().strip()))
    elif sender_email and "@" in sender_email:
        domain = _extract_domain_from_email(sender_email)
        if domain:
            entities.append((IndicatorType.DOMAIN, domain))

    for url in (urls or []):
        url_stripped = url.strip()
        if url_stripped:
            entities.append((IndicatorType.URL, url_stripped))
            domain = _extract_domain_from_url(url_stripped)
            if domain:
                entities.append((IndicatorType.DOMAIN, domain))
            for ip in _find_ips_in_text(url_stripped):
                entities.append((IndicatorType.IP, ip))

    # Deduplicate while preserving order
    seen: Set[tuple[str, str]] = set()
    unique_entities: List[tuple[str, str]] = []
    for entity in entities:
        if entity not in seen:
            seen.add(entity)
            unique_entities.append(entity)

    if not unique_entities:
        return ThreatMatchResult(
            matched=False,
            providers_queried=queried_providers,
            evidence={"note": "No entities to match."},
        )

    # Concurrently query all providers for all entities
    tasks = [
        provider_registry.lookup_all(itype, value, db)
        for itype, value in unique_entities
    ]

    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    all_indicators: List[NormalizedIndicator] = []
    matched_entities: List[str] = []
    entity_match_map: Dict[str, List[NormalizedIndicator]] = {}

    for (itype, value), outcome in zip(unique_entities, gathered):
        if isinstance(outcome, Exception):
            logger.warning("ti_entity_match_error", entity=value, error=str(outcome))
            continue
        if outcome:
            all_indicators.extend(outcome)
            matched_entities.append(f"{itype}:{value}")
            entity_match_map[f"{itype}:{value}"] = outcome

    # Compute consolidated threat_intel_risk score
    # Accumulate contributions; cap at 1.0
    accumulated_risk = 0.0
    for indicator in all_indicators:
        accumulated_risk += _indicator_risk_contribution(indicator)
    threat_intel_risk = round(min(1.0, accumulated_risk), 4)

    evidence: Dict[str, Any] = {
        "entities_queried": [f"{t}:{v}" for t, v in unique_entities],
        "matched_entities": matched_entities,
        "indicators_found": len(all_indicators),
        "providers_queried": queried_providers,
        "entity_match_detail": {
            entity: [ind.model_dump() for ind in inds]
            for entity, inds in entity_match_map.items()
        },
    }

    return ThreatMatchResult(
        matched=len(all_indicators) > 0,
        matched_entities=matched_entities,
        indicators=all_indicators,
        threat_intel_risk=threat_intel_risk,
        providers_queried=queried_providers,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Synchronous wrapper (for use in sync FastAPI endpoints)
# ---------------------------------------------------------------------------


def run_threat_intel_matching_sync(
    *,
    sender_email: Optional[str] = None,
    sender_domain: Optional[str] = None,
    urls: Optional[List[str]] = None,
    subject: Optional[str] = None,
    db: Optional[Session] = None,
) -> ThreatMatchResult:
    """
    Synchronous wrapper around run_threat_intel_matching for FastAPI sync endpoints.
    Creates a new event loop if none is running.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in an async context, schedule as a coroutine
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(
                    asyncio.run,
                    run_threat_intel_matching(
                        sender_email=sender_email,
                        sender_domain=sender_domain,
                        urls=urls,
                        subject=subject,
                        db=db,
                    ),
                )
                return future.result()
        else:
            return loop.run_until_complete(
                run_threat_intel_matching(
                    sender_email=sender_email,
                    sender_domain=sender_domain,
                    urls=urls,
                    subject=subject,
                    db=db,
                )
            )
    except Exception as exc:
        logger.error("ti_matching_sync_error", error=str(exc))
        return ThreatMatchResult(
            matched=False,
            evidence={"error": str(exc)},
        )
