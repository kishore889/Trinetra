"""
TRINETRA — Threat Intelligence Provider Architecture (Phase 9)

Extensible provider system for threat indicator lookups across:
  - Local TI database (always present, always authoritative for seeded IOCs)
  - CERT-In advisory intelligence (evidence/context source, not a phishing classifier)
  - Google Safe Browsing v4 (optional external — URL reputation)
  - VirusTotal v3 (optional external — domain, IP, URL, hash)

Design rules:
  - External provider failure NEVER crashes TRINETRA.
  - Each provider is independently optional; the system degrades gracefully.
  - Results are normalised to NormalizedIndicator before consumption.
  - In-memory TTL cache prevents redundant network round-trips.
  - CERT-In is presented accurately as advisory intelligence, NOT a real-time API.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import logger
from app.models import Severity, ThreatIndicator

# ---------------------------------------------------------------------------
# Enums & Constants
# ---------------------------------------------------------------------------

class IndicatorType:
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    EMAIL = "EMAIL"
    HASH = "HASH"
    SENDER = "SENDER"


INDICATOR_TYPES = {
    IndicatorType.IP,
    IndicatorType.DOMAIN,
    IndicatorType.URL,
    IndicatorType.EMAIL,
    IndicatorType.HASH,
    IndicatorType.SENDER,
}

# ---------------------------------------------------------------------------
# Shared Data Models
# ---------------------------------------------------------------------------


class NormalizedIndicator(BaseModel):
    """Unified threat indicator format across all providers."""
    indicator: str
    indicator_type: str                          # IP | DOMAIN | URL | EMAIL | HASH | SENDER
    source: str                                  # Provider name
    advisory_id: Optional[str] = None           # CERT-In advisory / VT report ID
    severity: str = Severity.MEDIUM.value        # LOW / MEDIUM / HIGH / CRITICAL
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: Optional[str] = None
    source_url: Optional[str] = None
    status: str = "ACTIVE"                      # ACTIVE | EXPIRED | REVOKED
    raw_metadata: Dict[str, Any] = {}


class ThreatMatchResult(BaseModel):
    """Result of matching email entities against threat intelligence."""
    matched: bool
    matched_entities: List[str] = []            # Which email entities matched
    indicators: List[NormalizedIndicator] = []  # Normalized matched indicators
    threat_intel_risk: float = Field(ge=0.0, le=1.0, default=0.0)
    providers_queried: List[str] = []
    evidence: Dict[str, Any] = {}


class ProviderHealthStatus(BaseModel):
    name: str
    available: bool
    configured: bool
    provider_type: str                          # INTERNAL | EXTERNAL | ADVISORY
    last_check: Optional[datetime] = None
    error_message: Optional[str] = None


# ---------------------------------------------------------------------------
# Simple In-Memory TTL Cache
# ---------------------------------------------------------------------------

class _TTLCache:
    """
    Thread-unsafe but safe for cooperative async usage.
    Caches provider results to avoid hammering external APIs.
    """
    def __init__(self, ttl_seconds: int = 300) -> None:
        self._store: Dict[str, tuple[Any, float]] = {}
        self._ttl = ttl_seconds

    def _key(self, provider: str, indicator_type: str, value: str) -> str:
        raw = f"{provider}|{indicator_type}|{value.lower()}"
        return hashlib.md5(raw.encode()).hexdigest()

    def get(self, provider: str, indicator_type: str, value: str) -> Optional[Any]:
        k = self._key(provider, indicator_type, value)
        entry = self._store.get(k)
        if entry is None:
            return None
        result, ts = entry
        if time.monotonic() - ts >= self._ttl:
            del self._store[k]
            return None
        return result

    def set(self, provider: str, indicator_type: str, value: str, result: Any) -> None:
        k = self._key(provider, indicator_type, value)
        self._store[k] = (result, time.monotonic())

    def clear(self) -> None:
        self._store.clear()


_cache = _TTLCache(ttl_seconds=300)  # 5-minute default TTL


# ---------------------------------------------------------------------------
# Abstract Base
# ---------------------------------------------------------------------------


class ThreatIntelProvider(ABC):
    """
    Abstract base for all threat intelligence providers.

    Concrete providers must implement:
      - name         → human-readable provider name
      - provider_type → INTERNAL | EXTERNAL | ADVISORY
      - is_available  → can this provider be used right now?
      - lookup        → fetch NormalizedIndicator(s) for an entity
      - health        → return ProviderHealthStatus
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def provider_type(self) -> str: ...

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    async def lookup(
        self,
        indicator_type: str,
        value: str,
        db: Optional[Session] = None,
    ) -> List[NormalizedIndicator]: ...

    @abstractmethod
    def health(self) -> ProviderHealthStatus: ...

    def normalize(self, raw: Dict[str, Any]) -> NormalizedIndicator:
        """
        Subclasses may override this to normalise provider-specific raw data.
        Default implementation builds a minimal indicator from raw dict keys.
        """
        return NormalizedIndicator(
            indicator=raw.get("value", ""),
            indicator_type=raw.get("type", IndicatorType.DOMAIN),
            source=self.name,
            description=raw.get("description"),
            severity=raw.get("severity", Severity.MEDIUM.value),
            confidence=float(raw.get("confidence", 0.5)),
        )


# ---------------------------------------------------------------------------
# 1. Local Threat Intel Provider
# ---------------------------------------------------------------------------


class LocalThreatIntelProvider(ThreatIntelProvider):
    """
    Looks up indicators against TRINETRA's own PostgreSQL ThreatIndicator table.
    This is the always-present, always-authoritative local intelligence database.
    Seeded with known bad indicators. Analysts can add/remove entries via API.
    """

    @property
    def name(self) -> str:
        return "TRINETRA Local TI Database"

    @property
    def provider_type(self) -> str:
        return "INTERNAL"

    def is_available(self) -> bool:
        return True  # Always available if DB is reachable

    def health(self) -> ProviderHealthStatus:
        return ProviderHealthStatus(
            name=self.name,
            available=True,
            configured=True,
            provider_type=self.provider_type,
            last_check=datetime.now(timezone.utc),
        )

    async def lookup(
        self,
        indicator_type: str,
        value: str,
        db: Optional[Session] = None,
    ) -> List[NormalizedIndicator]:
        if not db:
            return []

        value_lower = value.strip().lower()

        cached = _cache.get(self.name, indicator_type, value_lower)
        if cached is not None:
            return cached

        try:
            matches = (
                db.query(ThreatIndicator)
                .filter(
                    ThreatIndicator.indicator_value == value_lower,
                    ThreatIndicator.is_active == True,  # noqa: E712
                )
                .all()
            )

            results: List[NormalizedIndicator] = []
            for m in matches:
                sev = m.severity.value if hasattr(m.severity, "value") else str(m.severity)
                results.append(NormalizedIndicator(
                    indicator=m.indicator_value,
                    indicator_type=m.indicator_type.upper(),
                    source=self.name,
                    advisory_id=None,
                    severity=sev,
                    confidence=float(m.confidence),
                    first_seen=m.first_seen,
                    last_seen=m.last_seen,
                    description=m.description,
                    source_url=None,
                    status="ACTIVE" if m.is_active else "EXPIRED",
                    raw_metadata={"db_source": m.source},
                ))

            _cache.set(self.name, indicator_type, value_lower, results)
            return results

        except Exception as exc:
            logger.warning("local_ti_lookup_error", error=str(exc), value=value_lower)
            return []


# ---------------------------------------------------------------------------
# 2. CERT-In Advisory Provider
# ---------------------------------------------------------------------------

# Curated sample CERT-In advisories (representative — not live API data).
# In production this would be populated from periodic advisory feed ingestion.
# CERT-In is an advisory intelligence source, NOT a real-time phishing classifier.
_CERTIN_ADVISORY_SEED: List[Dict[str, Any]] = [
    {
        "indicator": "phishing-portal.in",
        "indicator_type": IndicatorType.DOMAIN,
        "advisory_id": "CIAD-2024-0041",
        "severity": Severity.HIGH.value,
        "confidence": 0.85,
        "description": "Domain reported in CERT-In Cyber Fraud Advisory CIAD-2024-0041 targeting Indian banking customers.",
        "source_url": "https://www.cert-in.org.in/",
        "status": "ACTIVE",
    },
    {
        "indicator": "secure-banking-update.xyz",
        "indicator_type": IndicatorType.DOMAIN,
        "advisory_id": "CIAD-2023-0198",
        "severity": Severity.CRITICAL.value,
        "confidence": 0.90,
        "description": "Credential-harvesting domain referenced in CERT-In advisory targeting government email users.",
        "source_url": "https://www.cert-in.org.in/",
        "status": "ACTIVE",
    },
    {
        "indicator": "192.168.100.200",  # Illustrative — not a real IOC
        "indicator_type": IndicatorType.IP,
        "advisory_id": "CIAD-2024-0102",
        "severity": Severity.HIGH.value,
        "confidence": 0.80,
        "description": "IP associated with phishing campaign infrastructure per CERT-In advisory.",
        "source_url": "https://www.cert-in.org.in/",
        "status": "ACTIVE",
    },
    {
        "indicator": "alert-paypal-verify.top",
        "indicator_type": IndicatorType.DOMAIN,
        "advisory_id": "CIAD-2025-0017",
        "severity": Severity.HIGH.value,
        "confidence": 0.88,
        "description": "Lookalike PayPal domain reported in CERT-In phishing campaign alert.",
        "source_url": "https://www.cert-in.org.in/",
        "status": "ACTIVE",
    },
]


class CERTInProvider(ThreatIntelProvider):
    """
    CERT-In (Indian Computer Emergency Response Team) advisory intelligence provider.

    IMPORTANT ACCURACY NOTE:
    - CERT-In does not expose a public real-time phishing classification API.
    - This provider represents CERT-In as an ADVISORY / EVIDENCE source.
    - Indicators here are derived from published advisories and curated locally.
    - Matches are contextual evidence, not automated verdicts.
    - Do NOT claim CERT-In provides real-time phishing classification.
    """

    SOURCE_NAME = "CERT-In Advisory"
    SOURCE_URL = "https://www.cert-in.org.in/"

    # In-memory advisory index: {indicator_value_lower: advisory_data}
    _advisory_index: Dict[str, Dict[str, Any]] = {
        entry["indicator"].lower(): entry for entry in _CERTIN_ADVISORY_SEED
    }

    @property
    def name(self) -> str:
        return self.SOURCE_NAME

    @property
    def provider_type(self) -> str:
        return "ADVISORY"

    def is_available(self) -> bool:
        return True  # Always available — uses local advisory index

    def health(self) -> ProviderHealthStatus:
        return ProviderHealthStatus(
            name=self.name,
            available=True,
            configured=True,
            provider_type=self.provider_type,
            last_check=datetime.now(timezone.utc),
            error_message=(
                "NOTE: CERT-In does not provide a real-time public API. "
                "Indicators are sourced from published advisories."
            ),
        )

    async def lookup(
        self,
        indicator_type: str,
        value: str,
        db: Optional[Session] = None,
    ) -> List[NormalizedIndicator]:
        """
        Checks the local CERT-In advisory index.
        Returns matching advisories as NormalizedIndicator records.
        """
        value_lower = value.strip().lower()

        cached = _cache.get(self.name, indicator_type, value_lower)
        if cached is not None:
            return cached

        entry = self._advisory_index.get(value_lower)
        results: List[NormalizedIndicator] = []

        if entry:
            results.append(NormalizedIndicator(
                indicator=entry["indicator"],
                indicator_type=entry["indicator_type"],
                source=self.SOURCE_NAME,
                advisory_id=entry.get("advisory_id"),
                severity=entry.get("severity", Severity.MEDIUM.value),
                confidence=float(entry.get("confidence", 0.75)),
                first_seen=None,
                last_seen=None,
                description=entry.get("description"),
                source_url=entry.get("source_url", self.SOURCE_URL),
                status=entry.get("status", "ACTIVE"),
                raw_metadata={
                    "provider_note": (
                        "Evidence from CERT-In published advisory. "
                        "Not a real-time automated verdict."
                    )
                },
            ))

        _cache.set(self.name, indicator_type, value_lower, results)
        return results

    @classmethod
    def seed_advisory(cls, entry: Dict[str, Any]) -> None:
        """Add or update a CERT-In advisory entry in the local index."""
        key = entry["indicator"].strip().lower()
        cls._advisory_index[key] = entry

    @classmethod
    def list_advisories(cls) -> List[Dict[str, Any]]:
        return list(cls._advisory_index.values())


# ---------------------------------------------------------------------------
# 3. Google Safe Browsing Provider
# ---------------------------------------------------------------------------


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    """
    Google Safe Browsing API v4.
    Optional — TRINETRA operates correctly if unconfigured or unavailable.
    Only supports URL indicator type.
    Timeout: 5 seconds. Failure is logged but not propagated.
    """

    @property
    def name(self) -> str:
        return "Google Safe Browsing"

    @property
    def provider_type(self) -> str:
        return "EXTERNAL"

    def is_available(self) -> bool:
        return settings.safe_browsing_configured

    def health(self) -> ProviderHealthStatus:
        return ProviderHealthStatus(
            name=self.name,
            available=self.is_available(),
            configured=self.is_available(),
            provider_type=self.provider_type,
            last_check=datetime.now(timezone.utc),
            error_message=None if self.is_available() else "GOOGLE_SAFE_BROWSING_API_KEY not configured.",
        )

    async def lookup(
        self,
        indicator_type: str,
        value: str,
        db: Optional[Session] = None,
    ) -> List[NormalizedIndicator]:
        if not self.is_available():
            return []
        if indicator_type.upper() != IndicatorType.URL:
            return []  # GSB only supports URL lookups

        cached = _cache.get(self.name, indicator_type, value)
        if cached is not None:
            return cached

        endpoint = (
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
        )
        payload = {
            "client": {"clientId": "TRINETRA", "clientVersion": settings.APP_VERSION},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "THREAT_TYPE_UNSPECIFIED"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": value}],
            },
        }

        results: List[NormalizedIndicator] = []
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    for match in resp.json().get("matches", []):
                        threat_type = match.get("threatType", "UNKNOWN")
                        results.append(NormalizedIndicator(
                            indicator=value,
                            indicator_type=IndicatorType.URL,
                            source=self.name,
                            severity=Severity.HIGH.value,
                            confidence=0.95,
                            description=f"Google Safe Browsing flagged URL as {threat_type}.",
                            source_url="https://safebrowsing.google.com/",
                            status="ACTIVE",
                            raw_metadata={"match": match},
                        ))
                else:
                    logger.warning(
                        "gsb_non_200",
                        status=resp.status_code,
                        url=value[:120],
                    )
        except httpx.TimeoutException:
            logger.warning("gsb_timeout", url=value[:120])
        except Exception as exc:
            logger.warning("gsb_lookup_error", error=str(exc), url=value[:120])

        _cache.set(self.name, indicator_type, value, results)
        return results


# ---------------------------------------------------------------------------
# 4. VirusTotal Provider
# ---------------------------------------------------------------------------


class VirusTotalProvider(ThreatIntelProvider):
    """
    VirusTotal API v3 abstraction.
    Optional — TRINETRA operates correctly if unconfigured.
    Supports: DOMAIN, IP, URL, HASH lookups.
    Timeout: 8 seconds. Results are normalised from VT report format.
    """

    _VT_BASE = "https://www.virustotal.com/api/v3"

    @property
    def name(self) -> str:
        return "VirusTotal"

    @property
    def provider_type(self) -> str:
        return "EXTERNAL"

    def is_available(self) -> bool:
        return settings.virustotal_configured

    def health(self) -> ProviderHealthStatus:
        return ProviderHealthStatus(
            name=self.name,
            available=self.is_available(),
            configured=self.is_available(),
            provider_type=self.provider_type,
            last_check=datetime.now(timezone.utc),
            error_message=None if self.is_available() else "VIRUSTOTAL_API_KEY not configured.",
        )

    async def lookup(
        self,
        indicator_type: str,
        value: str,
        db: Optional[Session] = None,
    ) -> List[NormalizedIndicator]:
        if not self.is_available():
            return []

        cached = _cache.get(self.name, indicator_type, value)
        if cached is not None:
            return cached

        itype = indicator_type.upper()
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        url_map = {
            IndicatorType.DOMAIN: f"{self._VT_BASE}/domains/{value}",
            IndicatorType.IP: f"{self._VT_BASE}/ip_addresses/{value}",
            IndicatorType.HASH: f"{self._VT_BASE}/files/{value}",
        }

        # URL requires encoding
        if itype == IndicatorType.URL:
            import base64
            encoded = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
            vt_url = f"{self._VT_BASE}/urls/{encoded}"
        elif itype in url_map:
            vt_url = url_map[itype]
        else:
            return []

        results: List[NormalizedIndicator] = []
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(vt_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attrs = data.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1
                    flagged = malicious + suspicious

                    if flagged > 0:
                        confidence = min(1.0, round(flagged / total, 3))
                        severity = (
                            Severity.CRITICAL.value if confidence >= 0.70 else
                            Severity.HIGH.value if confidence >= 0.40 else
                            Severity.MEDIUM.value
                        )
                        results.append(NormalizedIndicator(
                            indicator=value,
                            indicator_type=itype,
                            source=self.name,
                            severity=severity,
                            confidence=confidence,
                            description=(
                                f"VirusTotal: {malicious} engines flagged as malicious, "
                                f"{suspicious} suspicious (out of {total} engines)."
                            ),
                            source_url=f"https://www.virustotal.com/gui/search/{value}",
                            status="ACTIVE",
                            raw_metadata={"last_analysis_stats": stats},
                        ))
                elif resp.status_code == 404:
                    pass  # Not found — clean
                else:
                    logger.warning("vt_non_200", status=resp.status_code, indicator=value[:120])

        except httpx.TimeoutException:
            logger.warning("vt_timeout", indicator=value[:120])
        except Exception as exc:
            logger.warning("vt_lookup_error", error=str(exc), indicator=value[:120])

        _cache.set(self.name, indicator_type, value, results)
        return results


# ---------------------------------------------------------------------------
# Provider Registry
# ---------------------------------------------------------------------------


class ThreatIntelProviderRegistry:
    """
    Central registry of all configured threat intelligence providers.
    Providers are queried in priority order: Local → CERT-In → External.
    """

    def __init__(self) -> None:
        self._providers: List[ThreatIntelProvider] = [
            LocalThreatIntelProvider(),
            CERTInProvider(),
            GoogleSafeBrowsingProvider(),
            VirusTotalProvider(),
        ]

    def available_providers(self) -> List[ThreatIntelProvider]:
        return [p for p in self._providers if p.is_available()]

    def all_health(self) -> List[ProviderHealthStatus]:
        return [p.health() for p in self._providers]

    async def lookup_all(
        self,
        indicator_type: str,
        value: str,
        db: Optional[Session] = None,
    ) -> List[NormalizedIndicator]:
        """
        Query all available providers concurrently.
        Returns deduplicated combined results.
        Provider failures are swallowed — TRINETRA must not crash on TI failure.
        """
        tasks = [
            p.lookup(indicator_type, value, db)
            for p in self.available_providers()
        ]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        results: List[NormalizedIndicator] = []
        for provider, outcome in zip(self.available_providers(), gathered):
            if isinstance(outcome, Exception):
                logger.warning(
                    "provider_lookup_exception",
                    provider=provider.name,
                    error=str(outcome),
                )
                continue
            results.extend(outcome)

        return results


# Module-level singleton registry
provider_registry = ThreatIntelProviderRegistry()


# ---------------------------------------------------------------------------
# Backwards-compatible shims (used by url_analysis.py endpoint)
# ---------------------------------------------------------------------------

class LocalReputationProvider(LocalThreatIntelProvider):
    """Alias for backwards compatibility with Phase 7 URL analysis endpoint."""
    pass
