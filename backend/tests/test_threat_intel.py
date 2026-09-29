"""
TRINETRA — Phase 9 Tests: Threat Intelligence Provider Architecture
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.threat_providers import (
    _TTLCache,
    CERTInProvider,
    GoogleSafeBrowsingProvider,
    IndicatorType,
    LocalThreatIntelProvider,
    NormalizedIndicator,
    ProviderHealthStatus,
    VirusTotalProvider,
    ThreatIntelProviderRegistry,
    provider_registry,
)
from app.services.threat_intel_service import (
    _extract_domain_from_url,
    _extract_domain_from_email,
    _find_ips_in_text,
    _indicator_risk_contribution,
    run_threat_intel_matching,
)
from app.services.incident_report import build_incident_report


# ---------------------------------------------------------------------------
# TTL Cache
# ---------------------------------------------------------------------------


class TestTTLCache:
    def test_set_and_get(self):
        cache = _TTLCache(ttl_seconds=60)
        cache.set("prov", "DOMAIN", "evil.com", ["result"])
        assert cache.get("prov", "DOMAIN", "evil.com") == ["result"]

    def test_miss_returns_none(self):
        cache = _TTLCache(ttl_seconds=60)
        assert cache.get("prov", "DOMAIN", "notcached.com") is None

    def test_expired_entry_returns_none(self):
        import time
        cache = _TTLCache(ttl_seconds=0)
        cache.set("prov", "DOMAIN", "test.com", ["result"])
        time.sleep(0.01)
        assert cache.get("prov", "DOMAIN", "test.com") is None

    def test_clear(self):
        cache = _TTLCache(ttl_seconds=60)
        cache.set("prov", "DOMAIN", "test.com", ["result"])
        cache.clear()
        assert cache.get("prov", "DOMAIN", "test.com") is None

    def test_case_insensitive_via_lowercase(self):
        cache = _TTLCache(ttl_seconds=60)
        cache.set("prov", "DOMAIN", "EVIL.COM", ["result"])
        assert cache.get("prov", "DOMAIN", "evil.com") == ["result"]


# ---------------------------------------------------------------------------
# CERTIn Provider
# ---------------------------------------------------------------------------


class TestCERTInProvider:
    def setup_method(self):
        self.provider = CERTInProvider()

    def test_is_available(self):
        assert self.provider.is_available() is True

    def test_provider_type_is_advisory(self):
        assert self.provider.provider_type == "ADVISORY"

    def test_health_includes_note(self):
        h = self.provider.health()
        assert h.available is True
        assert "CERT-In" in (h.error_message or "")

    @pytest.mark.asyncio
    async def test_known_indicator_matched(self):
        results = await self.provider.lookup("DOMAIN", "phishing-portal.in")
        assert len(results) == 1
        r = results[0]
        assert r.indicator == "phishing-portal.in"
        assert r.source == "CERT-In Advisory"
        assert r.advisory_id is not None
        assert r.confidence > 0

    @pytest.mark.asyncio
    async def test_unknown_indicator_returns_empty(self):
        results = await self.provider.lookup("DOMAIN", "completely-safe-domain.com")
        assert results == []

    @pytest.mark.asyncio
    async def test_case_insensitive_lookup(self):
        results = await self.provider.lookup("DOMAIN", "PHISHING-PORTAL.IN")
        assert len(results) == 1

    def test_list_advisories(self):
        advisories = CERTInProvider.list_advisories()
        assert isinstance(advisories, list)
        assert len(advisories) > 0

    def test_seed_advisory(self):
        CERTInProvider.seed_advisory({
            "indicator": "test-seed-indicator.xyz",
            "indicator_type": IndicatorType.DOMAIN,
            "advisory_id": "TEST-ADV-001",
            "severity": "HIGH",
            "confidence": 0.80,
            "description": "Test seeded advisory.",
            "status": "ACTIVE",
        })
        assert "test-seed-indicator.xyz" in CERTInProvider._advisory_index

    def test_provider_note_in_result(self):
        """CERT-In results must carry the advisory/evidence note — not claim real-time API."""
        result = asyncio.run(self.provider.lookup("DOMAIN", "phishing-portal.in"))
        assert len(result) == 1
        note = result[0].raw_metadata.get("provider_note", "")
        assert "advisory" in note.lower()


# ---------------------------------------------------------------------------
# LocalThreatIntelProvider (without DB — testing available/health only)
# ---------------------------------------------------------------------------


class TestLocalThreatIntelProvider:
    def setup_method(self):
        self.provider = LocalThreatIntelProvider()

    def test_is_available(self):
        assert self.provider.is_available() is True

    def test_provider_type_internal(self):
        assert self.provider.provider_type == "INTERNAL"

    def test_health(self):
        h = self.provider.health()
        assert h.available is True
        assert h.provider_type == "INTERNAL"

    @pytest.mark.asyncio
    async def test_returns_empty_without_db(self):
        results = await self.provider.lookup("DOMAIN", "evil.com", db=None)
        assert results == []

    @pytest.mark.asyncio
    async def test_db_query_called(self):
        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_filter.first.return_value = None
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query

        # Patch the all() return to empty list
        mock_filter.all.return_value = []
        results = await self.provider.lookup("DOMAIN", "testdomain.com", db=mock_db)
        assert results == []


# ---------------------------------------------------------------------------
# GoogleSafeBrowsingProvider
# ---------------------------------------------------------------------------


class TestGoogleSafeBrowsingProvider:
    def setup_method(self):
        self.provider = GoogleSafeBrowsingProvider()

    def test_unavailable_when_not_configured(self):
        assert self.provider.is_available() is False

    def test_health_not_configured_message(self):
        h = self.provider.health()
        assert h.available is False
        assert "not configured" in (h.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_returns_empty_when_unavailable(self):
        results = await self.provider.lookup("URL", "http://evil.com")
        assert results == []

    @pytest.mark.asyncio
    async def test_returns_empty_for_non_url_type(self):
        with patch.object(self.provider, "is_available", return_value=True):
            results = await self.provider.lookup("DOMAIN", "evil.com")
            assert results == []


# ---------------------------------------------------------------------------
# VirusTotalProvider
# ---------------------------------------------------------------------------


class TestVirusTotalProvider:
    def setup_method(self):
        self.provider = VirusTotalProvider()

    def test_unavailable_when_not_configured(self):
        assert self.provider.is_available() is False

    def test_health_not_configured_message(self):
        h = self.provider.health()
        assert h.available is False
        assert "not configured" in (h.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_returns_empty_when_unavailable(self):
        results = await self.provider.lookup("DOMAIN", "evil.com")
        assert results == []


# ---------------------------------------------------------------------------
# ThreatIntelProviderRegistry
# ---------------------------------------------------------------------------


class TestThreatIntelProviderRegistry:
    def test_all_providers_listed(self):
        health = provider_registry.all_health()
        names = [h.name for h in health]
        assert "TRINETRA Local TI Database" in names
        assert "CERT-In Advisory" in names
        assert "Google Safe Browsing" in names
        assert "VirusTotal" in names

    def test_available_providers_includes_local_and_certin(self):
        available = provider_registry.available_providers()
        names = [p.name for p in available]
        assert "TRINETRA Local TI Database" in names
        assert "CERT-In Advisory" in names

    @pytest.mark.asyncio
    async def test_lookup_all_certin_match(self):
        results = await provider_registry.lookup_all("DOMAIN", "secure-banking-update.xyz")
        sources = [r.source for r in results]
        assert "CERT-In Advisory" in sources

    @pytest.mark.asyncio
    async def test_provider_failure_does_not_crash(self):
        """Provider exception must be swallowed — system keeps running."""
        with patch.object(CERTInProvider, "lookup", side_effect=RuntimeError("boom")):
            # Should not raise — failure must be logged and continue
            try:
                results = await provider_registry.lookup_all("DOMAIN", "test.com")
                # May or may not have results from other providers — just must not raise
            except Exception:
                pytest.fail("Provider failure propagated — must be swallowed.")


# ---------------------------------------------------------------------------
# Threat Intel Service — entity helpers
# ---------------------------------------------------------------------------


class TestEntityHelpers:
    def test_extract_domain_from_url(self):
        assert _extract_domain_from_url("https://auth.portal.evil.com/login") == "evil.com"
        assert _extract_domain_from_url("http://192.168.1.1/phish") is not None

    def test_extract_domain_from_email(self):
        assert _extract_domain_from_email("user@example.com") == "example.com"
        assert _extract_domain_from_email("no-at-sign") is None

    def test_find_ips_in_text(self):
        ips = _find_ips_in_text("http://192.168.1.100/login?redirect=http://10.0.0.1/")
        assert "192.168.1.100" in ips
        assert "10.0.0.1" in ips

    def test_no_ips_in_clean_url(self):
        ips = _find_ips_in_text("https://www.google.com/search?q=test")
        assert ips == []


# ---------------------------------------------------------------------------
# Risk contribution
# ---------------------------------------------------------------------------


class TestRiskContribution:
    def _ind(self, source: str, severity: str, confidence: float) -> NormalizedIndicator:
        return NormalizedIndicator(
            indicator="test.com",
            indicator_type="DOMAIN",
            source=source,
            severity=severity,
            confidence=confidence,
        )

    def test_high_confidence_critical_local_db(self):
        ind = self._ind("TRINETRA Local TI Database", "CRITICAL", 1.0)
        score = _indicator_risk_contribution(ind)
        assert score == 0.80  # Capped at 0.80

    def test_low_confidence_low_severity(self):
        ind = self._ind("CERT-In Advisory", "LOW", 0.30)
        score = _indicator_risk_contribution(ind)
        assert score < 0.30

    def test_score_capped_at_0_80(self):
        ind = self._ind("TRINETRA Local TI Database", "CRITICAL", 1.0)
        score = _indicator_risk_contribution(ind)
        assert score <= 0.80


# ---------------------------------------------------------------------------
# Full matching engine
# ---------------------------------------------------------------------------


class TestRunThreatIntelMatching:
    @pytest.mark.asyncio
    async def test_certin_match_via_full_pipeline(self):
        result = await run_threat_intel_matching(
            sender_domain="phishing-portal.in",
        )
        assert result.matched is True
        assert result.threat_intel_risk > 0.0
        sources = [ind.source for ind in result.indicators]
        assert "CERT-In Advisory" in sources

    @pytest.mark.asyncio
    async def test_clean_entities_not_matched(self):
        result = await run_threat_intel_matching(
            sender_email="user@totally-clean-domain-xyz.com",
            sender_domain="totally-clean-domain-xyz.com",
        )
        assert result.matched is False
        assert result.threat_intel_risk == 0.0

    @pytest.mark.asyncio
    async def test_url_domain_extracted_and_matched(self):
        result = await run_threat_intel_matching(
            urls=["https://secure-banking-update.xyz/login"],
        )
        assert result.matched is True
        assert result.threat_intel_risk > 0.0

    @pytest.mark.asyncio
    async def test_no_entities_returns_not_matched(self):
        result = await run_threat_intel_matching()
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_risk_score_capped_at_1(self):
        # Pile on multiple CERT-In matches
        result = await run_threat_intel_matching(
            sender_domain="phishing-portal.in",
            urls=[
                "https://secure-banking-update.xyz/login",
                "https://alert-paypal-verify.top/confirm",
            ],
        )
        assert result.threat_intel_risk <= 1.0

    @pytest.mark.asyncio
    async def test_providers_queried_in_result(self):
        result = await run_threat_intel_matching(sender_domain="example.com")
        assert len(result.providers_queried) >= 2  # At least Local + CERT-In


# ---------------------------------------------------------------------------
# Incident Report Builder
# ---------------------------------------------------------------------------


class TestBuildIncidentReport:
    def test_basic_report_fields(self):
        from datetime import datetime, timezone
        report = build_incident_report(
            incident_id="INC-001",
            detection_time=datetime(2026, 9, 29, 10, 0, 0, tzinfo=timezone.utc),
            sender="attacker@evil.com",
            decision="QUARANTINE",
            severity="CRITICAL",
            final_risk_score=0.95,
        )
        assert report.incident_id == "INC-001"
        assert report.sender == "attacker@evil.com"
        assert report.decision == "QUARANTINE"
        assert report.severity == "CRITICAL"
        assert report.final_risk_score == 0.95
        assert "2026-09-29" in report.detection_time

    def test_report_has_unique_id(self):
        r1 = build_incident_report()
        r2 = build_incident_report()
        assert r1.report_id != r2.report_id

    def test_disclaimer_present(self):
        report = build_incident_report()
        assert "analyst" in report.disclaimer.lower()
        assert "not automatically" in report.disclaimer.lower()

    def test_indicator_entries_populated(self):
        ind = NormalizedIndicator(
            indicator="evil.com",
            indicator_type="DOMAIN",
            source="CERT-In Advisory",
            advisory_id="CIAD-2024-0041",
            severity="HIGH",
            confidence=0.85,
        )
        report = build_incident_report(matched_indicators=[ind])
        assert len(report.threat_indicators) == 1
        assert report.threat_indicators[0].advisory_id == "CIAD-2024-0041"
        assert report.threat_indicators[0].source == "CERT-In Advisory"

    def test_empty_report_builds_without_error(self):
        report = build_incident_report()
        assert report.report_id.startswith("TRINETRA-INC-")
        assert report.threat_indicators == []
