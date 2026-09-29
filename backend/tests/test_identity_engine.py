"""
TRINETRA — Phase 8 Tests: Identity / Spoofing Intelligence Engine
"""
import pytest
from app.services.identity_engine import (
    analyze_sender_identity,
    parse_email_address,
    parse_authentication_results,
    detect_display_name_spoofing,
    detect_free_provider_impersonation,
    detect_reply_to_mismatch,
    ParsedAddress,
)


# ---------------------------------------------------------------------------
# parse_email_address
# ---------------------------------------------------------------------------


class TestParseEmailAddress:
    def test_simple_email(self):
        result = parse_email_address("user@example.com")
        assert result is not None
        assert result.email == "user@example.com"
        assert result.domain == "example.com"
        assert result.display_name is None

    def test_display_name_with_angle_brackets(self):
        result = parse_email_address("John Doe <john@example.com>")
        assert result is not None
        assert result.display_name == "John Doe"
        assert result.email == "john@example.com"

    def test_quoted_display_name(self):
        result = parse_email_address('"Microsoft Support" <support@fakems.xyz>')
        assert result is not None
        assert "Microsoft Support" in result.display_name
        assert result.domain == "fakems.xyz"

    def test_free_provider_detection(self):
        result = parse_email_address("PaypalSupport <alert@gmail.com>")
        assert result is not None
        assert result.is_free_provider is True

    def test_tld_extraction(self):
        result = parse_email_address("admin@malicious.xyz")
        assert result is not None
        assert result.tld == "xyz"

    def test_returns_none_for_invalid(self):
        result = parse_email_address("not-an-email")
        assert result is None

    def test_returns_none_for_empty(self):
        result = parse_email_address("")
        assert result is None


# ---------------------------------------------------------------------------
# parse_authentication_results
# ---------------------------------------------------------------------------


class TestParseAuthenticationResults:
    def _headers(self, auth_results="", spf="", dkim_sig=""):
        return {
            "authentication-results": auth_results,
            "received-spf": spf,
            "dkim-signature": dkim_sig,
        }

    def test_all_pass(self):
        headers = self._headers(
            auth_results="spf=pass dkim=pass dmarc=pass"
        )
        result = parse_authentication_results(headers)
        assert result.spf == "pass"
        assert result.dkim == "pass"
        assert result.dmarc == "pass"
        assert result.all_pass is True
        assert result.any_fail is False

    def test_spf_fail(self):
        headers = self._headers(auth_results="spf=fail dkim=pass dmarc=fail")
        result = parse_authentication_results(headers)
        assert result.spf == "fail"
        assert result.dmarc == "fail"
        assert result.any_fail is True
        assert result.all_pass is False

    def test_spf_softfail(self):
        headers = self._headers(spf="spf=softfail")
        result = parse_authentication_results(headers)
        assert result.spf == "softfail"
        assert result.any_fail is True

    def test_empty_headers(self):
        result = parse_authentication_results({})
        assert result.spf == "unknown"
        assert result.dkim == "unknown"
        assert result.dmarc == "unknown"
        assert result.all_pass is False

    def test_dkim_present_via_signature_header(self):
        headers = self._headers(dkim_sig="v=1; a=rsa-sha256; ...")
        result = parse_authentication_results(headers)
        assert result.dkim_present is True


# ---------------------------------------------------------------------------
# Signal detectors
# ---------------------------------------------------------------------------


class TestDisplayNameSpoofing:
    def _addr(self, display, domain):
        return ParsedAddress(
            raw="test", display_name=display, email=f"x@{domain}",
            local_part="x", domain=domain, tld=domain.split(".")[-1],
        )

    def test_detects_microsoft_spoof(self):
        addr = self._addr("Microsoft Security Team", "random-domain.com")
        sig = detect_display_name_spoofing(addr)
        assert sig is not None
        assert sig.signal_type == "DISPLAY_NAME_SPOOFING"

    def test_no_signal_for_legitimate(self):
        addr = self._addr("Microsoft", "microsoft.com")
        sig = detect_display_name_spoofing(addr)
        assert sig is None

    def test_detects_paypal_spoof(self):
        addr = self._addr("PayPal Billing Department", "malicious.top")
        sig = detect_display_name_spoofing(addr)
        assert sig is not None

    def test_no_signal_when_no_display_name(self):
        addr = self._addr(None, "evil.com")
        sig = detect_display_name_spoofing(addr)
        assert sig is None


class TestFreeProviderImpersonation:
    def _addr(self, display, domain):
        is_free = domain in {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}
        return ParsedAddress(
            raw="test", display_name=display, email=f"x@{domain}",
            local_part="x", domain=domain, tld=domain.split(".")[-1],
            is_free_provider=is_free,
        )

    def test_detects_paypal_from_gmail(self):
        addr = self._addr("PayPal Support", "gmail.com")
        sig = detect_free_provider_impersonation(addr)
        assert sig is not None
        assert sig.signal_type == "FREE_PROVIDER_BRAND_IMPERSONATION"

    def test_no_signal_for_non_brand_gmail(self):
        addr = self._addr("John Smith", "gmail.com")
        sig = detect_free_provider_impersonation(addr)
        assert sig is None

    def test_no_signal_for_brand_from_corporate(self):
        addr = self._addr("Apple Support", "apple.com")
        addr.is_free_provider = False
        sig = detect_free_provider_impersonation(addr)
        assert sig is None


class TestReplyToMismatch:
    def _addr(self, domain):
        return ParsedAddress(
            raw="test", email=f"x@{domain}", local_part="x",
            domain=domain, tld=domain.split(".")[-1],
        )

    def test_detects_mismatch(self):
        from_addr = self._addr("legitimate.com")
        reply_to = self._addr("hijacked-domain.com")
        sig = detect_reply_to_mismatch(from_addr, reply_to)
        assert sig is not None
        assert sig.signal_type == "REPLY_TO_DOMAIN_MISMATCH"

    def test_no_signal_when_domains_match(self):
        from_addr = self._addr("legitimate.com")
        reply_to = self._addr("legitimate.com")
        sig = detect_reply_to_mismatch(from_addr, reply_to)
        assert sig is None

    def test_no_signal_when_no_reply_to(self):
        from_addr = self._addr("legitimate.com")
        sig = detect_reply_to_mismatch(from_addr, None)
        assert sig is None


# ---------------------------------------------------------------------------
# Full analyze_sender_identity integration tests
# ---------------------------------------------------------------------------


class TestAnalyzeSenderIdentity:

    PHISHING_HEADERS = {
        "authentication-results": "spf=fail dkim=fail dmarc=fail",
    }

    CLEAN_HEADERS = {
        "authentication-results": "spf=pass dkim=pass dmarc=pass",
    }

    def test_high_risk_phishing_scenario(self):
        """Classic credential-harvesting phishing: spoofed Microsoft from free provider."""
        result = analyze_sender_identity(
            from_header='"Microsoft Security Alert" <security@gmail.com>',
            headers=self.PHISHING_HEADERS,
            reply_to_header="attacker@malicious.xyz",
        )
        assert result.identity_risk_score > 0.5
        signal_types = {s.signal_type for s in result.signals}
        assert "FREE_PROVIDER_BRAND_IMPERSONATION" in signal_types
        assert "REPLY_TO_DOMAIN_MISMATCH" in signal_types

    def test_low_risk_legitimate_scenario(self):
        """Legitimate corporate email with all auth passing."""
        result = analyze_sender_identity(
            from_header="John Smith <john.smith@microsoft.com>",
            headers=self.CLEAN_HEADERS,
        )
        # Should have very low or zero risk score
        assert result.identity_risk_score < 0.30
        assert result.authentication.all_pass is True

    def test_lookalike_domain_detected(self):
        result = analyze_sender_identity(
            from_header="support@micros0ft.com",
            headers={},
        )
        signal_types = {s.signal_type for s in result.signals}
        assert "LOOKALIKE_SENDER_DOMAIN" in signal_types

    def test_spf_fail_contributes_to_score(self):
        result = analyze_sender_identity(
            from_header="billing@unknown-domain.com",
            headers={"authentication-results": "spf=fail"},
        )
        assert result.identity_risk_score > 0.0
        assert result.authentication.spf == "fail"

    def test_known_sender_flagged(self):
        result = analyze_sender_identity(
            from_header="alice@trusted.com",
            headers=self.CLEAN_HEADERS,
            known_sender_emails={"alice@trusted.com"},
        )
        assert result.known_sender is True
        assert result.first_contact is False

    def test_first_contact_unknown_sender(self):
        result = analyze_sender_identity(
            from_header="stranger@brand-new-domain.com",
            headers={},
        )
        assert result.first_contact is True
        assert result.known_sender is False

    def test_envelope_from_mismatch_detected(self):
        result = analyze_sender_identity(
            from_header="support@bank.com",
            headers={},
            return_path_header="bounces@phishing-infra.top",
        )
        signal_types = {s.signal_type for s in result.signals}
        assert "ENVELOPE_FROM_MISMATCH" in signal_types

    def test_risk_score_capped_at_1(self):
        """Pile on every bad signal — score must not exceed 1.0."""
        result = analyze_sender_identity(
            from_header='"Paypal Security" <alert@gmail.com>',
            headers={"authentication-results": "spf=fail dkim=fail dmarc=fail"},
            reply_to_header="evil@hijacked.xyz",
            return_path_header="bounce@totally-different.top",
        )
        assert result.identity_risk_score <= 1.0
        assert result.identity_risk_score > 0.5
