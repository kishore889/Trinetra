"""
TRINETRA — Identity / Spoofing Intelligence Engine (Layer 3)

Analyzes sender identity and authentication signals to detect:
- Email authentication failures (SPF, DKIM, DMARC)
- Display name spoofing (mismatch between friendly name and actual address)
- Free-provider impersonation (corporate-sounding name from gmail.com / yahoo.com)
- Reply-To hijacking (reply-to differs from From address)
- Domain look-alike / cousin domain in sender address
- First-contact anomaly (sender never seen before)
- Homoglyph / punycode in sender domain
- Mismatched envelope / header From (P1/P2 mismatch)

SAFETY: No network calls. All analysis is lexical and structural.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FREE_EMAIL_PROVIDERS: Set[str] = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk",
    "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com", "aol.com", "protonmail.com",
    "tutanota.com", "zoho.com", "yandex.com", "yandex.ru", "mail.com",
    "gmx.com", "gmx.de", "inbox.com", "rediffmail.com",
}

# High-profile organisations whose name appearing in a display name from
# a free-email account is almost certainly spoofing.
SENSITIVE_BRAND_NAMES: List[str] = [
    "microsoft", "office", "google", "apple", "amazon", "paypal", "netflix",
    "bank of america", "wells fargo", "chase", "citibank", "barclays",
    "hsbc", "irs", "internal revenue", "federal", "linkedin", "facebook",
    "instagram", "whatsapp", "docusign", "dropbox", "salesforce", "adobe",
    "helpdesk", "support", "security", "admin", "noreply", "no-reply",
    "notification", "alert", "account", "billing", "invoice",
]

# Suspicious TLDs that often appear in cousin/lookalike sender domains
SUSPICIOUS_SENDER_TLDS: Set[str] = {
    "top", "xyz", "club", "online", "work", "loan", "info", "fit", "surf",
    "buzz", "icu", "cam", "cfd", "sbs", "rest", "support", "live", "link",
}

# Known authentication result keywords (from Received-SPF / Authentication-Results headers)
SPF_PASS_PATTERNS = re.compile(r'\bspf=pass\b', re.IGNORECASE)
SPF_FAIL_PATTERNS = re.compile(r'\bspf=(fail|softfail|none|neutral|temperror|permerror)\b', re.IGNORECASE)
DKIM_PASS_PATTERNS = re.compile(r'\bdkim=pass\b', re.IGNORECASE)
DKIM_FAIL_PATTERNS = re.compile(r'\bdkim=(fail|none|neutral|policy|temperror|permerror)\b', re.IGNORECASE)
DMARC_PASS_PATTERNS = re.compile(r'\bdmarc=pass\b', re.IGNORECASE)
DMARC_FAIL_PATTERNS = re.compile(r'\bdmarc=(fail|none|bestguesspass|temperror|permerror)\b', re.IGNORECASE)

# Regex to parse "Display Name <email@domain.com>" or just "email@domain.com"
EMAIL_ADDR_RE = re.compile(r'(?:"?([^"<>]*)"?\s+)?<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?')

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


class AuthenticationResult(BaseModel):
    spf: Optional[str] = None          # "pass" | "fail" | "softfail" | "none" | "unknown"
    dkim: Optional[str] = None         # "pass" | "fail" | "none" | "unknown"
    dmarc: Optional[str] = None        # "pass" | "fail" | "none" | "unknown"
    spf_present: bool = False
    dkim_present: bool = False
    dmarc_present: bool = False
    all_pass: bool = False
    any_fail: bool = False


class ParsedAddress(BaseModel):
    raw: str
    display_name: Optional[str] = None
    email: Optional[str] = None
    local_part: Optional[str] = None
    domain: Optional[str] = None
    tld: Optional[str] = None
    is_free_provider: bool = False


class IdentitySignal(BaseModel):
    signal_type: str
    weight: float = Field(ge=0.0, le=1.0)
    description: str
    evidence_value: Any = None


class IdentityAnalysisResult(BaseModel):
    identity_risk_score: float = Field(ge=0.0, le=1.0)
    authentication: AuthenticationResult
    from_address: Optional[ParsedAddress] = None
    reply_to_address: Optional[ParsedAddress] = None
    envelope_from: Optional[ParsedAddress] = None
    signals: List[IdentitySignal]
    evidence: Dict[str, Any]
    known_sender: bool = False
    first_contact: bool = True


# ---------------------------------------------------------------------------
# Parsing Helpers
# ---------------------------------------------------------------------------


def parse_email_address(raw: str) -> Optional[ParsedAddress]:
    """
    Parses a raw From/Reply-To/Envelope-From header value into structured parts.
    Returns None if no valid email address could be extracted.
    """
    if not raw or not raw.strip():
        return None

    raw = raw.strip()
    match = EMAIL_ADDR_RE.search(raw)
    if not match:
        return None

    display_name = (match.group(1) or "").strip().strip('"').strip("'")
    email = (match.group(2) or "").strip().lower()

    if "@" not in email:
        return None

    local_part, domain = email.rsplit("@", 1)
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""

    return ParsedAddress(
        raw=raw,
        display_name=display_name if display_name else None,
        email=email,
        local_part=local_part,
        domain=domain,
        tld=tld,
        is_free_provider=domain in FREE_EMAIL_PROVIDERS,
    )


def parse_authentication_results(headers: Dict[str, str]) -> AuthenticationResult:
    """
    Parses SPF, DKIM, DMARC results from email headers.

    Checks:
    - Authentication-Results
    - Received-SPF
    - DKIM-Signature presence
    """
    auth_header = headers.get("authentication-results", "") or headers.get("Authentication-Results", "")
    spf_header = headers.get("received-spf", "") or headers.get("Received-SPF", "")
    dkim_header = headers.get("dkim-signature", "") or headers.get("DKIM-Signature", "")

    combined = f"{auth_header} {spf_header}"

    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None

    # SPF
    if SPF_PASS_PATTERNS.search(combined):
        spf_result = "pass"
    elif m := SPF_FAIL_PATTERNS.search(combined):
        spf_result = m.group(1).lower()

    # DKIM
    if DKIM_PASS_PATTERNS.search(combined):
        dkim_result = "pass"
    elif m := DKIM_FAIL_PATTERNS.search(combined):
        dkim_result = m.group(1).lower()

    # DMARC
    if DMARC_PASS_PATTERNS.search(combined):
        dmarc_result = "pass"
    elif m := DMARC_FAIL_PATTERNS.search(combined):
        dmarc_result = m.group(1).lower()

    # DKIM presence via DKIM-Signature header
    dkim_present = bool(dkim_header) or dkim_result is not None
    spf_present = spf_result is not None
    dmarc_present = dmarc_result is not None

    all_pass = (spf_result == "pass" and dkim_result == "pass" and dmarc_result == "pass")
    any_fail = any(
        r not in (None, "pass") for r in [spf_result, dkim_result, dmarc_result]
    )

    return AuthenticationResult(
        spf=spf_result or "unknown",
        dkim=dkim_result or "unknown",
        dmarc=dmarc_result or "unknown",
        spf_present=spf_present,
        dkim_present=dkim_present,
        dmarc_present=dmarc_present,
        all_pass=all_pass,
        any_fail=any_fail,
    )


# ---------------------------------------------------------------------------
# Signal Detectors
# ---------------------------------------------------------------------------


def detect_display_name_spoofing(
    from_addr: ParsedAddress,
) -> Optional[IdentitySignal]:
    """
    Detects when the display name matches a sensitive brand but the actual
    sending domain is unrelated (e.g. "Microsoft <security@randomdomain.xyz>").
    """
    if not from_addr.display_name or not from_addr.domain:
        return None

    display_lower = from_addr.display_name.lower()
    for brand in SENSITIVE_BRAND_NAMES:
        if brand in display_lower:
            # If sender domain does NOT contain the brand, it's suspicious
            if brand not in from_addr.domain.lower():
                return IdentitySignal(
                    signal_type="DISPLAY_NAME_SPOOFING",
                    weight=0.90,
                    description=(
                        f"Display name '{from_addr.display_name}' references brand/keyword "
                        f"'{brand}' but the actual sending domain is '{from_addr.domain}'."
                    ),
                    evidence_value={
                        "display_name": from_addr.display_name,
                        "brand_keyword": brand,
                        "actual_domain": from_addr.domain,
                    },
                )
    return None


def detect_free_provider_impersonation(
    from_addr: ParsedAddress,
) -> Optional[IdentitySignal]:
    """
    Detects corporate-name / brand display names sent from free email providers.
    E.g. "Paypal Support <someone@gmail.com>"
    """
    if not from_addr.is_free_provider or not from_addr.display_name:
        return None

    display_lower = from_addr.display_name.lower()
    for brand in SENSITIVE_BRAND_NAMES:
        if brand in display_lower:
            return IdentitySignal(
                signal_type="FREE_PROVIDER_BRAND_IMPERSONATION",
                weight=0.88,
                description=(
                    f"Display name '{from_addr.display_name}' impersonates '{brand}' "
                    f"while using a free email provider ({from_addr.domain})."
                ),
                evidence_value={
                    "display_name": from_addr.display_name,
                    "brand_keyword": brand,
                    "provider_domain": from_addr.domain,
                },
            )
    return None


def detect_reply_to_mismatch(
    from_addr: ParsedAddress,
    reply_to_addr: Optional[ParsedAddress],
) -> Optional[IdentitySignal]:
    """
    Detects Reply-To hijacking — where replies would go to a completely different
    domain than the sender, a common phishing tactic to intercept victim responses.
    """
    if not reply_to_addr or not from_addr.domain or not reply_to_addr.domain:
        return None

    if from_addr.domain.lower() != reply_to_addr.domain.lower():
        return IdentitySignal(
            signal_type="REPLY_TO_DOMAIN_MISMATCH",
            weight=0.82,
            description=(
                f"Reply-To domain '{reply_to_addr.domain}' differs from "
                f"From domain '{from_addr.domain}'. Victim replies will be redirected."
            ),
            evidence_value={
                "from_domain": from_addr.domain,
                "reply_to_domain": reply_to_addr.domain,
                "reply_to_email": reply_to_addr.email,
            },
        )
    return None


def detect_authentication_failures(
    auth: AuthenticationResult,
) -> List[IdentitySignal]:
    """
    Emits signals for SPF/DKIM/DMARC failures or absent authentication.
    """
    signals: List[IdentitySignal] = []

    if auth.spf in ("fail", "softfail"):
        signals.append(IdentitySignal(
            signal_type="SPF_AUTHENTICATION_FAILURE",
            weight=0.80,
            description=f"SPF check returned '{auth.spf}'. The sending server is not authorized for this domain.",
            evidence_value={"spf_result": auth.spf},
        ))
    elif auth.spf == "unknown" and not auth.spf_present:
        signals.append(IdentitySignal(
            signal_type="SPF_RECORD_ABSENT",
            weight=0.40,
            description="No SPF authentication result found. Sender domain may lack SPF record.",
            evidence_value={"spf_result": "absent"},
        ))

    if auth.dkim in ("fail",):
        signals.append(IdentitySignal(
            signal_type="DKIM_SIGNATURE_FAILURE",
            weight=0.85,
            description="DKIM signature verification failed. Email content or headers may have been tampered.",
            evidence_value={"dkim_result": auth.dkim},
        ))
    elif auth.dkim == "unknown" and not auth.dkim_present:
        signals.append(IdentitySignal(
            signal_type="DKIM_SIGNATURE_ABSENT",
            weight=0.35,
            description="No DKIM signature present. Message authenticity cannot be cryptographically verified.",
            evidence_value={"dkim_result": "absent"},
        ))

    if auth.dmarc in ("fail",):
        signals.append(IdentitySignal(
            signal_type="DMARC_POLICY_FAILURE",
            weight=0.88,
            description="DMARC policy check failed. Email does not align with the sender domain's published policy.",
            evidence_value={"dmarc_result": auth.dmarc},
        ))
    elif auth.dmarc == "unknown" and not auth.dmarc_present:
        signals.append(IdentitySignal(
            signal_type="DMARC_RECORD_ABSENT",
            weight=0.35,
            description="No DMARC policy result found. Domain may not publish a DMARC record.",
            evidence_value={"dmarc_result": "absent"},
        ))

    return signals


def detect_lookalike_sender_domain(
    from_addr: ParsedAddress,
) -> Optional[IdentitySignal]:
    """
    Detects typosquatting / cousin domains in the sender's email domain.
    E.g. "security@micros0ft.com", "billing@paypa1.com"
    """
    if not from_addr.domain:
        return None

    domain_lower = from_addr.domain.lower()

    for brand in ["microsoft", "google", "apple", "paypal", "amazon",
                  "netflix", "bankofamerica", "wellsfargo", "chase",
                  "docusign", "dropbox", "linkedin", "facebook"]:

        # Direct partial match check (the brand name appears in the domain
        # but the domain is NOT the official one)
        if brand in domain_lower:
            # Legitimate domains: microsoft.com, google.com etc.
            # If domain is exactly brand.com, skip
            if domain_lower in (f"{brand}.com", f"{brand}.org", f"{brand}.net"):
                continue
            return IdentitySignal(
                signal_type="LOOKALIKE_SENDER_DOMAIN",
                weight=0.85,
                description=(
                    f"Sender domain '{from_addr.domain}' contains brand keyword '{brand}' "
                    f"but is not the legitimate official domain."
                ),
                evidence_value={"domain": from_addr.domain, "brand": brand},
            )

        # Fuzzy similarity check for near-matches
        core_domain = domain_lower.split(".")[0]
        sim = SequenceMatcher(None, core_domain, brand).ratio()
        if 0.80 <= sim < 1.0:
            return IdentitySignal(
                signal_type="LOOKALIKE_SENDER_DOMAIN",
                weight=0.82,
                description=(
                    f"Sender domain '{from_addr.domain}' is lexically similar to brand "
                    f"'{brand}' (similarity: {sim:.2f}). Possible typosquatting."
                ),
                evidence_value={"domain": from_addr.domain, "brand": brand, "similarity": round(sim, 3)},
            )

    return None


def detect_suspicious_sender_tld(
    from_addr: ParsedAddress,
) -> Optional[IdentitySignal]:
    """Flags sender domains using high-abuse TLDs."""
    if from_addr.tld and from_addr.tld.lower() in SUSPICIOUS_SENDER_TLDS:
        return IdentitySignal(
            signal_type="SUSPICIOUS_SENDER_TLD",
            weight=0.55,
            description=f"Sender domain uses high-abuse TLD '.{from_addr.tld}'.",
            evidence_value={"tld": from_addr.tld, "domain": from_addr.domain},
        )
    return None


def detect_homoglyph_sender(
    from_addr: ParsedAddress,
) -> Optional[IdentitySignal]:
    """Detects punycode / IDN in sender domain (potential homoglyph attack)."""
    if from_addr.domain and "xn--" in from_addr.domain.lower():
        return IdentitySignal(
            signal_type="SENDER_HOMOGLYPH_DOMAIN",
            weight=0.90,
            description=(
                f"Sender domain '{from_addr.domain}' uses Punycode/IDN encoding. "
                "May be a homoglyph attack designed to visually impersonate a legitimate domain."
            ),
            evidence_value={"domain": from_addr.domain},
        )
    return None


def detect_envelope_from_mismatch(
    from_addr: ParsedAddress,
    envelope_from: Optional[ParsedAddress],
) -> Optional[IdentitySignal]:
    """
    Detects P1/P2 mismatch: when the envelope sender (MAIL FROM / Return-Path)
    differs from the header From address, commonly used in phishing.
    """
    if not envelope_from or not from_addr.domain or not envelope_from.domain:
        return None

    if from_addr.domain.lower() != envelope_from.domain.lower():
        return IdentitySignal(
            signal_type="ENVELOPE_FROM_MISMATCH",
            weight=0.78,
            description=(
                f"Header From domain '{from_addr.domain}' does not match "
                f"envelope/return-path domain '{envelope_from.domain}'. "
                "Indicates potential spoofing via P1/P2 mismatch."
            ),
            evidence_value={
                "header_from": from_addr.email,
                "envelope_from": envelope_from.email,
            },
        )
    return None


# ---------------------------------------------------------------------------
# Main Analysis Entry Point
# ---------------------------------------------------------------------------


def analyze_sender_identity(
    *,
    from_header: str,
    headers: Dict[str, str],
    reply_to_header: Optional[str] = None,
    return_path_header: Optional[str] = None,
    known_sender_domains: Optional[Set[str]] = None,
    known_sender_emails: Optional[Set[str]] = None,
) -> IdentityAnalysisResult:
    """
    Full identity and spoofing analysis for a single email.

    Args:
        from_header:           Raw 'From' header value.
        headers:               Full dict of parsed email headers (lowercase keys preferred).
        reply_to_header:       Raw 'Reply-To' header value (optional).
        return_path_header:    Raw 'Return-Path' or 'X-Original-Sender' value (optional).
        known_sender_domains:  Set of domains seen before from this Gmail account.
        known_sender_emails:   Set of email addresses seen before.

    Returns:
        IdentityAnalysisResult with risk score, signals, and evidence.
    """
    known_sender_domains = known_sender_domains or set()
    known_sender_emails = known_sender_emails or set()

    # --- Parse addresses ---
    from_addr = parse_email_address(from_header)
    reply_to_addr = parse_email_address(reply_to_header) if reply_to_header else None
    envelope_from = parse_email_address(return_path_header) if return_path_header else None

    # --- Parse authentication results ---
    auth = parse_authentication_results(headers)

    # --- Determine sender familiarity ---
    known_sender = False
    first_contact = True
    if from_addr and from_addr.email:
        if from_addr.email in known_sender_emails:
            known_sender = True
            first_contact = False
        elif from_addr.domain in known_sender_domains:
            first_contact = False

    # --- Collect signals ---
    signals: List[IdentitySignal] = []

    if from_addr:
        # Display name spoofing
        sig = detect_display_name_spoofing(from_addr)
        if sig:
            signals.append(sig)

        # Free provider brand impersonation
        sig = detect_free_provider_impersonation(from_addr)
        if sig:
            signals.append(sig)

        # Reply-To mismatch
        sig = detect_reply_to_mismatch(from_addr, reply_to_addr)
        if sig:
            signals.append(sig)

        # Lookalike sender domain
        sig = detect_lookalike_sender_domain(from_addr)
        if sig:
            signals.append(sig)

        # Suspicious TLD
        sig = detect_suspicious_sender_tld(from_addr)
        if sig:
            signals.append(sig)

        # Homoglyph / punycode sender domain
        sig = detect_homoglyph_sender(from_addr)
        if sig:
            signals.append(sig)

        # Envelope-from (P1/P2) mismatch
        sig = detect_envelope_from_mismatch(from_addr, envelope_from)
        if sig:
            signals.append(sig)

    # Authentication failure signals
    auth_signals = detect_authentication_failures(auth)
    signals.extend(auth_signals)

    # First contact with a high-risk domain — mild penalty
    if first_contact and from_addr and not from_addr.is_free_provider:
        if from_addr.tld and from_addr.tld.lower() in SUSPICIOUS_SENDER_TLDS:
            signals.append(IdentitySignal(
                signal_type="FIRST_CONTACT_SUSPICIOUS_DOMAIN",
                weight=0.60,
                description=(
                    f"First-ever message from '{from_addr.domain}' which uses a high-abuse TLD. "
                    "No prior relationship with this sender."
                ),
                evidence_value={"domain": from_addr.domain},
            ))

    # --- Compute identity risk score ---
    # Weighted accumulation, capped at 1.0
    # Authentication failure alone cannot push score > 0.60 (structural signals are needed)
    auth_contribution = 0.0
    structural_contribution = 0.0

    for sig in signals:
        if sig.signal_type in (
            "SPF_AUTHENTICATION_FAILURE", "DKIM_SIGNATURE_FAILURE",
            "DMARC_POLICY_FAILURE", "SPF_RECORD_ABSENT",
            "DKIM_SIGNATURE_ABSENT", "DMARC_RECORD_ABSENT",
        ):
            auth_contribution += sig.weight * 0.20
        else:
            structural_contribution += sig.weight * 0.30

    identity_risk_score = round(min(1.0, auth_contribution + structural_contribution), 4)

    # If BOTH structural deception AND authentication failure are present, amplify
    has_structural = any(
        s.signal_type in (
            "DISPLAY_NAME_SPOOFING", "FREE_PROVIDER_BRAND_IMPERSONATION",
            "LOOKALIKE_SENDER_DOMAIN", "SENDER_HOMOGLYPH_DOMAIN",
            "REPLY_TO_DOMAIN_MISMATCH", "ENVELOPE_FROM_MISMATCH",
        ) for s in signals
    )
    has_auth_failure = auth.any_fail

    if has_structural and has_auth_failure:
        identity_risk_score = round(min(1.0, identity_risk_score + 0.20), 4)

    evidence: Dict[str, Any] = {
        "from_email": from_addr.email if from_addr else None,
        "from_domain": from_addr.domain if from_addr else None,
        "from_display_name": from_addr.display_name if from_addr else None,
        "reply_to_email": reply_to_addr.email if reply_to_addr else None,
        "envelope_from_email": envelope_from.email if envelope_from else None,
        "is_free_provider": from_addr.is_free_provider if from_addr else None,
        "spf": auth.spf,
        "dkim": auth.dkim,
        "dmarc": auth.dmarc,
        "auth_all_pass": auth.all_pass,
        "auth_any_fail": auth.any_fail,
        "signals_count": len(signals),
        "known_sender": known_sender,
        "first_contact": first_contact,
    }

    return IdentityAnalysisResult(
        identity_risk_score=identity_risk_score,
        authentication=auth,
        from_address=from_addr,
        reply_to_address=reply_to_addr,
        envelope_from=envelope_from,
        signals=signals,
        evidence=evidence,
        known_sender=known_sender,
        first_contact=first_contact,
    )
