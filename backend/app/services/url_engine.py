"""
TRINETRA — URL & Domain Intelligence Engine (Layer 2)

Performs static lexical, structural, and brand-impersonation analysis on URLs and domains.
SAFETY RULE: ZERO NETWORK VISITS. No URLs are requested or visited, preventing SSRF and exploit execution.
Calculates:
- Structural metrics (length, dot count, hyphens, subdomains, special chars)
- IP-based hostnames
- Punycode / IDN homoglyphs
- URL shortener identification
- Suspicious TLD detection
- Credential & auth keywords
- Claimed-brand lookalike / typo-squatting detection
- Threat provider abstraction (Safe Browsing, VirusTotal, Local TI DB)
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

# High-risk TLDs commonly abused in phishing campaigns
SUSPICIOUS_TLDS: Set[str] = {
    "top", "xyz", "club", "online", "work", "loan", "info", "fit", "surf",
    "buzz", "icu", "cam", "cfd", "sbs", "rest", "support", "live", "link"
}

# Known URL shortener domains
SHORTENER_DOMAINS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "cutt.ly", "goo.gl", "tiny.cc", "shorte.st"
}

# High-profile brands frequently targeted for impersonation
TARGET_BRANDS: List[str] = [
    "microsoft", "office365", "google", "apple", "paypal", "amazon",
    "bankofamerica", "wellsfargo", "chase", "netflix", "docusign", "dropbox",
    "outlook", "sharepoint", "facebook", "instagram", "whatsapp", "linkedin"
]

# Sensitive / Credential harvesting keywords
CREDENTIAL_KEYWORDS: Set[str] = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "update", "account", "security", "banking", "secure", "authenticate",
    "confirm", "password", "credential", "auth", "session", "recover", "token"
}


class URLSignal(BaseModel):
    signal_type: str
    weight: float
    description: str
    evidence_value: Any = None


class URLFeatureSet(BaseModel):
    raw_url: str
    normalized_url: str
    scheme: str
    hostname: str
    domain: str
    port: Optional[int] = None
    path: str
    query: str
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    subdomain_count: int
    dot_count: int
    hyphen_count: int
    digit_count: int
    special_char_count: int
    is_ip_hostname: bool
    is_punycode: bool
    is_shortener: bool
    is_https: bool
    has_credential_keywords: bool
    has_suspicious_tld: bool
    impersonated_brand: Optional[str] = None
    brand_similarity_score: float = 0.0


class URLAnalysisResult(BaseModel):
    url_risk_score: float  # 0.0 to 1.0
    domain_risk_score: float  # 0.0 to 1.0
    signals: List[URLSignal]
    features: URLFeatureSet
    evidence: Dict[str, Any]


class MultiURLAnalysisResult(BaseModel):
    max_url_risk_score: float
    average_url_risk_score: float
    total_urls_analyzed: int
    suspicious_urls_count: int
    highest_risk_url: Optional[str] = None
    analyzed_urls: List[URLAnalysisResult]


def normalize_url(raw_url: str) -> Tuple[str, urllib.parse.ParseResult]:
    """
    Safely normalizes raw URL without network communication.
    Ensures standard scheme, lowercase hostname, and standardized path.
    """
    url = raw_url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query = parsed.query

    normalized = urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))
    return normalized, parsed


def check_is_ip_address(hostname: str) -> bool:
    """Checks whether hostname is a raw IPv4 or IPv6 address."""
    clean_host = hostname.split(":")[0]  # strip port if present
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def extract_domain_parts(hostname: str) -> Tuple[str, int]:
    """
    Extracts base registrable domain and count of subdomains.
    Example: 'auth.portal.micros0ft.com' -> ('micros0ft.com', 2)
    """
    clean_host = hostname.split(":")[0]
    parts = clean_host.split(".")
    if len(parts) <= 2:
        return clean_host, 0
    # Basic second-level domain heuristic (handles standard .com, .org, etc.)
    domain = ".".join(parts[-2:])
    subdomains = len(parts) - 2
    return domain, subdomains


def check_brand_similarity(hostname: str) -> Tuple[Optional[str], float]:
    """
    Detects typosquatting and lookalike domains against high-profile target brands.
    Examples: 'micros0ft.com', 'paypa1-security.com', 'app1e-support.net'
    """
    clean_host = hostname.split(":")[0].lower()
    # Remove standard tlds and dots for comparison
    core_host = clean_host.split(".")[0] if "." in clean_host else clean_host

    best_brand = None
    highest_sim = 0.0

    for brand in TARGET_BRANDS:
        # If legitimately the brand domain or its subdomain, skip
        if clean_host == f"{brand}.com" or clean_host.endswith(f".{brand}.com"):
            continue

        # Check direct substring containment with modifications (e.g. google-security.com)
        if brand in clean_host:
            return brand, 0.95

        # Check leetspeak substitutions (0 -> o, 1 -> l, etc.)
        deobfuscated = clean_host.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s")
        if deobfuscated != clean_host and brand in deobfuscated:
            return brand, 0.92

        sim = SequenceMatcher(None, core_host, brand).ratio()
        if sim > 0.78 and sim < 1.0:
            if sim > highest_sim:
                highest_sim = sim
                best_brand = brand

    return best_brand, round(highest_sim, 3)


def analyze_single_url(raw_url: str) -> URLAnalysisResult:
    """
    Performs complete static analysis of a single URL.
    ZERO network calls performed.
    """
    normalized_url, parsed = normalize_url(raw_url)
    hostname = (parsed.hostname or "").lower()
    domain, subdomain_count = extract_domain_parts(hostname)

    path = parsed.path or ""
    query = parsed.query or ""

    # 1. Compute Structural Features
    is_ip = check_is_ip_address(hostname)
    is_punycode = "xn--" in hostname
    is_shortener = domain in SHORTENER_DOMAINS or hostname in SHORTENER_DOMAINS
    is_https = parsed.scheme.lower() == "https"

    dot_count = hostname.count(".")
    hyphen_count = raw_url.count("-")
    digit_count = sum(c.isdigit() for c in hostname)
    special_chars = sum(c in "@%&=_~" for c in raw_url)

    # Suspicious TLD check
    tld = hostname.split(".")[-1] if "." in hostname else ""
    has_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Credential keywords in path/query
    url_lower = raw_url.lower()
    matched_cred_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in url_lower]
    has_credential_keywords = len(matched_cred_keywords) > 0

    # Brand similarity / lookalike
    impersonated_brand, brand_sim = check_brand_similarity(hostname)

    features = URLFeatureSet(
        raw_url=raw_url,
        normalized_url=normalized_url,
        scheme=parsed.scheme.lower(),
        hostname=hostname,
        domain=domain,
        port=parsed.port,
        path=path,
        query=query,
        url_length=len(raw_url),
        hostname_length=len(hostname),
        path_length=len(path),
        query_length=len(query),
        subdomain_count=subdomain_count,
        dot_count=dot_count,
        hyphen_count=hyphen_count,
        digit_count=digit_count,
        special_char_count=special_chars,
        is_ip_hostname=is_ip,
        is_punycode=is_punycode,
        is_shortener=is_shortener,
        is_https=is_https,
        has_credential_keywords=has_credential_keywords,
        has_suspicious_tld=has_suspicious_tld,
        impersonated_brand=impersonated_brand,
        brand_similarity_score=brand_sim,
    )

    # 2. Derive Layer Signals & Weighted Risk Scores
    signals: List[URLSignal] = []
    accumulated_risk = 0.0

    if is_ip:
        signals.append(URLSignal(
            signal_type="RAW_IP_HOSTNAME",
            weight=0.85,
            description="URL uses raw IP address instead of domain name, obscuring hosting identity.",
            evidence_value=hostname,
        ))
        accumulated_risk += 0.40

    if is_punycode:
        signals.append(URLSignal(
            signal_type="PUNYCODE_HOMOGLYPH",
            weight=0.90,
            description="Hostname uses Punycode / IDN internationalized domain (potential homoglyph attack).",
            evidence_value=hostname,
        ))
        accumulated_risk += 0.45

    if is_shortener:
        signals.append(URLSignal(
            signal_type="URL_SHORTENER_OBFUSCATION",
            weight=0.60,
            description="URL utilizes a shortening service to conceal destination endpoint.",
            evidence_value=domain,
        ))
        accumulated_risk += 0.25

    if impersonated_brand:
        signals.append(URLSignal(
            signal_type="BRAND_LOOKALIKE_DOMAIN",
            weight=0.92,
            description=f"Hostname mimics known brand '{impersonated_brand}' (typosquatting / deceptive similarity).",
            evidence_value={"brand": impersonated_brand, "similarity": brand_sim},
        ))
        accumulated_risk += 0.50

    if has_credential_keywords:
        signals.append(URLSignal(
            signal_type="CREDENTIAL_HARVESTING_PATH",
            weight=0.75,
            description="URL path or query contains sensitive authentication terms.",
            evidence_value=matched_cred_keywords,
        ))
        accumulated_risk += 0.25

    if has_suspicious_tld:
        signals.append(URLSignal(
            signal_type="HIGH_RISK_TLD",
            weight=0.65,
            description=f"URL uses high-abuse top-level domain '.{tld}'.",
            evidence_value=tld,
        ))
        accumulated_risk += 0.20

    if not is_https:
        signals.append(URLSignal(
            signal_type="INSECURE_HTTP_SCHEME",
            weight=0.45,
            description="URL lacks TLS encryption (HTTP plain text).",
            evidence_value=parsed.scheme,
        ))
        accumulated_risk += 0.15

    if subdomain_count >= 3:
        signals.append(URLSignal(
            signal_type="EXCESSIVE_SUBDOMAINS",
            weight=0.60,
            description=f"Hostname contains {subdomain_count} nested subdomains.",
            evidence_value=subdomain_count,
        ))
        accumulated_risk += 0.20

    if len(raw_url) > 120 or len(query) > 60:
        signals.append(URLSignal(
            signal_type="LONG_QUERY_OBFUSCATION",
            weight=0.50,
            description="Abnormally long URL or query string used to bypass perimeter filters.",
            evidence_value={"url_len": len(raw_url), "query_len": len(query)},
        ))
        accumulated_risk += 0.15

    # Compute consolidated scores
    url_risk_score = round(min(1.0, accumulated_risk), 4)
    domain_risk_score = round(min(1.0, (
        (0.5 if is_ip else 0.0) +
        (0.5 if is_punycode else 0.0) +
        (0.4 if impersonated_brand else 0.0) +
        (0.2 if has_suspicious_tld else 0.0)
    )), 4)

    evidence = {
        "signals_count": len(signals),
        "impersonated_brand": impersonated_brand,
        "matched_credential_keywords": matched_cred_keywords,
        "is_ip_hostname": is_ip,
        "is_punycode": is_punycode,
        "is_shortener": is_shortener,
    }

    return URLAnalysisResult(
        url_risk_score=url_risk_score,
        domain_risk_score=domain_risk_score,
        signals=signals,
        features=features,
        evidence=evidence,
    )


def analyze_urls_list(urls: List[str]) -> MultiURLAnalysisResult:
    """Analyzes a collection of extracted URLs from an email."""
    if not urls:
        return MultiURLAnalysisResult(
            max_url_risk_score=0.0,
            average_url_risk_score=0.0,
            total_urls_analyzed=0,
            suspicious_urls_count=0,
            highest_risk_url=None,
            analyzed_urls=[],
        )

    results = [analyze_single_url(u) for u in urls]
    scores = [r.url_risk_score for r in results]
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)

    highest_idx = scores.index(max_score)
    highest_url = urls[highest_idx] if max_score > 0 else None
    suspicious_count = sum(1 for s in scores if s >= 0.5)

    return MultiURLAnalysisResult(
        max_url_risk_score=round(max_score, 4),
        average_url_risk_score=round(avg_score, 4),
        total_urls_analyzed=len(urls),
        suspicious_urls_count=suspicious_count,
        highest_risk_url=highest_url,
        analyzed_urls=results,
    )
