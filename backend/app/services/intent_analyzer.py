"""
TRINETRA — Phishing Intent & Semantic Signal Extraction

Analyzes textual content (subject, body text) for specific attack patterns:
- credential harvesting
- password request
- OTP / MFA request
- financial / wire / payment request
- account suspension / termination threat
- password reset lure
- urgent action / artificial deadline
- sensitive personal information request
- brand / authority impersonation language
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from pydantic import BaseModel


class IntentSignal(BaseModel):
    signal_type: str
    weight: float
    matched_phrases: List[str]
    description: str


# Rule patterns mapping to specific phishing intents
INTENT_PATTERNS: Dict[str, Tuple[float, str, List[re.Pattern]]] = {
    "CREDENTIAL_HARVESTING": (
        0.85,
        "Requests user credentials, login details, or account authentication verification.",
        [
            re.compile(r'\b(verify|validate|update|confirm)\s+(your|account|credentials|identity|profile)\b', re.I),
            re.compile(r'\b(login|sign[\s-]in|log[\s-]on)\s+(to|immediately|here|at)\b', re.I),
            re.compile(r'\b(re-enter|input)\s+(your|the)\s+(password|passcode|pin)\b', re.I),
            re.compile(r'\b(credential|access)\s+(expiry|expired|validation)\b', re.I),
        ]
    ),
    "PASSWORD_REQUEST": (
        0.90,
        "Explicitly solicits password or passcode disclosure.",
        [
            re.compile(r'\b(send|provide|submit|share)\s+(your\s+)?(password|passphrase|secret key)\b', re.I),
            re.compile(r'\b(password|passcode)\s+(change|reset)\s+(required|needed)\b', re.I),
        ]
    ),
    "OTP_MFA_REQUEST": (
        0.95,
        "Solicits One-Time Password (OTP), verification codes, or MFA tokens.",
        [
            re.compile(r'\b(one[\s-]time\s+password|otp|mfa|2fa|verification\s+code|security\s+token)\b', re.I),
            re.compile(r'\b(enter|share|provide|reply\s+with)\s+(the\s+)?(code|otp|token)\b', re.I),
        ]
    ),
    "FINANCIAL_PAYMENT_REQUEST": (
        0.80,
        "Requests urgent payment, wire transfer, remittance, or banking update.",
        [
            re.compile(r'\b(wire\s+transfer|remittance|bank\s+account|routing\s+number|direct\s+deposit)\b', re.I),
            re.compile(r'\b(overdue\s+invoice|unpaid\s+balance|payment\s+required|send\s+payment)\b', re.I),
            re.compile(r'\b(update\s+billing|billing\s+information|credit\s+card\s+details)\b', re.I),
        ]
    ),
    "ACCOUNT_SUSPENSION_THREAT": (
        0.75,
        "Threatens imminent account closure, suspension, or disruption of service.",
        [
            re.compile(r'\b(account\s+(will\s+be\s+)?(suspended|terminated|deactivated|closed|locked|blocked))\b', re.I),
            re.compile(r'\b(prevent|avoid)\s+(suspension|termination|account\s+closure)\b', re.I),
            re.compile(r'\b(immediate\s+action\s+required|take\s+action\s+now)\b', re.I),
        ]
    ),
    "URGENT_ACTION": (
        0.65,
        "Uses high-pressure psychological urgency and artificial deadlines.",
        [
            re.compile(r'\b(within\s+\d+\s+(hours?|minutes?|days?)|24\s+hours|48\s+hours)\b', re.I),
            re.compile(r'\b(urgent|urgently|immediate|strictly\s+required|critical\s+notice)\b', re.I),
            re.compile(r'\b(failure\s+to\s+comply|without\s+delay)\b', re.I),
        ]
    ),
    "SENSITIVE_INFO_REQUEST": (
        0.70,
        "Requests sensitive identity identifiers (SSN, national ID, tax information).",
        [
            re.compile(r'\b(social\s+security\s+number|ssn|tax\s+id|pan\s+card|aadhaar)\b', re.I),
            re.compile(r'\b(passport\s+copy|driver[\'s]*\s+license|identity\s+document)\b', re.I),
        ]
    ),
    "IMPERSONATION_LANGUAGE": (
        0.70,
        "Employs authoritative impersonation keywords (Security Team, IT Support, Executive).",
        [
            re.compile(r'\b(it\s+support|helpdesk|security\s+team|system\s+administrator|office\s+of\s+the\s+ceo)\b', re.I),
            re.compile(r'\b(microsoft\s+365|google\s+workspace|bank\s+of\s+america|paypal\s+support)\b', re.I),
        ]
    ),
}


def extract_phishing_intents(text: str) -> Tuple[List[IntentSignal], float]:
    """
    Scans normalized email text and subject for phishing intents.
    Returns list of matched IntentSignals and aggregated heuristic intent score (0.0 - 1.0).
    """
    if not text:
        return [], 0.0

    matched_signals: List[IntentSignal] = []
    max_weight = 0.0
    accumulated_weight = 0.0

    for intent_name, (weight, desc, patterns) in INTENT_PATTERNS.items():
        found_phrases = []
        for pat in patterns:
            for m in pat.finditer(text):
                found_phrases.append(m.group(0))

        if found_phrases:
            dedup_phrases = sorted(list(set(found_phrases)))
            matched_signals.append(
                IntentSignal(
                    signal_type=intent_name,
                    weight=weight,
                    matched_phrases=dedup_phrases[:5],
                    description=desc,
                )
            )
            accumulated_weight += weight * 0.4
            if weight > max_weight:
                max_weight = weight

    # Aggregate intent score
    intent_score = min(1.0, max_weight * 0.7 + min(0.3, accumulated_weight * 0.3))
    return matched_signals, round(intent_score, 4)
