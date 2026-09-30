# TRINETRA — CERT-In Threat Intelligence Advisory Integration

TRINETRA integrates **CERT-In (Indian Computer Emergency Response Team)** cybersecurity advisories as specialized threat intelligence context.

---

## Advisory Intelligence Model

CERT-In publishes official threat advisories covering emerging phishing techniques, ransomware campaigns, domain lookalikes targeting financial institutions, and malicious infrastructure.

### Data Schema (`ThreatIndicator` table)

```json
{
  "indicator_type": "DOMAIN",
  "indicator_value": "sbi-kyc-update.com",
  "source": "CERT-In",
  "advisory_id": "CIAD-2026-0042",
  "severity": "CRITICAL",
  "confidence": 0.95,
  "description": "CERT-In Advisory: Phishing campaign impersonating State Bank of India targeting credential theft."
}
```

---

## Ingestion & Threat Intel Pipeline

1. **Pre-Loaded Local DB Indicators**: Standard CERT-In advisory IOCs are seeded into the local database upon initialization (`app/services/seed_service.py`).
2. **Normalized Indicator Interface**: All threat indicators are normalized to the `NormalizedIndicator` schema before consumption by the Central Risk Engine.
3. **Advisory Attribution**: When an email matches a CERT-In IOC, TRINETRA tags the detection with high confidence and displays the CERT-In advisory ID and description directly in the XAI explanation panel.
