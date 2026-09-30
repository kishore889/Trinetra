# TRINETRA — Human-in-the-Loop (HITL) Analyst Review Queue

TRINETRA empowers SOC security analysts to review medium-confidence detections (`WARN` verdict), inspect detailed signals, and record feedback to improve security posture over time.

---

## Review Queue Workflow

1. **Review Inspection**: Analysts review suspicious emails in the HITL Queue (`http://localhost:5173/investigations`).
2. **Evidence Inspection**: Analysts inspect headers, SPF/DKIM/DMARC status, extracted URLs, threat intel matches, and NetworkX entity graphs.
3. **Analyst Classification**: Analysts record one of four standard security classifications:
   - `TRUE_POSITIVE` (Correctly flagged phishing email)
   - `FALSE_POSITIVE` (Legitimate email mistakenly flagged)
   - `TRUE_NEGATIVE` (Clean email correctly allowed)
   - `FALSE_NEGATIVE` (Phishing email missed by auto-detection)
4. **Audit Logging**: Reviews store analyst ID, display name, timestamp, comments, and review source.
5. **Dataset Export**: Standardized JSON/CSV exports are available via `/api/v1/review/export` for future offline model tuning.
