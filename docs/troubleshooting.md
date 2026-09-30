# TRINETRA — Operational Troubleshooting Guide

---

## Common Issues & Resolutions

### 1. Database Connection Failures
- **Symptom**: `OperationalError: could not connect to server`
- **Cause**: PostgreSQL container is not running or credentials in `.env` are mismatched.
- **Fix**: Check `docker-compose ps` or verify `DATABASE_URL` in `.env`. For local testing without Postgres, TRINETRA automatically falls back to SQLite `sqlite:///./trinetra.db`.

### 2. Rate Limiting 429 Errors
- **Symptom**: `429 Too Many Requests`
- **Cause**: Client IP exceeded `RATE_LIMIT_PER_MINUTE` (default 60 requests/minute).
- **Fix**: Wait 60 seconds or increase `RATE_LIMIT_PER_MINUTE` in `.env`.

### 3. Google OAuth Redirect Errors
- **Symptom**: `redirect_uri_mismatch` on Google Consent screen.
- **Cause**: Authorized Redirect URI in Google Cloud Console does not match `GOOGLE_REDIRECT_URI`.
- **Fix**: Add `http://localhost:8000/api/v1/auth/google/callback` to Google Cloud Console.

### 4. Threat Intelligence External API Timeouts
- **Symptom**: Warning logs for VirusTotal or Safe Browsing lookups.
- **Cause**: Network timeout or invalid API keys.
- **Fix**: TRINETRA handles provider timeouts gracefully and degraded features continue functioning via local CERT-In / heuristics.
