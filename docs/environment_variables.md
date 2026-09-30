# TRINETRA — Environment Variable Catalog

TRINETRA uses **Pydantic Settings** for type-safe environment configuration loaded from `.env` or system environment variables.

---

## Variable Reference

| Variable | Description | Default | Required? |
| :--- | :--- | :--- | :---: |
| `APP_ENV` | Application environment (`development`, `production`, `testing`) | `development` | Yes |
| `DEBUG` | Enable debug mode / detailed error traces | `true` | Yes |
| `SECRET_KEY` | 32-byte secret key used for signing JWT tokens | Auto-generated | Yes (Prod) |
| `DATABASE_URL` | SQLAlchemy connection string | `postgresql://...` | Yes |
| `GOOGLE_CLIENT_ID` | OAuth 2.0 Client ID from Google Cloud Console | `""` | Optional |
| `GOOGLE_CLIENT_SECRET` | OAuth 2.0 Client Secret from Google Cloud Console | `""` | Optional |
| `GOOGLE_REDIRECT_URI` | OAuth redirect URI callback URL | `http://localhost:8000/api/v1/auth/google/callback` | Yes |
| `GOOGLE_CLOUD_PROJECT` | GCP Project ID for Pub/Sub integration | `""` | Optional |
| `GOOGLE_PUBSUB_TOPIC` | Pub/Sub Topic string | `""` | Optional |
| `GEMINI_API_KEY` | Google Gemini API Key for NL Explainability | `""` | Optional |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API Key for URL/domain lookups | `""` | Optional |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing v4 API Key | `""` | Optional |
| `RISK_WEIGHT_CONTENT` | Weight assigned to Content NLP Layer (0.0 - 1.0) | `0.25` | Yes |
| `RISK_WEIGHT_URL` | Weight assigned to URL Intelligence Layer (0.0 - 1.0) | `0.30` | Yes |
| `RISK_WEIGHT_IDENTITY` | Weight assigned to Identity Layer (0.0 - 1.0) | `0.20` | Yes |
| `RISK_WEIGHT_THREAT_INTEL` | Weight assigned to Threat Intel Layer (0.0 - 1.0) | `0.15` | Yes |
| `RISK_WEIGHT_GRAPH` | Weight assigned to Graph Intelligence Layer (0.0 - 1.0) | `0.10` | Yes |
| `RISK_THRESHOLD_WARN` | Risk score threshold to trigger WARN verdict | `0.40` | Yes |
| `RISK_THRESHOLD_QUARANTINE` | Risk score threshold to trigger QUARANTINE verdict | `0.70` | Yes |
| `RATE_LIMIT_PER_MINUTE` | Maximum API requests allowed per client IP per minute | `60` | Yes |
