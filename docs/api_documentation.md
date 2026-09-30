# TRINETRA — REST API Reference

The TRINETRA API is exposed at `/api/v1`. Interactive OpenAPI documentation is accessible at `http://localhost:8000/docs` or `http://localhost:8000/redoc`.

---

## Authentication Endpoints (`/api/v1/auth`)

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/auth/login` | `POST` | Authenticates user with email/password; returns JWT access token. |
| `/api/v1/auth/token` | `POST` | OAuth2 password form compatibility login endpoint. |
| `/api/v1/auth/me` | `GET` | Returns authenticated user profile, role, and capabilities. |
| `/api/v1/auth/register` | `POST` | Admin-only endpoint to register system SOC users. |
| `/api/v1/auth/google/url` | `GET` | Generates Google OAuth 2.0 authorization link. |
| `/api/v1/auth/google/callback` | `GET` | Google OAuth redirect receiver; encrypts & stores tokens. |
| `/api/v1/auth/google/status` | `GET` | Returns public connection status without leaking secrets. |
| `/api/v1/auth/google/disconnect` | `POST` | Disconnects active Gmail account & purges tokens. |

---

## Core Detection & Risk Endpoints (`/api/v1`)

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/risk/evaluate` | `POST` | Evaluates email risk across all 5 sub-layers. |
| `/api/v1/risk/pipeline` | `POST` | Runs full 10-stage detection pipeline on arbitrary raw email JSON/MIME. |
| `/api/v1/analyze/content` | `POST` | Runs Content NLP + Phishing Intent analysis. |
| `/api/v1/analyze/url` | `POST` | Analyzes URL structure, homoglyphs, and brand typos. |
| `/api/v1/analyze/identity` | `POST` | Checks display name spoofing, domain age, SPF/DKIM/DMARC. |
| `/api/v1/threat-intel/lookup` | `POST` | Matches indicators against CERT-In, VT, and local DB. |
| `/api/v1/graph/entity` | `POST` | Builds graph entities and queries entity relationships. |
| `/api/v1/explain/explain` | `POST` | Generates natural language XAI explanation via Gemini/Fallback. |

---

## Operations & Demo Endpoints (`/api/v1`)

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/dashboard/metrics` | `GET` | Returns live SOC dashboard telemetry & risk distribution. |
| `/api/v1/actions/quarantine` | `POST` | Moves email to Gmail Trash/Quarantine and applies warning label. |
| `/api/v1/actions/release` | `POST` | Restores quarantined email to Gmail Inbox. |
| `/api/v1/review/queue` | `GET` | Lists medium-risk review queue items for analyst review. |
| `/api/v1/review/submit` | `POST` | Submits analyst feedback (`TRUE_POSITIVE`, `FALSE_POSITIVE`, etc.). |
| `/api/v1/review/export` | `GET` | Exports feedback dataset for future model improvements. |
| `/api/v1/demo/scenarios` | `GET` | Lists all 10 pre-loaded attack/defense demo scenarios. |
| `/api/v1/demo/run/{id}` | `POST` | Executes specified demo scenario through live pipeline. |
