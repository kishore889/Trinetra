# TRINETRA — AI-Powered Real-Time Phishing Detection & Threat Intelligence System

> **Identity:** TRINETRA Dark Teal SOC  
> **Backend Status:** ✅ 247 / 247 PASSING TESTS  
> **Frontend Status:** ✅ REACT 18 + VITE BUILD CLEAN  
> **Security Posture:** ✅ HARDENED (JWT, RBAC, OWASP Headers, SSRF, XSS, Rate Limiting)  

---

## Overview

**TRINETRA** is a production-grade, enterprise cybersecurity SOC platform engineered to detect, explain, and autonomously mitigate email phishing attacks in real time.

By fusing **5 sub-layers of security intelligence** into a central weighted Risk Engine, TRINETRA provides transparent Explainable AI (XAI) attributions and executes automated Gmail response actions (Quarantine, Trash, Warning Banners, Label Tagging) while empowering analysts through a Human-in-the-Loop (HITL) review workflow.

---

## Architecture Overview

```
Incoming Email ──▶ Ingestion & MIME Parser
                         │
        ┌────────────────┼────────────────┬────────────────┐
        ▼                ▼                ▼                ▼
  [ Content NLP ]  [ URL Intelligence ] [ Identity Engine ] [ Threat Intel ]
  (TF-IDF + ML)   (Homoglyphs, Typos)  (Domain/SPF/DKIM)  (CERT-In, VT, SB)
        │                │                │                │
        └────────────────┴────────┬───────┴────────────────┘
                                  ▼
                    [ Graph Entity Correlation ]
                    (NetworkX / Neo4j Entity Map)
                                  │
                                  ▼
                   [ Central Multi-Signal Risk Engine ]
                   (Weighted Scores + Decision Matrix)
                                  │
                                  ▼
                   [ Explainable AI Layer (XAI) ]
                   (Natural Language + Key Evidence)
                                  │
                                  ▼
                   [ Automated Gmail Response Actions ]
                   (Quarantine, Warning, Label, Audit)
```

---

## Technical Stack

- **Frontend**: React 18, Vite, TypeScript, Lucide Icons, TailwindCSS (Dark Teal SOC aesthetic).
- **Backend**: FastAPI, Python 3.11, Pydantic v2, Passlib (PBKDF2-SHA256), PyJWT.
- **Database**: PostgreSQL 16 / SQLite via SQLAlchemy 2.0 ORM.
- **Machine Learning & NLP**: Scikit-Learn (TF-IDF vectorizer + Classifier), Regex Heuristic Intent Analyzers.
- **Graph Intelligence**: NetworkX / Neo4j entity graph correlation.
- **Threat Intelligence**: CERT-In Advisories, VirusTotal v3, Google Safe Browsing v4, Local IOC DB.
- **Containerization**: Docker, Docker Compose, Nginx.

---

## Quick Start (Local Development)

### 1. Backend

```bash
cd backend
python -m venv venv
# PowerShell (Windows):
.\venv\Scripts\Activate.ps1
# Bash (Linux/macOS):
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Visit `http://localhost:5173` for the TRINETRA SOC Dashboard.

---

## Quick Start (Docker Compose)

```bash
cp .env.example .env
docker-compose up --build -d
```

- **TRINETRA UI**: `http://localhost:5173`
- **FastAPI API & OpenAPI Docs**: `http://localhost:8000/docs`

---

## Local Development & Clean Startup Commands

### 1. Backend (FastAPI + Uvicorn)
```bash
# Terminal 1: Navigate to backend and activate virtualenv
cd backend
.\venv\Scripts\Activate.ps1    # On Windows PowerShell
# or: source venv/bin/activate  # On Linux/macOS

# Start Uvicorn Server
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- Root Service Identity: `http://localhost:8000/`
- Health Endpoint: `http://localhost:8000/health`
- Interactive Swagger UI: `http://localhost:8000/docs`
- OpenAPI Specification: `http://localhost:8000/api/v1/openapi.json`

### 2. Frontend (React + Vite)
```bash
# Terminal 2: Navigate to frontend
cd frontend
npm install
npm run dev
```
- Web Application Console: `http://localhost:5173/`
- Reverse Proxy: Requests to `/api/...` and `/docs` automatically proxy to `http://127.0.0.1:8000`.

---

## Environment Variables & Configuration

Configuration is managed via `.env` (loaded automatically from project root or `backend/`).

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `APP_ENV` | Application environment (`development` / `production`) | `development` |
| `DEBUG` | Enable debug logs and telemetry | `true` |
| `SECRET_KEY` | Hex encryption key for internal session tokens | Pre-generated 64-char hex string |
| `DATABASE_URL` | Primary database URI (PostgreSQL or SQLite fallback) | `sqlite:///./trinetra_dev.db` |
| `GOOGLE_CLIENT_ID` | Google Cloud OAuth 2.0 Web Client ID | Configured via GCP Console |
| `GOOGLE_CLIENT_SECRET` | Google Cloud OAuth 2.0 Client Secret | Configured via GCP Console |
| `GOOGLE_REDIRECT_URI` | Authorized OAuth Redirect URI | `http://localhost:8000/api/v1/auth/google/callback` |
| `GOOGLE_CLOUD_PROJECT` | GCP Project ID for Gmail Watch Pub/Sub | `trinetra-soc` |
| `GOOGLE_PUBSUB_TOPIC` | Pub/Sub topic for push notifications | `projects/trinetra-soc/topics/gmail-events` |
| `GEMINI_API_KEY` | Google Gemini API key for Natural Language XAI | Optional (fallback to deterministic synthesis) |
| `VIRUSTOTAL_API_KEY` | VirusTotal API v3 key | Optional |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API v4 key | Optional |

---

## Detailed Documentation (`/docs`)

1. [System Architecture](docs/architecture.md)
2. [Database Schema](docs/database_schema.md)
3. [REST API Reference](docs/api_documentation.md)
4. [Local Setup Guide](docs/local_setup.md)
5. [Environment Variables](docs/environment_variables.md)
6. [Gmail OAuth 2.0 Setup](docs/gmail_oauth_setup.md)
7. [Gmail Watch & Cloud Pub/Sub](docs/pubsub_setup.md)
8. [CERT-In Threat Intelligence](docs/cert_in_setup.md)
9. [Machine Learning & NLP](docs/ml_training.md)
10. [Graph Intelligence Architecture](docs/graph_architecture.md)
11. [Central Risk Engine](docs/risk_engine.md)
12. [Human-in-the-Loop Review Queue](docs/human_in_loop.md)
13. [Security & Production Controls](docs/security.md)
14. [Deployment Guide (Docker & Cloud Run)](docs/deployment.md)
15. [Troubleshooting Guide](docs/troubleshooting.md)
