# TRINETRA
### AI-Powered Real-Time Phishing Detection & Threat Intelligence System

---

## Overview

**TRINETRA** is an enterprise-grade, modular phishing detection and threat intelligence platform. It uses multi-layer AI analysis across seven independent intelligence layers to identify, classify, and respond to email-based threats in real time.

Unlike a single-model classifier, TRINETRA employs a **multi-signal risk engine** that combines content intelligence, URL/domain analysis, identity spoofing detection, threat intelligence, and graph-based relationship analysis to produce explainable, auditable decisions.

---

## Architecture

```
Gmail
  ↓  Gmail API / OAuth 2.0
  ↓  Real-Time Email Ingestion
  ↓  Email Parser
  ↓  Content Intelligence          ← Layer 1
  ↓  URL / Domain Intelligence     ← Layer 2
  ↓  Sender / Identity Intelligence← Layer 3
  ↓  Threat Intelligence           ← Layer 4
  ↓  Graph Intelligence            ← Layer 5
  ↓  Multi-Signal Risk Engine      ← Layer 6
  ↓  Explainable AI                ← Layer 7
  ↓  Decision Engine
  ↓  ALLOW / WARN / QUARANTINE
  ↓  TRINETRA SOC Dashboard
  ↓  Human-in-the-Loop
  ↓  Incident Report / Audit
```

---

## Detection Layers

| # | Layer | Description |
|---|-------|-------------|
| 1 | Content Intelligence | TF-IDF + ML phishing content classification |
| 2 | URL / Domain Intelligence | URL extraction, domain reputation, lookalike detection |
| 3 | Identity / Spoofing Intelligence | SPF/DKIM/DMARC, sender spoofing, brand impersonation |
| 4 | Threat Intelligence | Local TI DB + optional VirusTotal, Google Safe Browsing |
| 5 | Graph Intelligence | Relationship mapping via NetworkX (Neo4j-compatible) |
| 6 | Central Risk Engine | Configurable weighted multi-signal risk computation |
| 7 | Explainability | Evidence-backed natural language explanations |

---

## Technology Stack

### Backend
| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| API Framework | FastAPI |
| Validation | Pydantic v2 |
| ORM | SQLAlchemy 2.0 |
| Database | PostgreSQL 16 |
| Migrations | Alembic |
| Logging | structlog |

### Frontend
| Component | Technology |
|-----------|-----------|
| Framework | React 18 + TypeScript |
| Build Tool | Vite |
| Styling | Tailwind CSS |
| Components | shadcn/ui |
| Routing | React Router |
| Charts | Recharts |
| Graph Viz | React Flow |
| Icons | Lucide Icons |

### ML & Intelligence
| Component | Technology |
|-----------|-----------|
| Baseline Classifier | TF-IDF + Logistic Regression |
| Semantic Layer | sentence-transformers (optional) |
| Explanations | Gemini API (assist only, not classifier) |
| Graph Engine | NetworkX → Neo4j compatible |

### Google Integrations
| Component | Role |
|-----------|------|
| Gmail API | Email access |
| Google OAuth 2.0 | Authentication |
| Gmail Watch | Real-time push triggers |
| Google Cloud Pub/Sub | Event delivery |
| Gmail History API | Delta sync |

---

## Email Lifecycle States

```
RECEIVED → PARSING → ANALYZING → ANALYZED → ACTION_PENDING → ACTIONED
                                                                    ↓
                                                                 FAILED
```

## Decision Outputs

| Severity | Decision |
|----------|----------|
| LOW / MEDIUM / HIGH / CRITICAL | ALLOW / WARN / QUARANTINE |

> Emails are **never permanently deleted** automatically.

---

## Project Structure

```
TRINETRA/
├── backend/                # FastAPI backend application
│   ├── app/
│   │   ├── api/            # API route definitions
│   │   ├── core/           # Config, logging, security, exceptions
│   │   ├── db/             # Database base + session management
│   │   ├── models/         # SQLAlchemy ORM models
│   │   ├── schemas/        # Pydantic request/response schemas
│   │   ├── services/       # Business logic services
│   │   ├── engines/        # Intelligence engine interfaces
│   │   ├── providers/      # Threat intelligence provider interfaces
│   │   └── graph/          # Graph engine interfaces
│   ├── alembic/            # Database migrations
│   └── tests/              # Backend tests
├── frontend/               # React + TypeScript frontend (Phase 3+)
├── data/                   # Local threat intelligence data
├── models/                 # Trained ML model artifacts
├── scripts/                # Utility scripts
├── docs/                   # Architecture and phase documentation
├── tests/                  # Integration tests
└── docker/                 # Docker configuration
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 16
- Docker & Docker Compose (recommended)

### Setup (Docker)

```bash
# 1. Copy environment configuration
cp .env.example .env
# Edit .env with your configuration

# 2. Start services
docker-compose up -d

# 3. Run database migrations
docker-compose exec backend alembic upgrade head

# 4. Verify health
curl http://localhost:8000/api/v1/health
```

### Setup (Local Development)

```bash
# 1. Set up Python environment
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate        # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp ../.env.example .env
# Edit .env

# 4. Run migrations
alembic upgrade head

# 5. Start development server
uvicorn app.main:app --reload --port 8000
```

### Running Tests

```bash
cd backend
pytest tests/ -v --cov=app --cov-report=term-missing
```

---

## API Documentation

Once running, visit:
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **Health Check:** http://localhost:8000/api/v1/health

---

## Security

TRINETRA implements:
- OAuth 2.0 for Gmail authentication (secrets never stored in plaintext)
- SSRF protection for URL analysis
- Input validation on all endpoints
- SQL injection prevention via ORM
- Rate limiting
- Secure headers
- Audit logging

---

## Phase Roadmap

| Phase | Title | Status |
|-------|-------|--------|
| 1 | Architecture Lock + Backend Foundation | ✅ Complete |
| 2 | Gmail Integration + Email Ingestion | 🔜 Planned |
| 3 | Frontend Foundation (SOC Dashboard) | 🔜 Planned |
| 4 | Content Intelligence Layer | 🔜 Planned |
| 5 | URL / Domain Intelligence Layer | 🔜 Planned |
| 6 | Identity / Spoofing Intelligence | 🔜 Planned |
| 7 | Threat Intelligence Layer | 🔜 Planned |
| 8 | Graph Intelligence Layer | 🔜 Planned |
| 9 | Multi-Signal Risk Engine | 🔜 Planned |
| 10 | Explainable AI Layer | 🔜 Planned |
| 11 | Decision Engine | 🔜 Planned |
| 12 | Human-in-the-Loop | 🔜 Planned |
| 13 | Incident Management | 🔜 Planned |
| 14 | SOC Dashboard (Advanced) | 🔜 Planned |
| 15 | Demo Center | 🔜 Planned |
| 16 | Production Hardening | 🔜 Planned |
| 17 | Performance & Scale | 🔜 Planned |
| 18 | Final Integration & Audit | 🔜 Planned |

---

## License

TRINETRA — Proprietary. All rights reserved.
