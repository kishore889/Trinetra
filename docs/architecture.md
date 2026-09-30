# TRINETRA — System Architecture & Cloud Infrastructure

## Overview

TRINETRA is an enterprise-grade **AI-Powered Real-Time Phishing Detection & Threat Intelligence System**. It combines multi-layer intelligence (Content NLP, URL Structure, Domain Identity, Threat Intel Feeds, and Graph Entity Correlation) into a centralized, explainable Risk Engine that executes automated response actions on connected Gmail environments.

```
Incoming Email / Event
        │
        ▼
[ Ingestion & MIME Parser ] ──▶ Extract Headers, Text, HTML, URLs, Attachments
        │
        ├───────────────────────┬───────────────────────┬───────────────────────┐
        ▼                       ▼                       ▼                       ▼
[ Content Intelligence ] [ URL Intelligence ] [ Identity Engine ] [ Threat Intel Provider ]
(TF-IDF + ML + Intent)  (Lexical, Homoglyphs) (Typo/Brand Spoofing) (CERT-In, VT, SafeBrowse)
        │                       │                       │                       │
        └───────────────────────┴───────────┬───────────┴───────────────────────┘
                                            ▼
                               [ Graph Intelligence Engine ]
                               (NetworkX / Neo4j Entity Map)
                                            │
                                            ▼
                             [ Central Multi-Signal Risk Engine ]
                             (Weighted Score + Threshold Matrix)
                                            │
                                            ▼
                             [ Explainable AI Layer (XAI) ]
                             (Natural Language + Key Evidence)
                                            │
                                            ▼
                             [ Automated Response Engine ]
                             (Quarantine, Warning, Label, Audit)
                                            │
                                            ▼
                             [ Analyst HITL Review Queue ]
                             (TP/FP Feedback + Dataset Export)
```

---

## Production Cloud Deployment Architecture

TRINETRA is engineered for seamless cloud deployment on Google Cloud Platform (GCP):

```
User Web Browser / SOC Analyst
        │ (HTTPS)
        ▼
[ Firebase Hosting / Cloud Run Frontend ]
        │ (REST API / JSON)
        ▼
[ Google Cloud Run Backend (FastAPI + Gunicorn) ]
        │
        ├──▶ [ Cloud SQL PostgreSQL ] (Relational Storage, Detections, Audits)
        ├──▶ [ Vertex AI / Gemini API ] (Natural Language Explanations)
        └──▶ [ External Threat APIs ] (VirusTotal, Google Safe Browsing)

Real-Time Gmail Push Ingestion Path:
Gmail Mailbox ──▶ Gmail Watch ──▶ Cloud Pub/Sub ──▶ Cloud Run Webhook ──▶ TRINETRA Pipeline
```

### Components

1. **Frontend**: React 18, Vite, TypeScript, TailwindCSS (Hosted on Firebase Hosting or Cloud Run Container).
2. **Backend**: FastAPI running on Python 3.11 inside Google Cloud Run (serverless autoscaling container).
3. **Database**: Managed Cloud SQL PostgreSQL (version 16) with automated backups and connection pooling.
4. **Real-Time Push**: Gmail Watch triggers push events to Google Cloud Pub/Sub, delivering webhooks to Cloud Run for instantaneous zero-polling email ingestion.
