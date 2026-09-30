# TRINETRA — Deployment Guide (Docker & Google Cloud)

---

## 1. Local / On-Premise Docker Compose Deployment

### Build & Launch Stack

```bash
cp .env.example .env
docker-compose up --build -d
```

### Accessing Services

- **TRINETRA Web UI**: `http://localhost:5173`
- **FastAPI API & OpenAPI Docs**: `http://localhost:8000/docs`
- **PostgreSQL Database**: `localhost:5432`

---

## 2. Production Google Cloud Platform (GCP) Deployment

### Step A: Deploy PostgreSQL on Cloud SQL

```bash
gcloud sql instances create trinetra-db \
    --database-version=POSTGRES_16 \
    --tier=db-custom-2-7680 \
    --region=us-central1

gcloud sql databases create trinetra --instance=trinetra-db
gcloud sql users create trinetra --instance=trinetra-db --password=STRONG_PASSWORD
```

### Step B: Build & Deploy Backend Container on Cloud Run

```bash
# Build image with Cloud Build
gcloud builds submit --tag gcr.io/$PROJECT_ID/trinetra-backend ./backend

# Deploy to Cloud Run
gcloud run deploy trinetra-backend \
    --image gcr.io/$PROJECT_ID/trinetra-backend \
    --platform managed \
    --region us-central1 \
    --allow-unauthenticated \
    --set-env-vars DATABASE_URL="postgresql://trinetra:STRONG_PASSWORD@/trinetra?host=/cloudsql/$PROJECT_ID:us-central1:trinetra-db" \
    --set-env-vars APP_ENV="production" \
    --set-env-vars DEBUG="false"
```

### Step C: Deploy Frontend to Firebase Hosting / Cloud Run

```bash
cd frontend
npm run build
firebase deploy --only hosting
```
