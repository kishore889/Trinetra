# TRINETRA — Local Setup Guide

Follow these steps to run TRINETRA locally in development mode.

---

## Prerequisites

- **Python 3.11+**
- **Node.js 20+** & `npm`
- **Git**
- **Docker & Docker Compose** (Optional, for running with PostgreSQL container)

---

## Option 1: Native Local Setup (Fastest for Development)

### 1. Backend Setup

```bash
cd backend
python -m venv venv

# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
source venv/bin/activate

pip install -r requirements.txt

# Run database migrations / seed initial data and launch API server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend server will run at `http://127.0.0.1:8000`.

### 2. Frontend Setup

In a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

The React + Vite frontend will launch at `http://localhost:5173`.

---

## Option 2: Docker Compose Setup

To launch the complete platform (PostgreSQL + FastAPI Backend + Nginx Frontend) with one command:

```bash
# Copy sample env
cp .env.example .env

# Build and start all containers
docker-compose up --build -d
```

- **Frontend**: `http://localhost:5173`
- **Backend API**: `http://localhost:8000`
- **PostgreSQL Database**: `localhost:5432`

---

## Running Verification Tests

To verify that all 247 backend tests pass cleanly:

```bash
cd backend
.\venv\Scripts\pytest -q
```
