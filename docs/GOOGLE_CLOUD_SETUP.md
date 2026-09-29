# TRINETRA — Google Cloud & Gmail OAuth 2.0 Setup Guide

This guide details the procedure for establishing Google Cloud credentials, OAuth 2.0 consent, and Gmail API integration for the **TRINETRA** AI-powered real-time phishing detection system.

---

## 1. Google Cloud Project Setup

1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Click **Select a project** > **New Project**.
3. Set **Project Name**: `TRINETRA-SOC` (or your preferred naming).
4. Note your **Project ID**.

---

## 2. Enable Required APIs

In your Google Cloud Project:
1. Navigate to **APIs & Services** > **Library**.
2. Search for and enable the following APIs:
   - **Gmail API** (Required for ingestion & watch notifications)
   - **Cloud Pub/Sub API** (Required for real-time webhook push delivery)

---

## 3. OAuth Consent Screen Configuration

1. Navigate to **APIs & Services** > **OAuth consent screen**.
2. Select **User Type**:
   - For internal domain testing / Google Workspace: **Internal**
   - For standard individual Gmail testing: **External**
3. Fill in mandatory app information:
   - **App name**: `TRINETRA`
   - **User support email**: Your administrator email
   - **Developer contact information**: Your administrator email
4. **Scopes**: Add the following minimum least-privilege scopes:
   - `openid`
   - `https://www.googleapis.com/auth/userinfo.email`
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/gmail.modify`
5. **Test Users**:
   - If using **External** user type during development, add the test Gmail accounts under **Test Users** that will authorize TRINETRA.

> **Verification Notice**: Unverified apps in development mode will display an "unverified app" consent screen when authenticating test accounts. This is normal during local development.

---

## 4. OAuth 2.0 Client Credentials

1. Navigate to **APIs & Services** > **Credentials**.
2. Click **Create Credentials** > **OAuth client ID**.
3. Select **Application type**: `Web application`.
4. Name: `TRINETRA Backend Client`.
5. Under **Authorized redirect URIs**, add:
   - `http://localhost:8000/api/v1/auth/google/callback`
6. Click **Create** and safely copy:
   - **Client ID**
   - **Client Secret**

---

## 5. Local Environment Configuration

Copy these values into your `TRINETRA/.env` file:

```env
# Google OAuth 2.0 Credentials
GOOGLE_CLIENT_ID=your_client_id_here.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret_here
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/auth/google/callback

# Google Cloud Pub/Sub (For Phase 4 Push Ingestion)
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_PUBSUB_TOPIC=projects/your-project-id/topics/trinetra-gmail-watch
```

---

## 6. Verification and Security Architecture

- **Token Protection**: Access and Refresh tokens are symmetrically encrypted at rest using AES-256 (`cryptography.fernet`) before being stored in PostgreSQL.
- **Data Minimization**: Secret keys and raw tokens are stripped from all public `/status` responses.
- **Recovery**: Automatic token refresh is performed whenever the stored `access_token` is expired or near expiration.
