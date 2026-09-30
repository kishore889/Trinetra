# TRINETRA — Gmail OAuth 2.0 Integration Setup Guide

Follow these steps to connect a live Google/Gmail account to TRINETRA.

---

## 1. Google Cloud Console Setup

1. Open [Google Cloud Console Credentials](https://console.cloud.google.com/apis/credentials).
2. Create a new GCP Project named `TRINETRA-SOC`.
3. Enable the **Gmail API** in Google Cloud API Library.
4. Configure the **OAuth Consent Screen**:
   - User Type: External or Internal (Enterprise workspace)
   - App Name: `TRINETRA SOC`
   - Scopes required:
     - `https://mail.google.com/` (Full Gmail access for quarantine/labels/trash)
     - `https://www.googleapis.com/auth/gmail.modify`
     - `https://www.googleapis.com/auth/userinfo.email`

---

## 2. Create OAuth 2.0 Client ID

1. Click **Create Credentials** -> **OAuth Client ID**.
2. Application Type: **Web application**.
3. Name: `TRINETRA Backend Client`.
4. Authorized Redirect URIs:
   - `http://localhost:8000/api/v1/auth/google/callback`
   - `https://your-domain.com/api/v1/auth/google/callback` (for production)
5. Download JSON credentials and copy the Client ID and Client Secret into `.env`:

```env
GOOGLE_CLIENT_ID="123456789-abc.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="GOCSPX-your_client_secret_here"
GOOGLE_REDIRECT_URI="http://localhost:8000/api/v1/auth/google/callback"
```

---

## 3. Connecting Gmail via TRINETRA UI

1. Open TRINETRA Frontend at `http://localhost:5173/gmail`.
2. Click **Connect Gmail Account**.
3. Grant permissions on Google's consent screen.
4. Upon callback, TRINETRA receives the OAuth authorization code, exchanges it for access & refresh tokens, encrypts them securely using AES, and begins real-time inbox monitoring.
