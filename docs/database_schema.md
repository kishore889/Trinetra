# TRINETRA — Database Schema Reference

TRINETRA uses **SQLAlchemy 2.0 ORM** with cross-database support (SQLite for local rapid testing, PostgreSQL 16 for production).

---

## Entity-Relationship Summary

```
        ┌───────────┐
        │   User    │ ◄─── Analyst & Admin Accounts
        └─────┬─────┘
              │ (1:N)
        ┌─────▼─────┐
        │GmailAccount│ ◄─── Monitored Mailboxes & Encrypted OAuth Tokens
        └─────┬─────┘
              │ (1:N)
        ┌─────▼─────┐             ┌─────────────┐
        │   Email   │ ──────────► │  EmailUrl   │ (1:N Extracted Links)
        └─────┬─────┘             └──────┬──────┘
              │                          │ (N:1)
              │ (1:1)             ┌──────▼──────┐
              │                   │   Domain    │ (Domain Reputation Registry)
        ┌─────▼─────┐             └─────────────┘
        │ Detection │ ◄─── Risk Scores & Decision Output
        └─────┬─────┘
              │ (1:1)
        ┌─────▼─────┐
        │ Feedback  │ ◄─── HITL Analyst Classification (TP/FP/TN/FN)
        └───────────┘
```

---

## Key Tables

### 1. `users`
- `id` (UUID, Primary Key)
- `email` (String 255, Unique, Indexed)
- `hashed_password` (String 255)
- `full_name` (String 255)
- `role` (String 50: `admin`, `analyst`, `viewer`)
- `is_active` (Boolean)

### 2. `gmail_accounts`
- `id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key `users.id`)
- `email_address` (String 255, Unique, Indexed)
- `history_id` (String 100)
- `token_info` (JSONB / Encrypted Tokens)

### 3. `emails`
- `id` (UUID, Primary Key)
- `gmail_account_id` (UUID, Foreign Key `gmail_accounts.id`)
- `message_id` (String 255, Unique, Indexed)
- `sender` (String 255, Indexed)
- `sender_domain` (String 255, Indexed)
- `recipient` (String 255, Indexed)
- `subject` (Text)
- `state` (Enum: `RECEIVED`, `PARSED`, `ANALYZED`, `QUARANTINED`, `SAFE`, `REVIEW`)

### 4. `detections`
- `id` (UUID, Primary Key)
- `email_id` (UUID, Foreign Key `emails.id`, Unique)
- `content_risk` (Float: 0.0–1.0)
- `url_risk` (Float: 0.0–1.0)
- `identity_risk` (Float: 0.0–1.0)
- `threat_intel_risk` (Float: 0.0–1.0)
- `graph_risk` (Float: 0.0–1.0)
- `final_risk_score` (Float: 0.0–1.0, Indexed)
- `severity` (Enum: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `decision` (Enum: `ALLOW`, `WARN`, `QUARANTINE`)
- `confidence` (Float: 0.0–1.0)

### 5. `feedbacks`
- `id` (UUID, Primary Key)
- `detection_id` (UUID, Foreign Key `detections.id`, Unique)
- `analyst_id` (UUID, Foreign Key `users.id`)
- `classification` (Enum: `TRUE_POSITIVE`, `FALSE_POSITIVE`, `TRUE_NEGATIVE`, `FALSE_NEGATIVE`)
- `comments` (Text)
- `reviewed_at` (DateTime)

### 6. `action_audits`
- `id` (UUID, Primary Key)
- `message_id` (String 255, Indexed)
- `action` (String 100: `QUARANTINE_MOVE`, `APPLY_WARNING_BANNER`, `ANALYST_RELEASE`)
- `actor` (String 255)
- `reason` (Text)
- `details` (JSONB)
