# TRINETRA — Security Architecture & Production Controls

## Overview

TRINETRA enforces strict, multi-layered security controls to protect the platform, data integrity, and connected email environments.

---

## Security Domains & Controls

1. **Authentication & JWT**: Signed JWT access tokens with Passlib PBKDF2-SHA256 password hashing.
2. **Authorization (RBAC)**: Role-Based Access Control (`admin`, `analyst`, `viewer`).
3. **SSRF Protection**: `validate_url_for_fetch()` blocks `127.0.0.1`, `localhost`, AWS metadata `169.254.169.254`, private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and non-HTTP schemes (`file://`, `data:`).
4. **XSS & Content Rendering**: `sanitize_html_body()` strips `<script>`, `<iframe>`, `<object>`, `<form>`, and inline JS handlers from email body previews.
5. **Rate Limiting**: Sliding-window rate limiting per IP/token (`settings.RATE_LIMIT_PER_MINUTE`).
6. **OWASP Security Headers**: Sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1`, `Strict-Transport-Security`, `Referrer-Policy`, and `Content-Security-Policy`.
7. **OAuth Secrecy**: Access/refresh tokens are encrypted at rest with AES and never returned to the frontend or written to log files.
8. **Sensitive Field Redaction**: Structured audit logger automatically redacts `password`, `token`, `secret`, `api_key`, and `cookie` parameters.
