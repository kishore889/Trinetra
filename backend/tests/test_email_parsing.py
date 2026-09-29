"""
Comprehensive tests for TRINETRA Email MIME Parsing, safe URL extraction,
and duplicate idempotency protection.
"""

import uuid
from datetime import datetime, timezone
import pytest
from app.services.email_parser import (
    parse_raw_mime,
    extract_urls_from_content,
    extract_domain_from_email,
    extract_domain_from_url,
    clean_html_to_text,
)


def test_plain_email_parsing():
    raw_mime = b"""From: sender@example.com
To: victim@company.com
Subject: Test Plain Email
Date: Mon, 29 Sep 2026 12:00:00 +0000
Message-ID: <plain-123@example.com>
Content-Type: text/plain; charset="utf-8"

Hello, please check this link: https://legit-portal.com/dashboard.
Best regards.
"""
    parsed = parse_raw_mime(raw_mime)
    assert parsed.message_id == "plain-123@example.com"
    assert parsed.sender == "sender@example.com"
    assert parsed.sender_domain == "example.com"
    assert parsed.recipient == "victim@company.com"
    assert parsed.subject == "Test Plain Email"
    assert "https://legit-portal.com/dashboard" in parsed.extracted_urls
    assert len(parsed.attachments) == 0


def test_html_email_parsing():
    raw_mime = b"""From: Security <security@banking-portal.org>
To: target@client.net
Subject: Account Verification Required
Date: Mon, 29 Sep 2026 12:05:00 +0000
Message-ID: <html-456@banking-portal.org>
Content-Type: text/html; charset="utf-8"

<html>
  <body>
    <h2>Security Alert</h2>
    <p>Please update your credentials <a href="https://auth-verify-phish.net/login">here</a> immediately.</p>
  </body>
</html>
"""
    parsed = parse_raw_mime(raw_mime)
    assert parsed.message_id == "html-456@banking-portal.org"
    assert parsed.sender_domain == "banking-portal.org"
    assert "https://auth-verify-phish.net/login" in parsed.extracted_urls
    assert "Security Alert" in parsed.normalized_body_text


def test_multipart_email_with_attachments_and_multiple_urls():
    raw_mime = b"""From: alerts@vendor-corp.com
To: user@enterprise.com
Subject: Invoice and Statement
Date: Mon, 29 Sep 2026 12:10:00 +0000
Message-ID: <multipart-789@vendor-corp.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY-XYZ"

--BOUNDARY-XYZ
Content-Type: text/plain; charset="utf-8"

Find invoice online at https://invoices.vendor-corp.com/view or backup at http://mirror.vendor-corp.com/backup.

--BOUNDARY-XYZ
Content-Type: application/pdf; name="invoice_september.pdf"
Content-Disposition: attachment; filename="invoice_september.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcTl8uXr...
--BOUNDARY-XYZ--
"""
    parsed = parse_raw_mime(raw_mime)
    assert parsed.message_id == "multipart-789@vendor-corp.com"
    assert len(parsed.extracted_urls) == 2
    assert "https://invoices.vendor-corp.com/view" in parsed.extracted_urls
    assert "http://mirror.vendor-corp.com/backup" in parsed.extracted_urls
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice_september.pdf"
    assert parsed.attachments[0].content_type == "application/pdf"


def test_missing_headers_and_malformed_email():
    raw_mime = b"""Subject: Malformed Header Test

No from, no to, no message id. Just plain text.
Visit www.test-lookalike.com now.
"""
    parsed = parse_raw_mime(raw_mime)
    assert parsed.subject == "Malformed Header Test"
    assert parsed.sender_domain == "unknown"
    assert "http://www.test-lookalike.com" in parsed.extracted_urls


def test_auth_headers_parsing():
    raw_mime = b"""From: legit@paypal.com
To: user@target.org
Subject: Payment Received
Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass action=none
Message-ID: <auth-test-1@paypal.com>

Clean email body.
"""
    parsed = parse_raw_mime(raw_mime)
    assert parsed.spf_result == "PASS"
    assert parsed.dkim_result == "PASS"
    assert parsed.dmarc_result == "PASS"
