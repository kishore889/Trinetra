"""
TRINETRA — Secure Email MIME & URL Parser

Extracts headers, body representations (plain text & sanitized HTML text),
extracts and normalizes URLs without visiting them (safe static analysis),
and extracts attachment metadata strictly without downloading or executing files.
"""

from __future__ import annotations

import base64
import email
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr, parsedate_to_datetime
import html
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel

# Regex to safely match URLs in plain text and HTML attributes without executing/visiting
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'`()\[\]{}]+',
    re.IGNORECASE
)

# HTML tags stripper
HTML_TAG_CLEANER = re.compile(r'<[^>]+>')


class AttachmentMetadata(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    content_id: Optional[str] = None


class ParsedEmailData(BaseModel):
    message_id: str
    thread_id: Optional[str] = None
    sender: str
    sender_name: Optional[str] = None
    sender_domain: str
    recipient: str
    recipient_name: Optional[str] = None
    cc: List[str] = []
    bcc: List[str] = []
    subject: str
    received_at: datetime
    plain_text: str
    html_content: Optional[str] = None
    normalized_body_text: str
    extracted_urls: List[str] = []
    attachments: List[AttachmentMetadata] = []
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    headers_dict: Dict[str, str] = {}


def extract_domain_from_email(email_str: str) -> str:
    """Extract domain from an email address (e.g., 'user@example.com' -> 'example.com')."""
    _, addr = parseaddr(email_str)
    if "@" in addr:
        return addr.split("@")[-1].lower().strip()
    return "unknown"


def extract_domain_from_url(url: str) -> str:
    """Extract registered/host domain from a URL safely."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urllib.parse.urlparse(url)
        return (parsed.hostname or "").lower().strip()
    except Exception:
        return ""


def clean_html_to_text(html_str: str) -> str:
    """Convert HTML string to clean readable plain text."""
    if not html_str:
        return ""
    # Strip script and style tags
    clean = re.sub(r'<(script|style)[^>]*>[\s\S]*?</\1>', ' ', html_str, flags=re.IGNORECASE)
    # Strip remaining HTML tags
    clean = HTML_TAG_CLEANER.sub(' ', clean)
    # Unescape HTML entities
    clean = html.unescape(clean)
    # Collapse multiple whitespaces
    return ' '.join(clean.split()).strip()


def extract_urls_from_content(text: str, html_str: Optional[str] = None) -> List[str]:
    """
    Extract and deduplicate all URLs from plain text and HTML href/src attributes.
    Zero network requests are performed.
    """
    found_urls = set()

    # Search plain text
    if text:
        matches = URL_REGEX.findall(text)
        for m in matches:
            found_urls.add(m.rstrip('.,;:!?"\')>'))

    # Search HTML attributes
    if html_str:
        href_matches = re.findall(r'(?:href|src)=["\']([^"\']+)["\']', html_str, re.IGNORECASE)
        for h in href_matches:
            if h.startswith(('http://', 'https://', 'www.')):
                found_urls.add(h.rstrip('.,;:!?"\')>'))

        # Also search raw HTML text for bare URLs
        matches = URL_REGEX.findall(html_str)
        for m in matches:
            found_urls.add(m.rstrip('.,;:!?"\')>'))

    # Normalize URLs
    normalized_list = []
    for u in found_urls:
        if u.startswith('www.'):
            u = 'http://' + u
        normalized_list.append(u)

    return sorted(list(set(normalized_list)))


def parse_auth_headers(headers: Dict[str, str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract SPF, DKIM, and DMARC verdicts from Authentication-Results or Received-SPF."""
    auth_results = headers.get("authentication-results", "").lower()
    received_spf = headers.get("received-spf", "").lower()

    spf = None
    dkim = None
    dmarc = None

    if "spf=pass" in auth_results or "pass" in received_spf:
        spf = "PASS"
    elif "spf=fail" in auth_results or "fail" in received_spf:
        spf = "FAIL"
    elif "spf=softfail" in auth_results or "softfail" in received_spf:
        spf = "SOFTFAIL"
    elif "spf=neutral" in auth_results:
        spf = "NEUTRAL"

    if "dkim=pass" in auth_results:
        dkim = "PASS"
    elif "dkim=fail" in auth_results:
        dkim = "FAIL"
    elif "dkim=none" in auth_results:
        dkim = "NONE"

    if "dmarc=pass" in auth_results:
        dmarc = "PASS"
    elif "dmarc=fail" in auth_results or "action=quarantine" in auth_results or "action=reject" in auth_results:
        dmarc = "FAIL"

    return spf, dkim, dmarc


def parse_raw_mime(raw_bytes: bytes, fallback_message_id: str = "") -> ParsedEmailData:
    """
    Parses raw RFC 822 / MIME bytes into structured ParsedEmailData.
    Handles multipart/mixed, multipart/alternative, and deeply nested attachments.
    """
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    headers_dict = {k.lower(): str(v) for k, v in msg.items()}

    # Extract Message-ID
    message_id = msg.get("Message-ID", "").strip("<> ") or fallback_message_id or f"msg-{datetime.now().timestamp()}"

    # Senders & Recipients
    from_header = msg.get("From", "")
    sender_name, sender = parseaddr(from_header)
    sender = sender.lower()
    sender_domain = extract_domain_from_email(sender)

    to_header = msg.get("To", "")
    recipient_name, recipient = parseaddr(to_header)
    recipient = recipient.lower()

    cc_list = [addr.lower() for _, addr in email.utils.getaddresses(msg.get_all("Cc", []))]
    bcc_list = [addr.lower() for _, addr in email.utils.getaddresses(msg.get_all("Bcc", []))]

    subject = str(msg.get("Subject", "(No Subject)"))

    # Received timestamp
    date_header = msg.get("Date")
    received_at = datetime.now(timezone.utc)
    if date_header:
        try:
            parsed_dt = parsedate_to_datetime(date_header)
            if parsed_dt.tzinfo is None:
                received_at = parsed_dt.replace(tzinfo=timezone.utc)
            else:
                received_at = parsed_dt.astimezone(timezone.utc)
        except Exception:
            pass

    # Extract parts
    plain_parts = []
    html_parts = []
    attachments = []

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", "")).lower()
        content_type = part.get_content_type().lower()

        is_attachment = "attachment" in content_disposition or bool(part.get_filename())

        if is_attachment:
            filename = part.get_filename() or "unnamed_attachment"
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                AttachmentMetadata(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=len(payload),
                    content_id=part.get("Content-ID"),
                )
            )
        else:
            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        plain_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass

    plain_text = "\n\n".join(plain_parts)
    html_content = "\n\n".join(html_parts) if html_parts else None

    # Derive normalized readable text
    if plain_text.strip():
        normalized_body = plain_text.strip()
    elif html_content:
        normalized_body = clean_html_to_text(html_content)
    else:
        normalized_body = ""

    # Safe URL extraction
    extracted_urls = extract_urls_from_content(plain_text, html_content)

    # Auth header parsing
    spf, dkim, dmarc = parse_auth_headers(headers_dict)

    return ParsedEmailData(
        message_id=message_id,
        thread_id=headers_dict.get("thread-id"),
        sender=sender,
        sender_name=sender_name,
        sender_domain=sender_domain,
        recipient=recipient,
        recipient_name=recipient_name,
        cc=cc_list,
        bcc=bcc_list,
        subject=subject,
        received_at=received_at,
        plain_text=plain_text,
        html_content=html_content,
        normalized_body_text=normalized_body,
        extracted_urls=extracted_urls,
        attachments=attachments,
        spf_result=spf,
        dkim_result=dkim,
        dmarc_result=dmarc,
        headers_dict=headers_dict,
    )


def parse_gmail_api_message(gmail_json: Dict[str, Any]) -> ParsedEmailData:
    """
    Parses a Gmail REST API full message resource (`users.messages.get` with format='RAW' or 'FULL').
    If 'raw' is present in gmail_json, delegates to `parse_raw_mime`.
    Otherwise parses standard payload structure.
    """
    raw_encoded = gmail_json.get("raw")
    if raw_encoded:
        # Standard Gmail raw is URL-safe base64 encoded
        raw_bytes = base64.urlsafe_b64decode(raw_encoded.encode("ASCII"))
        return parse_raw_mime(raw_bytes, fallback_message_id=gmail_json.get("id", ""))

    # Fallback to payload extraction if format was FULL
    payload = gmail_json.get("payload", {})
    headers_list = payload.get("headers", [])
    headers_dict = {h.get("name", "").lower(): h.get("value", "") for h in headers_list}

    message_id = headers_dict.get("message-id", "").strip("<> ") or gmail_json.get("id", "")
    from_header = headers_dict.get("from", "")
    sender_name, sender = parseaddr(from_header)
    sender = sender.lower()
    sender_domain = extract_domain_from_email(sender)

    to_header = headers_dict.get("to", "")
    recipient_name, recipient = parseaddr(to_header)
    recipient = recipient.lower()

    subject = headers_dict.get("subject", "(No Subject)")
    thread_id = gmail_json.get("threadId")

    # Internal date in ms
    internal_date = gmail_json.get("internalDate")
    if internal_date:
        received_at = datetime.fromtimestamp(int(internal_date) / 1000.0, tz=timezone.utc)
    else:
        received_at = datetime.now(timezone.utc)

    # Recursive body extraction from parts
    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[AttachmentMetadata] = []

    def walk_parts(part: Dict[str, Any]):
        mime_type = part.get("mimeType", "").lower()
        filename = part.get("filename", "")
        body = part.get("body", {})

        if filename:
            attachments.append(
                AttachmentMetadata(
                    filename=filename,
                    content_type=mime_type,
                    size_bytes=body.get("size", 0),
                    content_id=part.get("partId"),
                )
            )
        else:
            data = body.get("data")
            if data:
                try:
                    decoded = base64.urlsafe_b64decode(data.encode("ASCII")).decode("utf-8", errors="replace")
                    if mime_type == "text/plain":
                        plain_parts.append(decoded)
                    elif mime_type == "text/html":
                        html_parts.append(decoded)
                except Exception:
                    pass

        for subpart in part.get("parts", []):
            walk_parts(subpart)

    walk_parts(payload)

    plain_text = "\n\n".join(plain_parts)
    html_content = "\n\n".join(html_parts) if html_parts else None

    normalized_body = plain_text.strip() if plain_text.strip() else clean_html_to_text(html_content or "")
    extracted_urls = extract_urls_from_content(plain_text, html_content)
    spf, dkim, dmarc = parse_auth_headers(headers_dict)

    return ParsedEmailData(
        message_id=message_id,
        thread_id=thread_id,
        sender=sender,
        sender_name=sender_name,
        sender_domain=sender_domain,
        recipient=recipient,
        recipient_name=recipient_name,
        subject=subject,
        received_at=received_at,
        plain_text=plain_text,
        html_content=html_content,
        normalized_body_text=normalized_body,
        extracted_urls=extracted_urls,
        attachments=attachments,
        spf_result=spf,
        dkim_result=dkim,
        dmarc_result=dmarc,
        headers_dict=headers_dict,
    )
