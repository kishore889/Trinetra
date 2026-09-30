"""
TRINETRA — Email & HTML Security Sanitizer

Prevents Cross-Site Scripting (XSS), script execution, and malicious payload rendering
when displaying or analyzing email bodies and attachments.
"""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List

# Dangerous HTML elements and event handlers forbidden in email body rendering
_FORBIDDEN_TAGS_RE = re.compile(
    r"<(script|iframe|object|embed|applet|form|base|meta|link|style)[^>]*?>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)

_SELF_CLOSING_FORBIDDEN_RE = re.compile(
    r"<(script|iframe|object|embed|applet|form|base|meta|link|style)[^>]*?/?>",
    re.IGNORECASE,
)

_EVENT_HANDLERS_RE = re.compile(
    r"\s*(on[a-z]+)\s*=\s*([\"'][^\"']*[\"']|[^\s>]+)",
    re.IGNORECASE,
)

_DANGEROUS_SCHEMES_RE = re.compile(
    r"(javascript|vbscript|data):",
    re.IGNORECASE,
)


def sanitize_html_body(raw_html: str) -> str:
    """
    Sanitize HTML email body content to eliminate XSS script execution threats.

    - Removes <script>, <iframe>, <object>, <embed>, <form> tags
    - Strips inline JS event handlers (onload, onerror, onclick, etc.)
    - Neutralises javascript: and data: URI schemes in links/images
    """
    if not raw_html:
        return ""

    # Remove script and object blocks
    clean = _FORBIDDEN_TAGS_RE.sub("", raw_html)
    clean = _SELF_CLOSING_FORBIDDEN_RE.sub("", clean)

    # Strip inline event handlers
    clean = _EVENT_HANDLERS_RE.sub("", clean)

    # Neutralize inline javascript: links
    clean = _DANGEROUS_SCHEMES_RE.sub("unsafe-scheme-blocked:", clean)

    return clean


def escape_plain_text(text: str) -> str:
    """Safely escape plain text content for web rendering."""
    if not text:
        return ""
    return html.escape(text)


def sanitize_attachment_metadata(attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sanitize attachment metadata records.
    Never executes attachment content; only extracts safe metadata (filename, mime, size).
    """
    sanitized = []
    for att in attachments:
        filename = html.escape(att.get("filename", "unnamed_attachment"))
        mime_type = html.escape(att.get("mime_type", "application/octet-stream"))
        size = att.get("size", 0)

        # Flag executable attachment extensions
        is_executable = any(
            filename.lower().endswith(ext)
            for ext in [".exe", ".bat", ".cmd", ".vbs", ".js", ".jar", ".ps1", ".scr", ".pif", ".dll"]
        )

        sanitized.append(
            {
                "filename": filename,
                "mime_type": mime_type,
                "size_bytes": size,
                "is_executable": is_executable,
                "hazard_warning": "EXECUTABLE_FILE_TYPE" if is_executable else "SAFE",
            }
        )
    return sanitized
