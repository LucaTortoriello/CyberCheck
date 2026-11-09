"""Minimize target-controlled data retained in reports, history and logs."""

from urllib.parse import urlsplit, urlunsplit

import httpx

from cybercheck.core.config import LimitReached
from cybercheck.core.validation import UnsafeTarget

EVIDENCE_HEADERS = frozenset(
    {
        "content-type",
        "strict-transport-security",
        "content-security-policy",
        "content-security-policy-report-only",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-frame-options",
        "location",
    }
)


def redact_url(value: str) -> str:
    """Remove credentials, query values and fragments; retain the observed path.

    Paths can themselves be confidential: exported reports still need care.
    Invalid/unbounded URLs are not copied into diagnostics.
    """
    if len(value) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return "[redacted invalid URL]"
    try:
        parts = urlsplit(value)
        hostname = parts.hostname or ""
        if ":" in hostname:
            hostname = f"[{hostname}]"
        if parts.port:
            hostname += f":{parts.port}"
        return urlunsplit((parts.scheme, hostname, parts.path, "redacted" if parts.query else "", ""))
    except ValueError:
        return "[redacted invalid URL]"


def safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name.lower(): redact_url(value) if name.lower() == "location" else value
        for name, value in headers.items()
        if name.lower() in EVIDENCE_HEADERS
    }


def network_error(exc: Exception) -> dict[str, str]:
    """Keep useful error classification without arbitrary exception messages."""
    reason = (
        "public_target_policy"
        if isinstance(exc, UnsafeTarget)
        else "request_or_time_limit"
        if isinstance(exc, LimitReached)
        else "network_timeout"
        if isinstance(exc, (httpx.TimeoutException, TimeoutError))
        else "network_or_verification_failure"
    )
    return {"error_type": type(exc).__name__, "reason": reason}
