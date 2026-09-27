"""Server-side redaction.

Redaction happens before data leaves the process. The browser is not trusted
to hide a password it has already been sent, so masked is the default state and
unmasking is a separate, explicitly-authorised code path.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

REDACTED = "***REDACTED***"

# Matched case-insensitively against the key, so `smtp_password`,
# `Set-Cookie`, and `x-api-key` all trip.
SENSITIVE_MARKERS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "cookie",
    "session_id",
    "authorization",
    "apikey",
    "api_key",
    "credential",
    "private_key",
    "iban",
    "ssn",
    "card_number",
    "cardnumber",
    "cvv",
    "otp",
    "pin",
    "seed",
    "mnemonic",
    "2fa",
    "otpauth",
)

# Names that look sensitive but carry no secret material.
ALWAYS_SHOW = frozenset(
    {
        "password_hash",
        "canonical_credential_id",
        "archive_hash",
        "hwid",
        "auth_type",
        "identity_state",
        "seed_type",
    }
)

# Raw stealer log lines embed "url:username:password" in a single string.
_LOG_LINE = re.compile(r"(?P<head>[^\n]*?)(?::(?P<user>[^:\n]*))(?::(?P<pw>[^:\n]+))(?P<tail>\n|$)")


# Separators that key names use interchangeably. `x-api-key`, `X API Key`, and
# `api_key` must all normalise to the same shape before marker matching, or a
# hyphenated header name slips past the check.
_SEPARATORS = re.compile(r"[^a-z0-9]+")


def is_sensitive(key: str) -> bool:
    lowered = _SEPARATORS.sub("_", str(key).lower()).strip("_")
    if lowered in ALWAYS_SHOW:
        return False
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def _mask_string(value: str) -> str:
    """Partially mask a secret so it stays recognisable but not usable."""
    if len(value) <= 4:
        return REDACTED
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def redact(value: Any, *, reveal: bool = False, _key: str | None = None) -> Any:
    """Recursively mask sensitive values while preserving structure."""
    if reveal:
        return value
    if isinstance(value, Mapping):
        return {k: redact(v, reveal=reveal, _key=k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, reveal=reveal, _key=_key) for v in value]
    if isinstance(value, str) and _key is not None and is_sensitive(_key) and value:
        return _mask_string(value)
    if _key is not None and is_sensitive(_key) and value not in (None, "", [], {}):
        return REDACTED
    return value


def scrub_raw_log(text: str, *, reveal: bool = False) -> str:
    """Mask the trailing secret in `LOG` lines of the form url:user:pass."""
    if reveal:
        return text
    return _LOG_LINE.sub(lambda m: f"{m['head']}:{m['user']}:{REDACTED}{m['tail']}", text)


def strip_bulk_sensitive(record: Mapping, *, reveal: bool = False) -> dict:
    """Redact one record and drop fields the UI never needs."""
    cleaned = redact(dict(record), reveal=reveal)
    if not reveal:
        for droppable in ("_version_", "id", "record_id"):
            cleaned.pop(droppable, None)
    return cleaned


def count_masked(payload: Any) -> int:
    """How many redactions were applied, so the UI can disclose it."""
    if isinstance(payload, Mapping):
        return sum(
            (1 if v == REDACTED or (isinstance(v, str) and "*" in v and len(v) > 4) else 0)
            + count_masked(v)
            for k, v in payload.items()
            if is_sensitive(k) or isinstance(v, (Mapping, list, tuple))
        )
    if isinstance(payload, list):
        return sum(count_masked(v) for v in payload)
    return 0
