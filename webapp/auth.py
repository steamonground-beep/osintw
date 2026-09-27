"""Authentication, CSRF, and rate limiting.

Session state lives in a signed, httpOnly cookie. The CSRF token is carried
inside that cookie, which is why cross-site script cannot read it: `httpOnly`
keeps it away from `document.cookie` and the signature keeps it unmodifiable.
The frontend reads it from `GET /api/session` and echoes it in a header, so
every state-changing request must be same-origin.
"""

from __future__ import annotations

import functools
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import current_app, g, jsonify, request

from .config import (
    COOKIE_NAME,
    LOGIN_LOCKOUT_SECONDS,
    LOGIN_MAX_ATTEMPTS,
    LOGIN_WINDOW_SECONDS,
    SEARCH_MAX_REQUESTS,
    SEARCH_WINDOW_SECONDS,
)


# ---------------------------------------------------------------------------
# signed session cookie
# ---------------------------------------------------------------------------


def _serializer():
    return current_app.session_interface.get_signing_serializer(current_app)


def issue_session() -> str:
    """Create the cookie value for a freshly authenticated user."""
    payload = {
        "sub": "operator",
        "csrf": secrets.token_urlsafe(32),
        "exp": int(time.time()) + current_app.config["SESSION_MAX_AGE"],
    }
    return _serializer().dumps(payload)


def read_session() -> dict | None:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return None
    try:
        data = _serializer().loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if int(data.get("exp", 0)) < int(time.time()):
        return None
    return data


def clear_session(response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


def set_session(response):
    secure = current_app.config["SESSION_COOKIE_SECURE"]
    response.set_cookie(
        COOKIE_NAME,
        issue_session(),
        max_age=current_app.config["SESSION_MAX_AGE"],
        httponly=True,
        secure=secure,
        samesite="Strict",
        path="/",
    )
    return response


# ---------------------------------------------------------------------------
# password check
# ---------------------------------------------------------------------------


def check_password(candidate: str) -> bool:
    expected = current_app.config["SITE_PASSWORD"]
    if not expected:
        return False
    # Constant-time, and always compares full length so a wrong-length input
    # does not fail faster than a right-length one.
    return hmac.compare_digest(
        str(candidate or "").encode("utf-8"), str(expected).encode("utf-8")
    )


# ---------------------------------------------------------------------------
# rate limiting
# ---------------------------------------------------------------------------


class SlidingWindowLimiter:
    """In-process sliding-window counter.

    Best-effort by design: Vercel routes each request to an arbitrary
    instance, so this bounds a single instance's abuse rather than the whole
    deployment. It is a speed bump, not a quota system.
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] > window:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = int(window - (now - bucket[0])) + 1
                return False, max(1, retry_after)
            bucket.append(now)
        return True, 0

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


def client_key() -> str:
    """Identify the caller. Trusts X-Forwarded-For only behind a proxy."""
    if current_app.config.get("TRUST_PROXY"):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def enforce(limit: int, window: int, bucket: str) -> None:
    limiter = current_app.config["LIMITER"]
    ok, retry_after = limiter.check(f"{bucket}:{client_key()}", limit, window)
    if not ok:
        response = jsonify(
            {"error": "rate_limited", "message": f"Too many requests. Retry in {retry_after}s."}
        )
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        raise RateLimited(response)


class RateLimited(Exception):
    def __init__(self, response):
        self.response = response


def login_guard(fn):
    """Throttle failed logins per source address."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            enforce(LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS, "login")
        except RateLimited as limited:
            raise limited
        return fn(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# guards
# ---------------------------------------------------------------------------


def require_auth(fn):
    """Reject unauthenticated or CSRF-less requests."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        session = read_session()
        if session is None:
            return jsonify({"error": "unauthorized", "message": "Sign in to continue."}), 401

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            supplied = request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf", "")
            if not expected or not hmac.compare_digest(
                str(supplied).encode(), str(expected).encode()
            ):
                return (
                    jsonify({"error": "csrf", "message": "Missing or invalid CSRF token."}),
                    403,
                )

        g.session = session
        g.search_id = request.headers.get("X-Search-Id") or None
        try:
            enforce(SEARCH_MAX_REQUESTS, SEARCH_WINDOW_SECONDS, "search")
        except RateLimited as limited:
            return limited.response
        return fn(*args, **kwargs)

    return wrapper


def current_csrf() -> str:
    session = g.get("session")
    return session.get("csrf", "") if session else ""
