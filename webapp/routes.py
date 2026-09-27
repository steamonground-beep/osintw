"""HTTP API.

Every data route requires an authenticated session and a CSRF token. Sensitive
values are redacted here, before serialisation, unless the caller is both
authenticated and explicitly permitted to reveal.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from flask import Blueprint, current_app, jsonify, request

from .auth import check_password, clear_session, login_guard, read_session, require_auth, set_session
from .config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from .oathnet_client import OathNet
from .redact import count_masked, redact, strip_bulk_sensitive

api = Blueprint("api", __name__, url_prefix="/api")

# Indicator shapes the UI can auto-detect. Kept in step with the CLI.
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](-*[a-z0-9])*\.)+[a-z]{2,}$", re.I)

# Lookup name -> (endpoint, query-parameter, human label)
LOOKUPS: dict[str, tuple[str, str, str]] = {
    "discord": ("/service/discord-userinfo", "discord_id", "Discord profile"),
    "discord-history": ("/service/discord-username-history", "discord_id", "Discord username history"),
    "steam": ("/service/steam", "steam_id", "Steam profile"),
    "xbox": ("/service/xbox", "xbl_id", "Xbox Live profile"),
    "minecraft": ("/service/mc-history", "username", "Minecraft username history"),
    "ip": ("/service/ip-info", "ip", "IP geolocation and network"),
    "ghunt": ("/service/ghunt", "email", "Google account info"),
    "holehe": ("/service/holehe", "email", "Email account existence"),
    "roblox": ("/service/roblox-userinfo", None, "Roblox profile"),
    "subdomains": ("/service/extract-subdomain", "domain", "Subdomains"),
    "phonebook": ("/service/v2/phonebook", "domain", "Phonebook domain intelligence"),
}

# Fields a caller may repeat. Anything else in the filter list is ignored, so
# the proxy cannot be steered into unexpected query parameters.
BREACH_FILTERS = {
    "dbname", "email", "username", "domain", "ip", "country", "phone",
    "first_name", "last_name", "full_name", "city", "state", "discord_id",
    "iban", "ssn", "gender", "password", "password_hash",
}
STEALER_FILTERS = {
    "domain", "subdomain", "email", "email_domain", "username", "ip",
    "discord_id", "hwid", "source_type", "password", "path", "log_id",
    "country", "city", "os", "service", "phone", "steam_id", "antivirus",
}
VICTIM_FILTERS = {
    "email", "email_domain", "username", "discord_id", "ip", "victim_ip",
    "hwid", "os", "country", "city", "domain", "subdomain", "service", "log_id",
}

MAX_QUERY_LENGTH = 320
MAX_FILTER_VALUES = 25


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def client() -> OathNet:
    return current_app.config["OATHNET_CLIENT"]


def _body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _query(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("A query value is required.")
    if len(text) > MAX_QUERY_LENGTH:
        raise ValueError(f"Query is too long (max {MAX_QUERY_LENGTH} characters).")
    return text


def _page_size(raw: Any) -> int:
    try:
        size = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_PAGE_SIZE
    return max(1, min(size, MAX_PAGE_SIZE))


def _filters(payload: Mapping, allowed: set[str]) -> dict:
    """Copy only whitelisted, well-formed filters into query params."""
    collected: dict[str, list[str]] = {}
    filters = payload.get("filters")
    if not isinstance(filters, Mapping):
        return {}
    for name, values in filters.items():
        if name not in allowed:
            continue
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, (list, tuple)):
            continue
        cleaned = [str(v).strip() for v in values if str(v).strip()][:MAX_FILTER_VALUES]
        if cleaned:
            collected[f"{name}[]"] = cleaned
    return collected


def _reveal_requested() -> bool:
    return bool(request.headers.get("X-Reveal") == "confirm") and current_app.config["ALLOW_REVEAL"]


def detect_indicator(value: str) -> str:
    if EMAIL.match(value):
        return "email"
    if IPV4.match(value):
        return "ip"
    if re.fullmatch(r"\d{17,20}", value):
        return "discord"
    if DOMAIN.match(value):
        return "domain"
    return "unknown"


def _rows(payload: Any) -> list[dict]:
    if isinstance(payload, Mapping):
        for key in ("items", "results", "files", "subdomains", "domains"):
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, Mapping)]
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, Mapping)]
    return []


def _envelope(data: Any, reveal: bool, **extra) -> dict:
    """Package a page of records for the browser.

    `detail` keeps the upstream page object (minus secrets) so the UI can read
    pagination state without a second request.
    """
    meta = data.get("meta") if isinstance(data, Mapping) else None
    rows = [strip_bulk_sensitive(row, reveal=reveal) for row in _rows(data)]
    return {
        "ok": True,
        "revealed": reveal,
        "masked_count": 0 if reveal else count_masked(rows),
        "rows": rows,
        "meta": redact(meta, reveal=reveal) if isinstance(meta, Mapping) else {},
        "detail": redact(data, reveal=reveal),
        **extra,
    }


# ---------------------------------------------------------------------------
# auth routes
# ---------------------------------------------------------------------------


@api.get("/session")
def session_state():
    session = read_session()
    if session is None:
        return jsonify({"authenticated": False, "csrf": None})
    return jsonify(
        {
            "authenticated": True,
            "csrf": session.get("csrf"),
            "allow_reveal": current_app.config["ALLOW_REVEAL"],
        }
    )


@api.post("/login")
@login_guard
def login():
    password = _body().get("password", "")
    if not check_password(password):
        return jsonify({"error": "invalid_credentials", "message": "Incorrect password."}), 401
    response = jsonify({"ok": True})
    return set_session(response)


@api.post("/logout")
def logout():
    return clear_session(jsonify({"ok": True}))


# ---------------------------------------------------------------------------
# status routes
# ---------------------------------------------------------------------------


@api.get("/health")
@require_auth
def health():
    return jsonify({"ok": True, "oathnet": client().health()})


@api.get("/quota")
@require_auth
def quota():
    return jsonify({"ok": True, "quota": client().quota.as_dict()})


@api.get("/detect")
@require_auth
def detect():
    try:
        value = _query(request.args.get("q"))
    except ValueError as exc:
        return jsonify({"error": "invalid", "message": str(exc)}), 400
    kind = detect_indicator(value)
    suggestions = {
        "email": ["holehe", "ghunt", "breach", "stealer"],
        "ip": ["ip", "breach", "stealer"],
        "discord": ["discord", "discord-history", "breach", "stealer"],
        "domain": ["subdomains", "phonebook", "breach", "stealer"],
        "unknown": ["breach", "stealer"],
    }[kind]
    return jsonify({"ok": True, "kind": kind, "suggested": suggestions})


# ---------------------------------------------------------------------------
# search routes
# ---------------------------------------------------------------------------


@api.post("/breach")
@require_auth
def breach_search():
    payload = _body()
    try:
        query = _query(payload.get("query"))
    except ValueError as exc:
        return jsonify({"error": "invalid", "message": str(exc)}), 400

    params: dict[str, Any] = {"q": query, "page_size": _page_size(payload.get("page_size"))}
    if payload.get("wildcard"):
        params["wildcard"] = "true"
    params.update(_filters(payload, BREACH_FILTERS))
    if payload.get("cursor"):
        params["cursor"] = str(payload["cursor"])[:200]

    data = client().get("/service/v2/breach/search", params)
    reveal = _reveal_requested()
    return jsonify(_envelope(data, reveal, query=query))


@api.post("/stealer")
@require_auth
def stealer_search():
    payload = _body()
    try:
        query = _query(payload.get("query"))
    except ValueError as exc:
        return jsonify({"error": "invalid", "message": str(exc)}), 400

    params: dict[str, Any] = {"q": query, "page_size": _page_size(payload.get("page_size"))}
    if payload.get("wildcard"):
        params["wildcard"] = "true"
    if payload.get("log_id"):
        params["log_id"] = str(payload["log_id"])[:120]
    params.update(_filters(payload, STEALER_FILTERS))
    if payload.get("cursor"):
        params["cursor"] = str(payload["cursor"])[:200]

    data = client().get("/service/v2/stealer/search", params)
    reveal = _reveal_requested()
    return jsonify(_envelope(data, reveal, query=query))


@api.post("/victims")
@require_auth
def victim_search():
    payload = _body()
    params: dict[str, Any] = {"page_size": _page_size(payload.get("page_size"))}
    if payload.get("query"):
        try:
            params["q"] = _query(payload["query"])
        except ValueError as exc:
            return jsonify({"error": "invalid", "message": str(exc)}), 400
    for name in ("log_id", "total_docs_min", "service_count_min"):
        if payload.get(name) is not None:
            params[name] = str(payload[name])[:60]
    params.update(_filters(payload, VICTIM_FILTERS))

    data = client().get("/service/v2/victims/search", params)
    reveal = _reveal_requested()
    return jsonify(_envelope(data, reveal))


# ---------------------------------------------------------------------------
# enrichment routes
# ---------------------------------------------------------------------------


@api.post("/lookup")
@require_auth
def lookup():
    payload = _body()
    name = str(payload.get("lookup", "")).strip()
    if name not in LOOKUPS:
        return jsonify(
            {"error": "invalid", "message": f"Unknown lookup '{name}'.", "available": sorted(LOOKUPS)}
        ), 400
    try:
        value = _query(payload.get("value"))
    except ValueError as exc:
        return jsonify({"error": "invalid", "message": str(exc)}), 400

    endpoint, param, label = LOOKUPS[name]
    params: dict[str, Any] = {}
    if param:
        params[param] = value
    elif name == "roblox":
        params["user_id" if value.isdigit() else "username"] = value
    if payload.get("alive"):
        params["is_alive"] = "true"

    data = client().get(endpoint, params)
    reveal = _reveal_requested()
    return jsonify({"ok": True, "lookup": name, "label": label, "revealed": reveal,
                    "data": redact(data, reveal=reveal)})


@api.get("/lookups")
@require_auth
def list_lookups():
    return jsonify(
        {
            "ok": True,
            "lookups": [
                {"name": name, "label": label, "param": param}
                for name, (param, _endpoint, label) in sorted(LOOKUPS.items())
            ],
        }
    )
