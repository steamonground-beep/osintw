"""Environment configuration.

Refuses to start a publicly-reachable instance without the secrets that make
it safe. A missing SITE_PASSWORD would otherwise expose an unauthenticated
proxy to stolen-credential data.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

DEFAULT_BASE_URL = "https://oathnet.org/api"
COOKIE_NAME = "osint_session"

# Login throttling, per client address.
LOGIN_MAX_ATTEMPTS = 8
LOGIN_WINDOW_SECONDS = 900
LOGIN_LOCKOUT_SECONDS = 900

# Search throttling, per client address.
SEARCH_MAX_REQUESTS = 120
SEARCH_WINDOW_SECONDS = 60

# Hard ceiling on records returned to the browser in one response.
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 25


class ConfigError(RuntimeError):
    pass


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    oathnet_api_key: str
    oathnet_base_url: str
    site_password: str
    secret_key: str
    is_production: bool
    allow_reveal: bool
    allow_registration: bool = False
    session_max_age: int = 8 * 3600
    # When true, no password is required: every visitor is an operator. Opt-in
    # via PUBLIC_MODE=1 so that forgetting SITE_PASSWORD cannot silently open
    # the site to the internet.
    public_mode: bool = False

    @property
    def secure_cookies(self) -> bool:
        return self.is_production


def load_settings() -> Settings:
    is_production = _flag("VERCEL") or _flag("NODE_ENV", False) and os.environ.get("NODE_ENV") == "production"
    is_production = is_production or _flag("PRODUCTION")

    api_key = os.environ.get("OATHNET_API_KEY", "").strip()
    password = os.environ.get("SITE_PASSWORD", "").strip()
    secret = os.environ.get("SECRET_KEY", "").strip()
    public_mode = _flag("PUBLIC_MODE", False)

    if is_production:
        # A password is only mandatory when the site is not explicitly public.
        required = [("OATHNET_API_KEY", api_key), ("SECRET_KEY", secret)]
        if not public_mode:
            required.append(("SITE_PASSWORD", password))
        missing = [name for name, value in required if not value]
        if missing:
            raise ConfigError(
                "Refusing to start in production without: " + ", ".join(missing) + "\n"
                "Set these as Vercel environment variables. To run without a "
                "password, set PUBLIC_MODE=1 and SITE_PASSWORD is not required."
            )
        if not public_mode and len(password) < 12:
            raise ConfigError("SITE_PASSWORD must be at least 12 characters.")
        if len(secret) < 32:
            raise ConfigError("SECRET_KEY must be at least 32 characters.")

    if not secret:
        # Ephemeral in local dev: sessions reset on restart, which is fine.
        secret = secrets.token_hex(32)

    return Settings(
        oathnet_api_key=api_key,
        oathnet_base_url=os.environ.get("OATHNET_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
        site_password=password,
        secret_key=secret,
        is_production=is_production,
        # Revealing plaintext credentials is opt-in even for authenticated users.
        allow_reveal=_flag("ALLOW_REVEAL", False),
        allow_registration=_flag("ALLOW_REGISTRATION", False),
        public_mode=public_mode,
    )
