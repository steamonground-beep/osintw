"""Application factory."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from .auth import RateLimited, SlidingWindowLimiter
from .config import ConfigError, load_settings
from .oathnet_client import OathNet, UpstreamError
from .redact import redact

__all__ = ["create_app"]

PUBLIC_DIR = Path(__file__).resolve().parent.parent / "public"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
}


def _configure_logging() -> None:
    """Log to stdout, and never let credentials reach the log stream."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # urllib3 logs full request lines at DEBUG, which can include query strings.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def create_app(settings=None) -> Flask:
    _configure_logging()
    settings = settings or load_settings()

    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=settings.secret_key,
        SITE_PASSWORD=settings.site_password,
        SESSION_MAX_AGE=settings.session_max_age,
        SESSION_COOKIE_SECURE=settings.secure_cookies,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        ALLOW_REVEAL=settings.allow_reveal,
        ALLOW_REGISTRATION=settings.allow_registration,
        PUBLIC_MODE=settings.public_mode,
        # Vercel terminates TLS and sets these; trust them for client IPs only.
        TRUST_PROXY=bool(settings.is_production),
        LIMITER=SlidingWindowLimiter(),
        OATHNET_CLIENT=OathNet(settings.oathnet_api_key, settings.oathnet_base_url),
        MAX_CONTENT_LENGTH=256 * 1024,
    )
    app.json.sort_keys = False

    from .routes import api

    app.register_blueprint(api)

    if settings.public_mode:
        app.logger.warning(
            "PUBLIC_MODE is on: this site requires no password and every "
            "visitor can run searches against the configured OathNet key."
        )

    @app.after_request
    def _security_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        # The UI is same-origin only; no CORS headers are emitted anywhere.
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/")
    def index():
        return send_from_directory(PUBLIC_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_files(filename: str):
        if filename.startswith("api/") or filename == "api":
            return jsonify({"error": "not_found", "message": "No such endpoint."}), 404
        target = (PUBLIC_DIR / filename).resolve()
        if not str(target).startswith(str(PUBLIC_DIR.resolve())):
            return jsonify({"error": "not_found"}), 404
        if not target.is_file():
            return send_from_directory(PUBLIC_DIR, "index.html")
        return send_from_directory(PUBLIC_DIR, filename)

    @app.errorhandler(RateLimited)
    def _rate_limited(exc: RateLimited):
        return exc.response

    @app.errorhandler(UpstreamError)
    def _upstream(exc: UpstreamError):
        return jsonify({"error": exc.kind, "message": str(exc)}), exc.status

    @app.errorhandler(404)
    def _not_found(_exc):
        if request.path.startswith("/api/"):
            return jsonify({"error": "not_found", "message": "No such endpoint."}), 404
        return send_from_directory(PUBLIC_DIR, "index.html")

    @app.errorhandler(405)
    def _method_not_allowed(_exc):
        return jsonify({"error": "method_not_allowed", "message": "Wrong HTTP method."}), 405

    @app.errorhandler(413)
    def _too_large(_exc):
        return jsonify({"error": "too_large", "message": "Request body is too large."}), 413

    @app.errorhandler(500)
    def _server_error(_exc):
        # Never echo internals; they can carry query values.
        app.logger.exception("unhandled error on %s %s", request.method, request.path)
        return jsonify({"error": "server_error", "message": "Internal error."}), 500

    @app.errorhandler(ConfigError)
    def _config_error(exc: ConfigError):
        return jsonify({"error": "misconfigured", "message": redact(str(exc))}), 500

    return app
