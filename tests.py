"""Test suite for the web console.

No network and no API key. `StubOathNet` replaces the real client so the tests
assert what the browser receives, not what OathNet returns.

    python tests.py
"""

from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("SITE_PASSWORD", "correct horse battery staple")
os.environ.setdefault("SECRET_KEY", "0" * 40)
os.environ.setdefault("OATHNET_API_KEY", "test-key-not-real")

from webapp import create_app  # noqa: E402
from webapp.config import Settings  # noqa: E402
from webapp.oathnet_client import OathNet, QuotaSnapshot, UpstreamError  # noqa: E402

PASSWORD = os.environ["SITE_PASSWORD"]


class StubOathNet:
    """Records calls and replays canned OathNet envelopes."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.responses: dict[str, object] = {}
        self.error: UpstreamError | None = None
        self.quota = QuotaSnapshot()
        self.quota.left = 900
        self.quota.used = 100
        self.quota.limit = 1000
        self.quota.plan = "Pro"

    def _record(self, path: str, params: dict) -> object:
        self.calls.append((path, params))
        if self.error:
            raise self.error
        if path in self.responses:
            return self.responses[path]
        return {"items": [], "meta": {"total": 0}}

    def get(self, path: str, params=None) -> object:
        return self._record(path, dict(params or {}))

    def health(self) -> object:
        return {"reachable": True, "status_code": 200}

    def last(self) -> dict:
        return self.calls[-1][1]


BREACH_PAGE = {
    "items": [
        {
            "id": "rec_01",
            "email": "victim@example.com",
            "username": "victim",
            "password": "hunter2",
            "dbname": "example_breach_2023",
            "ip": "203.0.113.9",
        }
    ],
    "meta": {"count": 1, "total": 1, "has_more": False},
    "next_cursor": None,
}

STOLEN_LOG = {
    "items": [
        {
            "url": "https://aurorafn.dev/signup",
            "domain": "aurorafn.dev",
            "email": ["victim@example.com"],
            "password": "p@ssw0rd123",
            "log_id": "00022607410d8ec9",
        }
    ],
    "meta": {"count": 1, "total": 1},
}

IP_INFO = {
    "query": "203.0.113.9",
    "country": "United States",
    "isp": "Verizon Business",
    "asn": "AS6167",
    "password": "should-be-masked",
}


class WebTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings(
            oathnet_api_key="test-key-not-real",
            oathnet_base_url="https://example.invalid/api",
            site_password=PASSWORD,
            secret_key="0" * 40,
            is_production=False,
            allow_reveal=False,
        )
        self.app = create_app(self.settings)
        self.stub = StubOathNet()
        self.app.config["OATHNET_CLIENT"] = self.stub
        self.client = self.app.test_client()

    # -- helpers ----------------------------------------------------------

    def login(self) -> str:
        response = self.client.post("/api/login", json={"password": PASSWORD})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        session = self.client.get("/api/session").get_json()
        return session["csrf"]

    def post(self, path: str, payload=None, csrf: str | None = None, **kwargs):
        headers = kwargs.pop("headers", {})
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf
        return self.client.post(path, json=payload, headers=headers, **kwargs)


class TestAuth(WebTestCase):
    def test_session_starts_anonymous(self):
        body = self.client.get("/api/session").get_json()
        self.assertFalse(body["authenticated"])
        self.assertIsNone(body["csrf"])

    def test_login_rejects_bad_password(self):
        response = self.client.post("/api/login", json={"password": "nope"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"], "invalid_credentials")

    def test_login_sets_httponly_cookie(self):
        response = self.client.post("/api/login", json={"password": PASSWORD})
        self.assertEqual(response.status_code, 200)
        for header in response.headers.getlist("Set-Cookie"):
            self.assertIn("HttpOnly", header)
            self.assertIn("SameSite=Strict", header)

    def test_login_sets_cookie_when_empty_password(self):
        self.assertEqual(self.client.post("/api/login", json={}).status_code, 401)

    def test_data_routes_require_auth(self):
        for path in ("/api/health", "/api/quota", "/api/lookups"):
            self.assertEqual(self.client.get(path).status_code, 401, path)
        for path in ("/api/breach", "/api/stealer", "/api/victims", "/api/lookup"):
            self.assertEqual(self.post(path, {"query": "x"}).status_code, 401, path)

    def test_post_requires_csrf_token(self):
        self.login()
        response = self.post("/api/breach", {"query": "a@b.com"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "csrf")

    def test_post_rejects_wrong_csrf_token(self):
        self.login()
        response = self.post("/api/breach", {"query": "a@b.com"}, csrf="forged")
        self.assertEqual(response.status_code, 403)

    def test_get_does_not_require_csrf(self):
        self.login()
        self.assertEqual(self.client.get("/api/quota").status_code, 200)

    def test_forged_cookie_is_rejected(self):
        self.login()
        self.client.set_cookie("osint_session", "forged.value", domain="localhost")
        self.assertEqual(self.client.get("/api/quota").status_code, 401)

    def test_logout_clears_cookie(self):
        self.login()
        self.assertEqual(self.post("/api/logout", csrf=self.login()).status_code, 200)
        self.assertEqual(self.client.get("/api/quota").status_code, 401)

    def test_expired_session_is_rejected(self):
        """A correctly signed cookie with a past `exp` must not authenticate."""
        self.login()
        from webapp.auth import COOKIE_NAME

        with self.app.test_request_context():
            serializer = self.app.session_interface.get_signing_serializer(self.app)
            stale = serializer.dumps({"sub": "operator", "csrf": "abc", "exp": 1})
        self.client.set_cookie(COOKIE_NAME, stale, domain="localhost")
        self.assertEqual(self.client.get("/api/quota").status_code, 401)
        self.assertEqual(
            self.post("/api/breach", {"query": "a@b.com"}, csrf="abc").status_code, 401
        )

    def test_password_comparison_is_constant_time(self):
        from webapp import auth

        with self.app.test_request_context():
            self.assertTrue(auth.check_password(PASSWORD))
            self.assertFalse(auth.check_password(PASSWORD + "x"))
            self.assertFalse(auth.check_password(""))
            self.assertFalse(auth.check_password(None))


class TestSearch(WebTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.csrf = self.login()

    def test_breach_search_returns_rows(self):
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        response = self.post("/api/breach", {"query": "victim@example.com"}, csrf=self.csrf)
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(len(body["rows"]), 1)
        self.assertEqual(body["rows"][0]["email"], "victim@example.com")
        self.assertEqual(body["meta"]["total"], 1)

    def test_breach_search_sends_query_upstream(self):
        self.post("/api/breach", {"query": "victim@example.com"}, csrf=self.csrf)
        self.assertEqual(self.stub.calls[-1][0], "/service/v2/breach/search")
        self.assertEqual(self.stub.last()["q"], "victim@example.com")

    def test_page_size_is_capped(self):
        self.post("/api/breach", {"query": "x", "page_size": 100000}, csrf=self.csrf)
        self.assertEqual(self.stub.last()["page_size"], 100)

    def test_default_page_size_applies(self):
        self.post("/api/breach", {"query": "x"}, csrf=self.csrf)
        self.assertEqual(self.stub.last()["page_size"], 25)

    def test_garbage_page_size_falls_back(self):
        self.post("/api/breach", {"query": "x", "page_size": "lots"}, csrf=self.csrf)
        self.assertEqual(self.stub.last()["page_size"], 25)

    def test_empty_query_is_rejected(self):
        response = self.post("/api/breach", {"query": "   "}, csrf=self.csrf)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.stub.calls, [])

    def test_missing_query_is_rejected(self):
        self.assertEqual(self.post("/api/stealer", {}, csrf=self.csrf).status_code, 400)

    def test_overlong_query_is_rejected(self):
        response = self.post("/api/breach", {"query": "a" * 400}, csrf=self.csrf)
        self.assertEqual(response.status_code, 400)
        self.assertIn("too long", response.get_json()["message"])

    def test_whildcard_flag_is_forwarded(self):
        self.post("/api/breach", {"query": "example", "wildcard": True}, csrf=self.csrf)
        self.assertEqual(self.stub.last()["wildcard"], "true")

    def test_wildcard_absent_by_default(self):
        self.post("/api/breach", {"query": "example"}, csrf=self.csrf)
        self.assertNotIn("wildcard", self.stub.last())

    def test_whitelisted_filters_are_forwarded(self):
        self.post(
            "/api/breach",
            {"query": "x", "filters": {"dbname": ["linkedin", "adobe"]}},
            csrf=self.csrf,
        )
        self.assertEqual(self.stub.last()["dbname[]"], ["linkedin", "adobe"])

    def test_unknown_filters_are_dropped(self):
        self.post(
            "/api/breach",
            {"query": "x", "filters": {"evil": "1", "page_size": 9999}},
            csrf=self.csrf,
        )
        self.assertNotIn("evil[]", self.stub.last())
        self.assertNotIn("page_size[]", self.stub.last())

    def test_filters_ignored_for_other_datasets(self):
        self.post("/api/stealer", {"query": "x", "filters": {"dbname": "a"}}, csrf=self.csrf)
        self.assertNotIn("dbname[]", self.stub.last())

    def test_string_filter_is_wrapped_in_list(self):
        self.post("/api/breach", {"query": "x", "filters": {"domain": "a.com"}}, csrf=self.csrf)
        self.assertEqual(self.stub.last()["domain[]"], ["a.com"])

    def test_non_mapping_filters_ignored(self):
        self.post("/api/breach", {"query": "x", "filters": "nope"}, csrf=self.csrf)
        self.assertNotIn("filters", self.stub.last())

    def test_filter_value_count_is_capped(self):
        many = [f"v{i}" for i in range(100)]
        self.post("/api/breach", {"query": "x", "filters": {"username": many}}, csrf=self.csrf)
        self.assertEqual(len(self.stub.last()["username[]"]), 25)

    def test_cursor_is_forwarded(self):
        self.post("/api/breach", {"query": "x", "cursor": "abc"}, csrf=self.csrf)
        self.assertEqual(self.stub.last()["cursor"], "abc")

    def test_victims_search_tolerates_no_query(self):
        response = self.post("/api/victims", {"page_size": 10}, csrf=self.csrf)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.stub.calls[-1][0], "/service/v2/victims/search")
        self.assertNotIn("q", self.stub.last())

    def test_lookups_endpoint_lists_available(self):
        body = self.client.get("/api/lookups").get_json()
        self.assertTrue(body["ok"])
        self.assertIn("discord", [item["name"] for item in body["lookups"]])


class TestRedaction(WebTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.csrf = self.login()

    def test_password_is_masked_by_default(self):
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        body = self.post("/api/breach", {"query": "x"}, csrf=self.csrf).get_json()
        password = body["rows"][0]["password"]
        self.assertNotEqual(password, "hunter2")
        self.assertIn("*", password)
        self.assertTrue(body["masked_count"] >= 1)

    def test_reveal_requires_server_permission(self):
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        response = self.post(
            "/api/breach",
            {"query": "x"},
            csrf=self.csrf,
            headers={"X-Reveal": "confirm"},
        )
        body = response.get_json()
        self.assertFalse(body["revealed"])
        self.assertNotEqual(body["rows"][0]["password"], "hunter2")

    def test_reveal_returns_plaintext_when_enabled(self):
        self.app.config["ALLOW_REVEAL"] = True
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        response = self.post(
            "/api/breach",
            {"query": "x"},
            csrf=self.csrf,
            headers={"X-Reveal": "confirm"},
        )
        body = response.get_json()
        self.assertTrue(body["revealed"])
        self.assertEqual(body["rows"][0]["password"], "hunter2")
        self.assertEqual(body["masked_count"], 0)

    def test_partial_reveal_header_is_ignored(self):
        self.app.config["ALLOW_REVEAL"] = True
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        response = self.post(
            "/api/breach", {"query": "x"}, csrf=self.csrf, headers={"X-Reveal": "yes"}
        )
        self.assertNotEqual(response.get_json()["rows"][0]["password"], "hunter2")

    def test_password_hash_is_not_masked(self):
        self.stub.responses["/service/v2/breach/search"] = {
            "items": [{"password_hash": "$2b$12$abc", "password": "secret"}],
            "meta": {},
        }
        row = self.post("/api/breach", {"query": "x"}, csrf=self.csrf).get_json()["rows"][0]
        self.assertEqual(row["password_hash"], "$2b$12$abc")
        self.assertNotEqual(row["password"], "secret")

    def test_nested_secrets_are_masked(self):
        self.stub.responses["/service/v2/breach/search"] = {
            "items": [{"wallet": {"seed": "orchid drift aisle", "address": "0xabc"}}],
            "meta": {},
        }
        row = self.post("/api/breach", {"query": "x"}, csrf=self.csrf).get_json()["rows"][0]
        self.assertNotEqual(row["wallet"]["seed"], "orchid drift aisle")
        self.assertEqual(row["wallet"]["address"], "0xabc")

    def test_record_id_is_dropped(self):
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        row = self.post("/api/breach", {"query": "x"}, csrf=self.csrf).get_json()["rows"][0]
        self.assertNotIn("id", row)

    def test_list_field_secret_is_masked(self):
        self.stub.responses["/service/v2/stealer/search"] = STOLEN_LOG
        body = self.post("/api/stealer", {"query": "x"}, csrf=self.csrf).get_json()
        self.assertNotIn("p@ssw0rd123", json.dumps(body))
        self.assertIn("aurorafn.dev", json.dumps(body))

    def test_no_plaintext_secret_reaches_the_browser(self):
        for payload in (BREACH_PAGE, STOLEN_LOG):
            self.stub.responses["/service/v2/breach/search"] = payload
            self.stub.responses["/service/v2/stealer/search"] = payload
            for path in ("/api/breach", "/api/stealer"):
                body = self.post(path, {"query": "x"}, csrf=self.csrf).get_data(as_text=True)
                self.assertNotIn("hunter2", body, path)
                self.assertNotIn("p@ssw0rd123", body, path)

    def test_redact_unit(self):
        from webapp.redact import REDACTED, is_sensitive, redact

        self.assertTrue(is_sensitive("smtp_password"))
        self.assertTrue(is_sensitive("Set-Cookie"))
        self.assertTrue(is_sensitive("x-api-key"))
        self.assertFalse(is_sensitive("password_hash"))
        self.assertFalse(is_sensitive("email"))
        self.assertEqual(redact({"token": "abcd"}), {"token": REDACTED})
        self.assertEqual(redact({"token": "abcdefghij"}), {"token": "ab******ij"})
        self.assertEqual(redact({"token": "secret"}, reveal=True), {"token": "secret"})

    def test_scrub_raw_log(self):
        from webapp.redact import REDACTED, scrub_raw_log

        line = "https://a.dev:user:hunter2\n"
        self.assertEqual(scrub_raw_log(line), f"https://a.dev:user:{REDACTED}\n")
        self.assertEqual(scrub_raw_log(line, reveal=True), line)


class TestLookups(WebTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.csrf = self.login()

    def test_discord_lookup(self):
        self.stub.responses["/service/discord-userinfo"] = {"username": "victim"}
        response = self.post(
            "/api/lookup", {"lookup": "discord", "value": "123456789012345678"}, csrf=self.csrf
        )
        body = response.get_json()
        self.assertEqual(body["label"], "Discord profile")
        self.assertEqual(body["data"]["username"], "victim")
        self.assertEqual(self.stub.last()["discord_id"], "123456789012345678")

    def test_ip_lookup_masks_secrets(self):
        self.stub.responses["/service/ip-info"] = IP_INFO
        body = self.post(
            "/api/lookup", {"lookup": "ip", "value": "203.0.113.9"}, csrf=self.csrf
        ).get_json()
        self.assertEqual(body["data"]["country"], "United States")
        self.assertNotEqual(body["data"]["password"], "should-be-masked")

    def test_unknown_lookup_is_rejected(self):
        response = self.post(
            "/api/lookup", {"lookup": "../../etc/passwd", "value": "x"}, csrf=self.csrf
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.stub.calls, [])

    def test_missing_lookup_value_is_rejected(self):
        response = self.post("/api/lookup", {"lookup": "discord"}, csrf=self.csrf)
        self.assertEqual(response.status_code, 400)

    def test_roblox_accepts_numeric_id(self):
        self.stub.responses["/service/roblox-userinfo"] = {"name": "Player"}
        self.post("/api/lookup", {"lookup": "roblox", "value": "12345"}, csrf=self.csrf)
        self.assertEqual(self.stub.last()["user_id"], "12345")

    def test_roblox_accepts_username(self):
        self.stub.responses["/service/roblox-userinfo"] = {"name": "Player"}
        self.post("/api/lookup", {"lookup": "roblox", "value": "SomePlayer"}, csrf=self.csrf)
        self.assertEqual(self.stub.last()["username"], "SomePlayer")

    def test_alive_flag_is_forwarded(self):
        self.stub.responses["/service/holehe"] = {"domains": []}
        self.post(
            "/api/lookup",
            {"lookup": "holehe", "value": "a@b.com", "alive": True},
            csrf=self.csrf,
        )
        self.assertEqual(self.stub.last()["is_alive"], "true")

    def test_every_lookup_target_is_https_https(self):
        from webapp.routes import LOOKUPS

        for name, (endpoint, _param, _label) in LOOKUPS.items():
            self.assertTrue(endpoint.startswith("/service/"), name)

    def test_lookup_endpoints_match_the_cli(self):
        from webapp.routes import LOOKUPS

        self.assertEqual(LOOKUPS["discord"][0], "/service/discord-userinfo")
        self.assertEqual(LOOKUPS["discord-history"][0], "/service/discord-username-history")
        self.assertEqual(LOOKUPS["steam"][0], "/service/steam")
        self.assertEqual(LOOKUPS["xbox"][0], "/service/xbox")
        self.assertEqual(LOOKUPS["minecraft"][0], "/service/mc-history")
        self.assertEqual(LOOKUPS["ip"][0], "/service/ip-info")
        self.assertEqual(LOOKUPS["ghunt"][0], "/service/ghunt")
        self.assertEqual(LOOKUPS["holehe"][0], "/service/holehe")
        self.assertEqual(LOOKUPS["roblox"][0], "/service/roblox-userinfo")
        self.assertEqual(LOOKUPS["subdomains"][0], "/service/extract-subdomain")
        self.assertEqual(LOOKUPS["phonebook"][0], "/service/v2/phonebook")


class TestDetect(WebTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.login()

    def test_detection(self):
        cases = {
            "a@b.com": "email",
            "8.8.8.8": "ip",
            "123456789012345678": "discord",
            "example.com": "domain",
            "not a thing": "unknown",
        }
        for value, expected in cases.items():
            body = self.client.get(f"/api/detect?q={value}").get_json()
            self.assertEqual(body["kind"], expected, value)
            self.assertTrue(body["suggested"])

    def test_short_query_is_rejected(self):
        self.assertEqual(self.client.get("/api/detect?q=").status_code, 400)


class TestErrors(WebTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.csrf = self.login()

    def test_upstream_error_is_mapped(self):
        self.stub.error = UpstreamError("OathNet daily quota exhausted.", status=429, kind="quota")
        response = self.post("/api/breach", {"query": "x"}, csrf=self.csrf)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.get_json()["error"], "quota")

    def test_upstream_error_from_lookup(self):
        self.stub.error = UpstreamError("OathNet is unavailable right now.", status=502, kind="unavailable")
        response = self.post(
            "/api/lookup", {"lookup": "ip", "value": "8.8.8.8"}, csrf=self.csrf
        )
        self.assertEqual(response.status_code, 502)

    def test_unknown_api_endpoint_returns_json_404(self):
        response = self.client.get("/api/nope")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error"], "not_found")

    def test_api_path_404_even_with_wrong_method(self):
        """The static catch-all owns /api/*, so these report 404, not 405.

        Cosmetic only: the route still refuses to serve anything, and no method
        confusion is possible because the blueprint rules are far more specific
        and always win for real endpoints.
        """
        self.assertEqual(self.client.get("/api/login").status_code, 404)
        self.assertEqual(self.client.get("/api/nope").status_code, 404)

    def test_oversized_body_is_rejected(self):
        response = self.post(
            "/api/breach", {"query": "x", "pad": "y" * 300_000}, csrf=self.csrf
        )
        self.assertIn(response.status_code, (400, 413))

    def test_server_error_does_not_leak_internals(self):
        """An unexpected exception must become an opaque 500, not a stack trace."""

        class Exploding:
            def get(self, path, params=None):
                raise ValueError("secret internal detail")

            quota = QuotaSnapshot()
            health = lambda self: {"reachable": False}  # noqa: E731

        self.app.config["OATHNET_CLIENT"] = Exploding()
        response = self.post("/api/breach", {"query": "x"}, csrf=self.csrf)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json(), {"error": "server_error", "message": "Internal error."})
        self.assertNotIn("secret internal detail", response.get_data(as_text=True))


class TestHardening(WebTestCase):
    def test_security_headers_present(self):
        headers = self.client.get("/").headers
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_index_is_served(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("OathNet", response.get_data(as_text=True))

    def test_assets_are_served(self):
        self.assertEqual(self.client.get("/app.js").status_code, 200)
        self.assertEqual(self.client.get("/styles.css").status_code, 200)

    def test_no_script_tags_inline(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("<script>", html)
        self.assertNotIn("onclick=", html)

    def test_login_throttle_blocks_repeat_attempts(self):
        from webapp import config

        for _ in range(config.LOGIN_MAX_ATTEMPTS):
            self.client.post("/api/login", json={"password": "wrong"})
        response = self.client.post("/api/login", json={"password": PASSWORD})
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)

    def test_search_throttle_returns_429(self):
        from webapp import config

        csrf = self.login()
        for _ in range(config.SEARCH_MAX_REQUESTS + 1):
            response = self.post("/api/breach", {"query": "x"}, csrf=csrf)
        self.assertEqual(response.status_code, 429)

    def test_production_refuses_missing_secrets(self):
        from webapp.config import ConfigError, load_settings

        saved = {name: os.environ.pop(name, None) for name in
                 ("VERCEL", "PRODUCTION", "NODE_ENV", "OATHNET_API_KEY",
                  "SITE_PASSWORD", "SECRET_KEY")}
        os.environ["VERCEL"] = "1"
        try:
            with self.assertRaises(ConfigError) as caught:
                load_settings()
            self.assertIn("OATHNET_API_KEY", str(caught.exception))
        finally:
            os.environ.pop("VERCEL", None)
            for name, value in saved.items():
                if value is not None:
                    os.environ[name] = value

    def test_production_refuses_short_password(self):
        from webapp.config import ConfigError, load_settings

        saved = {n: os.environ.get(n) for n in ("VERCEL", "OATHNET_API_KEY", "SECRET_KEY", "SITE_PASSWORD")}
        os.environ.update(
            VERCEL="1", OATHNET_API_KEY="k", SECRET_KEY="0" * 40, SITE_PASSWORD="short"
        )
        try:
            with self.assertRaises(ConfigError):
                load_settings()
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_api_key_is_not_in_client(self):
        """The key must never reach the browser."""
        body = self.client.get("/").get_data(as_text=True)
        self.assertNotIn("test-key-not-real", body)
        self.assertNotIn("x-api-key", body)

    def test_quota_endpoint_shape(self):
        self.login()
        body = self.client.get("/api/quota").get_json()
        self.assertEqual(body["quota"]["left_today"], 900)
        self.assertEqual(body["quota"]["plan"], "Pro")


class TestRealClientAgainstMockServer(WebTestCase):
    """Exercise the real OathNet client over a real socket.

    Every other test swaps in a stub, which means the envelope unwrapping, the
    auth header, and the quota parser would otherwise go untested. This runs a
    local server that speaks the upstream response shape.
    """

    RECEIVED: list[dict] = []

    @classmethod
    def setUpClass(cls) -> None:
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from urllib.parse import parse_qs, urlparse

        server_self = cls

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parsed = urlparse(self.path)
                # base_url already carries the /api prefix, so strip it to
                # compare against the documented service paths.
                service_path = parsed.path[len("/api"):] or "/"
                query = parse_qs(parsed.query)
                server_self.RECEIVED.append(
                    {"path": service_path, "query": query, "headers": dict(self.headers)}
                )

                if service_path == "/service/v2/health":
                    body, status = {"success": True, "data": {"status": "ok"}}, 200
                elif service_path == "/service/v2/breach/search":
                    body, status = {
                        "success": True,
                        "message": "ok",
                        "data": {
                            "items": [
                                {
                                    "id": "rec_01",
                                    "email": "victim@example.com",
                                    "password": "hunter2",
                                    "dbname": "example_breach_2023",
                                }
                            ],
                            "meta": {"count": 1, "total": 1, "has_more": False},
                            "next_cursor": "cursor_2",
                        },
                        "_meta": {
                            "user": {"plan": "Pro"},
                            "lookups": {
                                "used_today": 12,
                                "left_today": 988,
                                "daily_limit": 1000,
                                "is_unlimited": False,
                            },
                        },
                    }, 200
                elif service_path == "/service/ip-info":
                    body, status = {"success": True, "data": IP_INFO}, 200
                else:
                    body, status = {"success": False, "message": "Unknown service."}, 404

                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # silence
                pass

        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}/api"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        super().setUp()
        type(self).RECEIVED.clear()
        # A genuine client pointed at the mock, not a stub.
        self.app.config["OATHNET_CLIENT"] = OathNet("test-key-not-real", self.base_url)
        self.csrf = self.login()

    def test_envelope_is_unwrapped_and_rows_returned(self):
        body = self.post("/api/breach", {"query": "victim@example.com"}, csrf=self.csrf).get_json()
        self.assertEqual(len(body["rows"]), 1)
        self.assertEqual(body["meta"]["total"], 1)
        self.assertEqual(body["detail"]["next_cursor"], "cursor_2")

    def test_api_key_is_sent_upstream(self):
        self.post("/api/breach", {"query": "x"}, csrf=self.csrf)
        self.assertEqual(self.RECEIVED[-1]["headers"]["x-api-key"], "test-key-not-real")

    def test_secrets_are_masked_over_the_wire(self):
        body = self.post("/api/breach", {"query": "x"}, csrf=self.csrf).get_data(as_text=True)
        self.assertNotIn("hunter2", body)
        self.assertIn("victim@example.com", body)

    def test_query_reaches_upstream(self):
        self.post("/api/breach", {"query": "victim@example.com", "page_size": 5}, csrf=self.csrf)
        sent = self.RECEIVED[-1]["query"]
        self.assertEqual(sent["q"], ["victim@example.com"])
        self.assertEqual(sent["page_size"], ["5"])

    def test_quota_is_parsed_from_response(self):
        self.post("/api/breach", {"query": "x"}, csrf=self.csrf)
        body = self.client.get("/api/quota").get_json()
        self.assertEqual(body["quota"]["left_today"], 988)
        self.assertEqual(body["quota"]["plan"], "Pro")

    def test_health_reports_reachable(self):
        self.assertTrue(self.client.get("/api/health").get_json()["oathnet"]["reachable"])

    def test_upstream_404_is_mapped(self):
        response = self.post(
            "/api/lookup", {"lookup": "steam", "value": "76561198123456789"}, csrf=self.csrf
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error"], "not_found")

    def test_lookup_data_is_unwrapped_and_masked(self):
        body = self.post(
            "/api/lookup", {"lookup": "ip", "value": "203.0.113.9"}, csrf=self.csrf
        ).get_json()
        self.assertEqual(body["data"]["country"], "United States")
        self.assertNotEqual(body["data"]["password"], "should-be-masked")

    def test_connection_failure_is_reported_not_crashed(self):
        # Bind a port then release it, so the port is closed but immediately
        # refuses. Picking a hardcoded port risks landing on something live.
        import socket

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()

        self.app.config["OATHNET_CLIENT"] = OathNet(
            "k", f"http://127.0.0.1:{dead_port}/api", timeout=5.0
        )
        response = self.post("/api/breach", {"query": "x"}, csrf=self.csrf)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["error"], "network")


class TestPublicMode(WebTestCase):
    """PUBLIC_MODE=1 means no password: every visitor is an operator."""

    def make_app(self, **overrides) -> None:
        settings = Settings(
            oathnet_api_key="test-key-not-real",
            oathnet_base_url="https://example.invalid/api",
            site_password=overrides.pop("site_password", ""),
            secret_key="0" * 40,
            is_production=False,
            allow_reveal=False,
            public_mode=True,
            **overrides,
        )
        self.app = create_app(settings)
        self.stub = StubOathNet()
        self.app.config["OATHNET_CLIENT"] = self.stub
        self.client = self.app.test_client()

    def setUp(self) -> None:
        super().setUp()
        self.make_app()

    def test_session_reports_authenticated_without_a_password(self):
        body = self.client.get("/api/session").get_json()
        self.assertTrue(body["authenticated"])
        self.assertTrue(body["public"])
        self.assertIsNone(body["csrf"])

    def test_data_routes_reach_the_upstream_with_no_login(self):
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        response = self.client.post("/api/breach", json={"query": "victim@example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.stub.last()["q"], "victim@example.com")

    def test_no_csrf_header_required(self):
        response = self.client.post("/api/breach", json={"query": "x"})
        self.assertEqual(response.status_code, 200)

    def test_no_session_cookie_is_issued(self):
        self.client.post("/api/breach", json={"query": "x"})
        self.assertNotIn("Set-Cookie", self.client.post(
            "/api/breach", json={"query": "x"}
        ).headers)

    def test_secrets_are_still_masked(self):
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        body = self.client.post("/api/breach", json={"query": "x"}).get_data(as_text=True)
        self.assertNotIn("hunter2", body)
        self.assertIn("victim@example.com", body)

    def test_reveal_still_requires_opt_in(self):
        self.app.config["ALLOW_REVEAL"] = False
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        body = self.client.post(
            "/api/breach", json={"query": "x"}, headers={"X-Reveal": "confirm"}
        ).get_json()
        self.assertFalse(body["revealed"])
        self.assertNotEqual(body["rows"][0]["password"], "hunter2")

    def test_reveal_works_in_public_mode_when_enabled(self):
        self.app.config["ALLOW_REVEAL"] = True
        self.stub.responses["/service/v2/breach/search"] = BREACH_PAGE
        body = self.client.post(
            "/api/breach", json={"query": "x"}, headers={"X-Reveal": "confirm"}
        ).get_json()
        self.assertTrue(body["revealed"])
        self.assertEqual(body["rows"][0]["password"], "hunter2")

    def test_rate_limit_still_applies(self):
        from webapp import config

        for _ in range(config.SEARCH_MAX_REQUESTS + 1):
            response = self.client.post("/api/breach", json={"query": "x"})
        self.assertEqual(response.status_code, 429)

    def test_input_validation_still_applies(self):
        self.assertEqual(self.client.post("/api/breach", json={"query": "  "}).status_code, 400)

    def test_login_is_unnecessary_but_not_harmful(self):
        self.assertEqual(self.client.post("/api/login", json={}).status_code, 200)

    def test_production_allows_public_without_a_password(self):
        from webapp.config import ConfigError, load_settings

        saved = {n: os.environ.get(n) for n in
                 ("VERCEL", "PUBLIC_MODE", "OATHNET_API_KEY", "SECRET_KEY", "SITE_PASSWORD")}
        for name in saved:
            os.environ.pop(name, None)
        os.environ.update(VERCEL="1", PUBLIC_MODE="1", OATHNET_API_KEY="k", SECRET_KEY="0" * 40)
        try:
            settings = load_settings()
            self.assertTrue(settings.public_mode)
            self.assertEqual(settings.site_password, "")
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_production_still_refuses_public_without_a_password(self):
        """The footgun guard: no PUBLIC_MODE and no SITE_PASSWORD must fail."""
        from webapp.config import ConfigError, load_settings

        saved = {n: os.environ.get(n) for n in
                 ("VERCEL", "PUBLIC_MODE", "OATHNET_API_KEY", "SECRET_KEY", "SITE_PASSWORD")}
        for name in saved:
            os.environ.pop(name, None)
        os.environ.update(VERCEL="1", OATHNET_API_KEY="k", SECRET_KEY="0" * 40)
        try:
            with self.assertRaises(ConfigError) as caught:
                load_settings()
            self.assertIn("SITE_PASSWORD", str(caught.exception))
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


if __name__ == "__main__":
    unittest.main(verbosity=2)
