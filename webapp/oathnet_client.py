"""Server-side OathNet API client.

The key is read from the environment and never leaves this module's headers.
Nothing here logs request or response bodies.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

RETRYABLE = (429, 500, 502, 503, 504)


class UpstreamError(Exception):
    """An OathNet call failed. Carries a status the browser can act on."""

    def __init__(self, message: str, *, status: int = 502, kind: str = "upstream"):
        super().__init__(message)
        self.status = status
        self.kind = kind


class QuotaSnapshot:
    __slots__ = ("used", "left", "limit", "unlimited", "plan")

    def __init__(self) -> None:
        self.used: int | None = None
        self.left: int | None = None
        self.limit: int | None = None
        self.unlimited = False
        self.plan: str | None = None

    @classmethod
    def parse(cls, payload: Any) -> "QuotaSnapshot | None":
        if not isinstance(payload, Mapping):
            return None
        meta = payload.get("_meta")
        if meta is None and isinstance(payload.get("data"), Mapping):
            meta = payload["data"].get("_meta")
        if not isinstance(meta, Mapping):
            return None
        lookups = meta.get("lookups")
        if not isinstance(lookups, Mapping):
            return None
        snap = cls()
        snap.used = lookups.get("used_today")
        snap.left = lookups.get("left_today")
        snap.limit = lookups.get("daily_limit")
        snap.unlimited = bool(lookups.get("is_unlimited"))
        user = meta.get("user")
        if isinstance(user, Mapping):
            snap.plan = user.get("plan")
        return snap

    def as_dict(self) -> dict:
        return {
            "used_today": self.used,
            "left_today": self.left,
            "daily_limit": self.limit,
            "is_unlimited": self.unlimited,
            "plan": self.plan,
        }


class OathNet:
    def __init__(self, api_key: str, base_url: str, timeout: float = 25.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._key = api_key
        self.quota = QuotaSnapshot()

        self._http = requests.Session()
        self._http.headers.update(
            {
                "x-api-key": api_key,
                "accept": "application/json",
                "user-agent": "oathnet-web/1.0",
            }
        )
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.5,
            status_forcelist=RETRYABLE,
            allowed_methods=frozenset({"GET", "POST"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
        self._http.mount("https://", adapter)
        self._http.mount("http://", adapter)

    # -- internals --------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    @staticmethod
    def _message(response: requests.Response, body: Any) -> str:
        if isinstance(body, Mapping):
            message = body.get("message")
            if isinstance(message, str) and message:
                return message
            errors = body.get("errors")
            if isinstance(errors, Mapping):
                for key in ("error", "detail", "details"):
                    value = errors.get(key)
                    if isinstance(value, str) and value:
                        return value
        text = (response.text or "").strip()
        return text[:200] or (response.reason or "request failed")

    def _raise(self, response: requests.Response, body: Any) -> None:
        status = response.status_code
        message = self._message(response, body)
        lowered = message.lower()

        if status == 401:
            raise UpstreamError("OathNet rejected the server's API key.", status=502, kind="auth")
        if status == 403:
            if "quota" in lowered or "limit" in lowered:
                raise UpstreamError("OathNet daily quota exhausted.", status=429, kind="quota")
            raise UpstreamError("Upstream refused the request.", status=502, kind="forbidden")
        if status == 404:
            raise UpstreamError(message, status=404, kind="not_found")
        if status == 429:
            raise UpstreamError("Rate limited by OathNet.", status=429, kind="rate_limit")
        if status in (400, 409, 422):
            raise UpstreamError(message, status=400, kind="invalid")
        if status >= 500:
            raise UpstreamError("OathNet is unavailable right now.", status=502, kind="unavailable")
        raise UpstreamError(message, status=502, kind="upstream")

    def _request(self, method: str, path: str, *, params=None, json_body=None) -> Any:
        url = self._url(path)
        try:
            response = self._http.request(
                method, url, params=params, json=json_body, timeout=self.timeout
            )
        except requests.exceptions.Timeout as exc:
            raise UpstreamError("Timed out contacting OathNet.", status=504, kind="timeout") from exc
        except requests.exceptions.RequestException as exc:
            raise UpstreamError("Could not reach OathNet.", status=502, kind="network") from exc

        ctype = response.headers.get("content-type", "")
        body: Any = None
        if response.status_code < 400:
            if "json" in ctype:
                try:
                    body = response.json()
                except ValueError:
                    raise UpstreamError("Malformed response from OathNet.", status=502, kind="protocol")
            else:
                raise UpstreamError("Unexpected non-JSON response from OathNet.", status=502, kind="protocol")
        else:
            try:
                body = response.json()
            except ValueError:
                body = None

        if response.status_code >= 400:
            self._raise(response, body)

        snapshot = QuotaSnapshot.parse(body)
        if snapshot:
            self.quota = snapshot

        if isinstance(body, Mapping) and "success" in body:
            if not body.get("success"):
                self._raise(response, body)
            return body.get("data")
        return body

    # -- verbs ------------------------------------------------------------

    def get(self, path: str, params: Mapping | None = None) -> Any:
        return self._request("GET", path, params=dict(params or {}))

    def get_text(self, path: str, params: Mapping | None = None) -> str:
        url = self._url(path)
        try:
            response = self._http.get(url, params=dict(params or {}), timeout=self.timeout)
        except requests.exceptions.RequestException as exc:
            raise UpstreamError("Could not reach OathNet.", status=502, kind="network") from exc
        if response.status_code >= 400:
            self._raise(response, None)
        return response.text

    def post(self, path: str, body: Any, params: Mapping | None = None) -> Any:
        return self._request("POST", path, params=dict(params or {}), json_body=body)

    def health(self) -> Any:
        url = self._url("/service/v2/health")
        try:
            response = self._http.get(url, timeout=8.0)
        except requests.exceptions.RequestException:
            return {"reachable": False}
        try:
            return {"reachable": response.status_code < 500, "status_code": response.status_code}
        except Exception:  # pragma: no cover - defensive
            return {"reachable": False}
