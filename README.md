# OathNet Research Console

A private, password-gated web front end for the OathNet OSINT API. The API key
lives only on the server: the browser talks to this app, this app talks to
OathNet, and plaintext secrets are masked before any response leaves the
process.

## What it does

- **Breach search** — query indexed breach records.
- **Stealer log search** — query infostealer output, including the `url:user:pass` lines.
- **Victim search** — enumerate victim profiles and their infected hosts.
- **Enrichment** — 12 single-subject lookups: Discord profile and username history,
  Steam, Xbox, Minecraft history, IP geolocation, Google account info, email
  existence (holehe), Roblox, subdomains, and phonebook domain intelligence.
- **Filtering** — repeatable field filters, wildcard match, cursor paging.
- **Export** — download a result set as JSON or CSV.
- **Quota meter** — remaining daily lookups, straight from the upstream response.

## Security model

This is the part that matters, so read it before changing anything.

| Control | Behaviour |
| --- | --- |
| Authentication | Single shared password, compared with `hmac.compare_digest`. No session is issued until it matches. |
| Session | Signed, `httpOnly`, `SameSite=Strict` cookie, 8-hour expiry. Payload holds only a subject, an expiry, and a CSRF token. |
| CSRF | Every state-changing request must echo the session's CSRF token in `X-CSRF-Token`. |
| Secrets | Masked server-side on every response unless the session is authorised *and* sends `X-Reveal: confirm`. |
| Reveal | Requires `ALLOW_REVEAL=1` **and** an authenticated session **and** the confirm header. Off by default. |
| Input | Query length capped at 320 chars, page size capped at 100, filter values whitelisted per dataset and capped at 25, body capped at 256 KB. |
| Rate limits | 8 failed logins per 15 min; 120 searches per minute, both per client address. |
| Headers | CSP with no `unsafe-inline`, `X-Frame-Options: DENY`, `nosniff`, HSTS in production. No CORS headers are emitted, so the API is same-origin only. |
| Logging | Request and response bodies are never logged. `urllib3` is pinned to WARNING so query strings cannot leak at DEBUG. |
| Startup | Refuses to boot in production without `OATHNET_API_KEY`, `SITE_PASSWORD`, and `SECRET_KEY`, or with a password under 12 characters. |

Two honest limitations:

1. **Rate limiting is per instance and in-process.** Vercel routes requests to
   arbitrary instances, so these limits bound one instance's abuse, not the whole
   deployment. They are a speed bump, not a quota system.
2. **Masking protects transport and shoulder-surfing, not the data itself.** If
   you enable `ALLOW_REVEAL`, plaintext credentials render in the browser. That
   is the point, but it means the machine is now holding stolen credentials in
   the DOM.

### Running with no password

Set `PUBLIC_MODE=1` and the login screen disappears: every visitor is treated as
an operator. `SITE_PASSWORD` becomes optional, no session cookie is issued, and
CSRF is skipped because there is no per-visitor state left to forge.

What does **not** change: secret masking, the filter whitelist, input limits, and
the search rate limit. The rate limit matters most here — with no password, the
URL is the only barrier, so 120 requests/minute per address is now the only
thing between a scraper and your daily quota.

`PUBLIC_MODE` is an explicit opt-in rather than an inference from an empty
`SITE_PASSWORD`, so that forgetting to set a password can never silently publish
the site. The UI shows a banner while it is on.

## Run locally

```bash
pip install -r requirements.txt
copy .env.example .env      # Windows; use `cp` on macOS/Linux
```

`load_settings` reads `os.environ`, so either export the variables or set them
in the shell before starting. Then:

```bash
python app.py
```

Open http://127.0.0.1:5000 and sign in with `SITE_PASSWORD`.

## Test

```bash
python tests.py
```

90 tests, no network, no API key, no quota. `StubOathNet` replays real upstream
response envelopes so the tests assert what the browser receives, and
`TestRealClientAgainstMockServer` drives the actual HTTP client against a local
server.

## Deploy to Vercel

```bash
npm i -g vercel
vercel            # preview
vercel --prod     # production
```

Add these as environment variables for **both** preview and production
(`vercel env add` or Settings → Environment Variables):

| Variable | Required | Notes |
| --- | --- | --- |
| `OATHNET_API_KEY` | yes | Your OathNet key. |
| `SECRET_KEY` | yes | 32+ characters. Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. |
| `SITE_PASSWORD` | unless `PUBLIC_MODE=1` | Console password, 12+ characters. |
| `PUBLIC_MODE` | no | `1` to run with no password at all. |
| `ALLOW_REVEAL` | no | `1` to permit plaintext secrets. Default off. |

Vercel sets `VERCEL=1` automatically, which is what activates the production
refusal in `webapp/config.py`. If the app boots and immediately 500s, it is
almost certainly a missing or short secret.

### Layout

```
app.py                     Vercel entrypoint; exports the Flask instance as `app`
webapp/__init__.py         app factory, error handling, security headers, static files
webapp/config.py           environment parsing and production refusal
webapp/auth.py             signed sessions, CSRF, rate limiting
webapp/oathnet_client.py   server-side OathNet HTTP client with retries
webapp/redact.py           secret masking, applied before serialisation
webapp/routes.py           API surface and the filter whitelist
public/                    static front end, no build step
tests.py                   test suite
```

Vercel auto-detects the Flask instance in the root `app.py`, so there is no
`pyproject.toml` and no `[tool.vercel] entrypoint` to keep in sync. The whole
app is a single function; `webapp/routes.py` owns the `/api/*` routing and
`public/` is served from the CDN. Note that Vercel serves `public/**` itself,
so `app.static_folder` is left unset and the static routes in
`webapp/__init__.py` exist for `vercel dev` and local runs.

## Legal

This queries data about people. Breach and stealer-log records are not consent.
Use it on systems you own or have written authorisation to assess, keep a record
of what you queried and why, and follow the laws that apply to you — the Computer
Fraud and Abuse Act, the UK Computer Misuse Act, and GDPR are the usual
reference points in this domain. Breach notification and data-protection
obligations land on the data controller, not on the tool. Do not use this to
harass, dox, or build a targeting list.
