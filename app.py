"""Vercel entrypoint.

Vercel auto-detects a Flask instance named `app` in a root-level `app.py`, so
no `pyproject.toml` and no `[tool.vercel] entrypoint` is needed. The whole
application is a single function: `webapp/routes.py` owns the `/api/*` routing
and `public/` is served from the CDN.

Keep this file thin. Anything that fails at import time, including the
production refusal in `webapp/config.py`, should surface as a failed build
rather than a confusing runtime 500.
"""

from __future__ import annotations

import os

from webapp import create_app

app = create_app()

# Some WSGI hosts look for `handler`.
handler = app


if __name__ == "__main__":  # pragma: no cover - local convenience
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
