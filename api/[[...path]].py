"""Vercel serverless entry point.

Vercel discovers Flask apps by the module-level `app` object. The catch-all
route lets every /api/* request share one cold-start instance.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from webapp import create_app  # noqa: E402

app = create_app()

# Vercel routes any path not matched by `public/` or another function here.
handler = app


if __name__ == "__main__":  # pragma: no cover - local convenience
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
