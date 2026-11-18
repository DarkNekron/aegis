"""Serves the built React application (single-process mode, see ARCHITECTURE.md §1).

There is deliberately no catch-all route (it would shadow any route registered later). Instead the
404 handler calls ``spa_response``: only when no real route matched, for a GET outside ``/api``, is
a file from the build (or ``index.html`` for client-side routes such as /paths) returned.

* ``/assets/*``: content-hashed bundles, cached long-term (``immutable``).
* Paths are resolved inside the build directory only; traversal attempts get ``index.html``.
* ``/api/*`` 404s keep the normal structured JSON error.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse

IMMUTABLE = "public, max-age=31536000, immutable"


def install_spa(app: FastAPI, dist: Path) -> bool:
    enabled = (dist / "index.html").is_file()
    app.state.spa_root = dist.resolve() if enabled else None
    return enabled


def spa_response(request: Request) -> FileResponse | None:
    root: Path | None = getattr(request.app.state, "spa_root", None)
    path = request.url.path
    if root is None or request.method not in ("GET", "HEAD") or path == "/api" or path.startswith("/api/"):
        return None
    relative = path.lstrip("/")
    candidate = (root / relative).resolve()
    if relative and candidate.is_file() and candidate.is_relative_to(root):
        cache = IMMUTABLE if relative.startswith("assets/") else "no-cache"
        return FileResponse(candidate, headers={"Cache-Control": cache})
    return FileResponse(root / "index.html", headers={"Cache-Control": "no-store"})
