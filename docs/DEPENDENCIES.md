# AEGIS — Dependency Plan

The rule is that every dependency must earn its place. Anything not listed here is deliberately excluded.
The exact pins are in `backend/requirements*.txt` and `frontend/package-lock.json`.

## Backend runtime (Python 3.12)

| Package | Version | Purpose | Why this one |
|---|---|---|---|
| fastapi | 0.163.2 | HTTP API, OpenAPI docs, dependency-injected auth/RBAC | Typed validation at the boundary |
| uvicorn | 0.54.0 | ASGI server (1 worker) | Installed **without** the `[standard]` extras (websockets/httptools/pyyaml) because they are unused |
| pydantic / pydantic-settings | 2.14.3 / 2.16.3 | Schemas, env-based configuration | |
| SQLAlchemy | 2.1.9 | ORM, SQLite now and PostgreSQL later | Installed as pure Python on this machine (see below) |
| alembic | 1.20.1 | Schema migrations | Keeps the PostgreSQL migration path open |
| networkx | 3.7 | In-memory graph **data structure** and zero-copy filtered views | AEGIS implements its own path, cut and centrality algorithms |
| ijson | 3.6.0 | Streaming JSON parser (C yajl2 backend verified) | Flat memory on large SharpHound files |
| argon2-cffi | 25.1.0 | Argon2id password hashing | OWASP recommended |
| psutil | 7.2.2 | Free-RAM/CPU/disk checks, System Health page | |
| python-multipart | 0.0.34 | Multipart file uploads | Required by FastAPI for `UploadFile` |
| Jinja2 | 3.1.6 | HTML reports (autoescape on) | |
| reportlab | 5.1.0 | PDF reports | Pure Python with no system libraries. WeasyPrint was rejected because it needs GTK. |

## Backend dev/test

| Package | Version | Purpose |
|---|---|---|
| pytest / pytest-cov | 9.2.0 / 7.1.0 | Unit and integration tests, coverage |
| httpx2 | 2.16.2 | Required by FastAPI/Starlette `TestClient` (successor to `httpx`, published by the pydantic org) |
| ruff | 0.17.5 | Lint and format |
| watchfiles | 1.3.0 | Only for `uvicorn --reload` while editing backend code |

## Frontend

| Package | Version | Kind | Purpose |
|---|---|---|---|
| react / react-dom | 19.3.1 | runtime | UI |
| react-router-dom | 7.18.5 | runtime | Page routing |
| cytoscape | 3.35.0 | runtime | Attack-graph visualisation (ships its own TS types) |
| recharts | 3.11.0 | runtime | Dashboard charts |
| lucide-react | 1.75.0 | runtime | Icons (tree-shaken) |
| vite | 8.3.8 | dev | Dev server and bundler (Rolldown) |
| @vitejs/plugin-react | 6.3.0 | dev | JSX / Fast Refresh |
| typescript | 7.0.2 | dev | Type checking (native compiler) |
| @types/react, @types/react-dom | 19.3.0 | dev | Types |
| tailwindcss, @tailwindcss/vite | 4.3.5 | dev | Styling (no PostCSS config needed) |

## Deliberately excluded

| Not used | Reason |
|---|---|
| Neo4j / any graph DB | 1–2 GB JVM heap and no capability gap at the target graph sizes |
| PostgreSQL (for now) | SQLite is enough for a single analyst. The schema stays portable. |
| Redis / Celery | The in-process bounded job runner is enough. A broker adds hundreds of MB. |
| Docker (required) | Not installed and needs admin and WSL2. Compose files are provided as optional. |
| pandas / numpy | Not needed. CSV import uses the stdlib `csv` module in streaming mode. |
| GPU / CUDA libraries | No algorithm here benefits |
| slowapi / limits | A rate limiter is about 60 lines of in-process code, so no extra dependency is needed |
| python-jose / JWT | Server-side sessions are simpler to revoke and fit a same-origin SPA |
| WeasyPrint / headless Chrome PDF | Native GTK dependency or a 300 MB browser |

## Platform-specific notes

* **Windows Smart App Control** blocks SQLAlchemy's unsigned Cython `.pyd` files. `scripts/setup_backend.ps1`
  detects this and reinstalls the same version from the official sdist with `DISABLE_SQLALCHEMY_CEXT=1`, so the result is pure Python.
  The API is identical, and the pure-Python build is slightly slower on ORM-heavy loops. Bulk ingestion uses Core `insert()` batches to compensate.
* coverage's C tracer is blocked for the same reason. coverage falls back to its Python tracer automatically, which was verified.
* All other native modules (pydantic-core, argon2 bindings, ijson yajl2_c, psutil, markupsafe, pillow,
  Rolldown, Tailwind oxide, TypeScript 7) load correctly.
