# AEGIS — Developer Guide

## Everyday commands (Windows, from the repository root)

| Task | Command |
|---|---|
| Set up / repair the backend venv | `powershell -ExecutionPolicy Bypass -File scripts\setup_backend.ps1 -Dev` |
| Run the backend | `powershell -ExecutionPolicy Bypass -File scripts\run_backend.ps1` (add `-Reload` while editing) |
| Run the tests | `cd backend; .venv\Scripts\python.exe -m pytest` |
| Tests with coverage | `cd backend; .venv\Scripts\python.exe -m pytest --cov` |
| Lint (incl. security rules) | `cd backend; .venv\Scripts\ruff.exe check app tests migrations` |
| New DB migration after editing models | `cd backend; .venv\Scripts\python.exe -m alembic revision --autogenerate -m "describe change"` |
| Frontend dev server | `cd frontend; npm run dev` (only while working on the UI) |
| Frontend type check / build | `cd frontend; npm run typecheck` / `npm run build` |

> Use `python -m <tool>`, never `pytest.exe`, `uvicorn.exe` or `alembic.exe`. Windows Smart App Control blocks
> pip's unsigned launcher executables on the development machine.

API docs are at `http://127.0.0.1:8000/api/docs` (disabled when `AEGIS_ENV=production`).

## Backend layout
```
backend/app/
  core/        config, errors, logging (secret redaction), resources, jobs, middleware
  db/          declarative base, engine/session, migrate-on-startup
  models/      auth (users, sessions, audit), directory (snapshots, objects, edges), analysis
  api/         routers + dependencies (services are read from app.state)
backend/migrations/   Alembic (batch mode for SQLite)
backend/tests/        pytest. Fixtures use a temporary data dir and a fake resource probe.
```

## Conventions
* **Long-running work** goes through `JobRunner.submit(...)` and must call `ctx.token.checkpoint()` in its loops.
  Use `JobKind.HEAVY` for anything that walks the graph.
* **Errors shown to users** are `AegisError` subclasses with safe messages. Any other exception becomes a
  generic 500 with a reference ID, and the details go only to the server log.
* **Model changes need a migration.** `tests/test_database.py::test_migrations_match_models` fails otherwise.
* **Never log request bodies or secrets.** The redaction filter is a safety net, not a licence to log them.
