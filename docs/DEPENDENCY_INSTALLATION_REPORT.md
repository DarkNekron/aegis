# AEGIS — Dependency Installation Report (Phase 2)

**Date:** 2026-11-18. **Privileges used:** standard user only. No system-wide changes were made.

## Summary

| Area | Result |
|---|---|
| Python venv | `backend/.venv`, Python 3.12.10 (python.org build) ✅ |
| Backend runtime packages | 32 installed (13 direct + 19 transitive), all pinned ✅ |
| Backend dev packages | 13 additional, pinned ✅ |
| `pip check` | No broken requirements ✅ |
| venv ↔ requirements-dev.txt | Exact match (`pip install --dry-run` shows nothing to install) ✅ |
| Frontend packages | 6 runtime + 8 dev direct, exact versions, `package-lock.json` generated ✅ |
| `node_modules` size | 187 MB |
| Frontend type check (TS 7) | Passes, including imports from every runtime library ✅ |
| Frontend production build | Passes (Vite 8.3.8, about 0.2 s, 220 kB JS / 69 kB gzip for the shell) ✅ |
| Global installs | **None.** No global pip or npm packages were added. |

## Verification performed

* Imported every backend package inside the venv.
* ijson uses the **C `yajl2_c` backend**, the fast streaming path.
* SQLite 3.49.1 with **WAL** and **JSON1** works through SQLAlchemy.
* Argon2id hash and verify round-trip.
* ReportLab rendered a one-page PDF (1.5 KB).
* NetworkX `subgraph_view` with an edge filter hides edges while the original graph stays untouched. This is the
  basis of the simulation engine.
* The FastAPI `TestClient` works with `httpx2` and no deprecation warnings (checked with `-W error::DeprecationWarning`).
* The pytest + coverage smoke test passed with coverage's Python-tracer fallback.
* Cytoscape ran headless in Node and built a graph.
* `scripts/setup_backend.ps1` passed two runs: an idempotent rerun, and a run that **exercises the Smart App
  Control fallback**. For the second run the blocked binary SQLAlchemy wheel was put back deliberately, and the script detected the block and repaired it.

## Issues found and how they were resolved

| # | Issue | Resolution |
|---|---|---|
| 1 | **Smart App Control** blocked `sqlalchemy/util/_collections_cy.pyd` ("An Application Control policy has blocked this file") | Reinstalled SQLAlchemy 2.1.9 from the official sdist with `DISABLE_SQLALCHEMY_CEXT=1`, giving a pure-Python build with the same version. This is automated in the setup script. Smart App Control was **not** disabled, because that would be a system-wide security change and it cannot easily be turned back on. |
| 2 | coverage C tracer blocked by the same policy | No action needed. coverage falls back to its Python tracer, which was verified. |
| 3 | Starlette deprecates `httpx` for `TestClient` | Installed `httpx2` after checking its provenance (pydantic org, original httpx author, named in Starlette's source) and removed `httpx`. |
| 4 | `uvicorn[standard]` pulled in websockets, httptools and PyYAML, which are unused | Uninstalled them. Runtime uses plain `uvicorn`. `watchfiles` is kept as a dev-only reload helper. |
| 5 | Orphan packages (`httpcore`, `certifi`) after the swap | Uninstalled them. A dependency-closure check found zero orphans afterwards. |
| 6 | Setup script bug: PowerShell 5.1 turned the probe's stderr into a terminating error, so the fallback never ran | Fixed by moving the probe into `Test-SqlAlchemyImport` and retested successfully. |
| 7 | `npm audit`: 5 "high" findings | All five come from **one** advisory: GHSA-fc5q-39xc-vjpf, a ReDoS in `picomatch` ≤ 4.0.7 used by Vite's file globbing. **No patched version exists yet** (4.0.7 is the latest), and npm's only "fix" is a two-major downgrade of Vite. **Risk accepted.** It is build-time only, glob patterns come from the project's own config and never from user input, and picomatch is not in the shipped bundle. Re-check with `npm audit` when picomatch is updated. |
| 8 | Extraneous packages (`tslib`, `@tybys/wasm-util`) in `node_modules` | `npm prune`. 0 extraneous remain. |

## Installed backend packages

| Package | Version | Kind | Status |
|---|---|---|---|
| fastapi | 0.163.2 | runtime | ✅ |
| uvicorn | 0.54.0 | runtime | ✅ |
| pydantic | 2.14.3 | runtime | ✅ |
| pydantic-settings | 2.16.3 | runtime | ✅ |
| SQLAlchemy | 2.1.9 (pure Python) | runtime | ✅ see issue 1 |
| alembic | 1.20.1 | runtime | ✅ |
| networkx | 3.7 | runtime | ✅ |
| ijson | 3.6.0 | runtime | ✅ C backend |
| argon2-cffi | 25.1.0 | runtime | ✅ |
| psutil | 7.2.2 | runtime | ✅ |
| python-multipart | 0.0.34 | runtime | ✅ |
| Jinja2 | 3.1.6 | runtime | ✅ |
| reportlab | 5.1.0 | runtime | ✅ |
| annotated-doc 0.0.7, annotated-types 0.8.0, anyio 4.16.0, argon2-cffi-bindings 26.2.0, cffi 2.1.1, charset-normalizer 3.5.2, click 8.5.1, h11 0.16.0, idna 3.20, Mako 1.4.3, MarkupSafe 3.0.4, opentelemetry-api 1.45.2, pillow 13.0.0, pycparser 3.12, pydantic_core 2.50.4, python-dotenv 1.2.4, starlette 1.10.0, typing_extensions 4.16.0, typing-inspection 0.4.5 | | transitive | ✅ |
| pytest | 9.2.0 | dev | ✅ |
| pytest-cov | 7.1.0 | dev | ✅ |
| httpx2 | 2.16.2 | dev | ✅ |
| ruff | 0.17.5 | dev | ✅ |
| watchfiles | 1.3.0 | dev | ✅ |
| colorama 0.4.6, coverage 7.17.3, httpcore2 2.16.2, iniconfig 2.3.1, packaging 26.3, pluggy 1.7.0, Pygments 2.21.0, truststore 0.10.5 | | dev transitive | ✅ |

## Installed frontend packages
See the table in [DEPENDENCIES.md](DEPENDENCIES.md#frontend). Every entry is installed at the listed exact version.

## Not installed (by design)
PostgreSQL, Docker, Neo4j, Redis, Node global tools, CUDA. The reasons are in [DEPENDENCIES.md](DEPENDENCIES.md#deliberately-excluded).
Docker files will be written in Phase 7, but they **cannot be tested on this machine**, and the documentation will say so.

## Reproducing on a fresh clone
```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_backend.ps1 -Dev
cd frontend; npm ci
```
