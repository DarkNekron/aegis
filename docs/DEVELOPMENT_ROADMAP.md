# AEGIS — Development Roadmap

Each stage ends with passing tests and a Git commit. A stage is not "done" while it has placeholder functions.

Status legend: ✅ done · 🔄 in progress · ⏳ pending

| # | Stage | Deliverables | Exit criteria | Status |
|---|---|---|---|---|
| 0 | System inspection | `SYSTEM_ASSESSMENT.md` | Report written from measured data | ✅ |
| 1 | Architecture | `ARCHITECTURE.md`, `DEPENDENCIES.md`, this roadmap | Reviewed by owner | ✅ owner gave the go-ahead (2026-11-18) |
| 2 | Environment | venv, pinned requirements, Vite/React/Tailwind scaffold, `.env.example`, install report | Import checks and `tsc` pass | ✅ |
| 3.0 | Backend foundation | settings, DB/ORM models, Alembic, resource manager, job runner, health endpoint | Unit tests for limits, jobs and cancellation | ✅ 50 tests; live smoke test: 86 MB idle RSS |
| 3.1 | Module 1 — Ingestion | BloodHound CE/SharpHound JSON+ZIP, custom JSON, CSV; safe ZIP; normaliser; import summary | Tests: valid, malformed, ZIP traversal, ZIP bomb, duplicates | ✅ 61 ingestion tests; 20k-user import: 9.4 s, +14 MB RSS |
| 3.2 | Synthetic datasets | generator + 3 fixed datasets with documented ground truth | Datasets validate against the ingestion engine | ✅ ground truth verified by an independent reference checker (17 tests) |
| 3.3 | Module 2 — Graph construction | rules table, builder, tier-0 classifier, DCSync derivation, graph cache | Tests: edge semantics, unknown kinds not traversed | ✅ engine matches the reference on all datasets; 20k-user graph: 0.9 s, 87 MB |
| 3.4 | Module 3 — Attack-path engine | reverse Dijkstra, Yen k-paths, bounded DFS, dedup, min-cut, sampled betweenness, explanations | Ground-truth path tests pass | ⏳ |
| 3.5 | Module 4 — Risk engine | scoring model, configurable weights, `RISK_SCORING.md` | Deterministic score tests | ⏳ |
| 5.0 | Security layer | auth, sessions, CSRF, RBAC, rate limit, audit log, headers | AuthN/AuthZ tests per role | ⏳ |
| 3.6 | Module 6 — Simulation | view-based what-if, all action types | Original graph unchanged (tested) | ⏳ |
| 3.7 | Module 7 — Comparison | object/edge/path diffs, change report | Diff tests across two snapshots | ⏳ |
| 3.8 | Module 8 — Reporting | HTML, PDF and JSON with all 13 sections | Reports generate from sample data | ⏳ |
| 4 | Frontend + Module 5 | 10 pages, Cytoscape explorer, filtering and incremental expansion | `tsc`, build, manual walkthrough | ⏳ |
| 6 | Validation | integration tests, benchmarks with measured time and peak RAM | `BENCHMARKS.md` from real runs | ⏳ |
| 7 | Docs & GitHub readiness | README, install, API, dev, testing, security, datasets, troubleshooting | Fresh-clone install works | ⏳ |

The security layer is built **before** the modules that add state-changing endpoints. That way every later endpoint is protected
from the moment it exists.

## Stage notes

**3.0 Backend foundation (done 2026-11-18)**
* `/api/system/health` is unauthenticated until stage 5.0 adds auth. It exposes no secrets or paths, only
  resource figures and limits. `/api/health` will stay public.
* Job timeouts are cooperative, because Python cannot safely kill threads. Every algorithm must call
  `ctx.token.checkpoint()` in its loops. This is enforced by code review and by timeout tests for each module.

**3.1 Ingestion (done 2026-11-18)**
* Imports run through `python -m app.cli import <snapshot> <file>` for now. The HTTP upload endpoint is wired in
  stage 5.0, behind authentication, RBAC and CSRF, using the already-tested `UploadWriter`.
* Uploaded raw files will be deleted after import by default, because they contain sensitive directory data.

**3.2 Synthetic datasets (done 2026-11-18)**
* The conventions in `sample_data/README.md` (tier-0 definition, traversable relationships, conditional edges,
  starting identities) are the specification for stages 3.3 and 3.4.
* `backend/tests/reference_paths.py` is a deliberately naive oracle. The real engine must agree with it on every
  dataset, and it must never be imported by application code.

**3.3 Graph construction (done 2026-11-18)**
* The tier-0 classification is written back to `ad_objects.is_tier0` / `tier0_reason` on every build, so list
  views and reports do not need the in-memory graph.
* The graph memory estimate was recalibrated from measurement (see BENCHMARKS.md). It had been 35% too low.
