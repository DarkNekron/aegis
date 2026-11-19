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
| 3.4 | Module 3 — Attack-path engine | reverse Dijkstra, Yen k-paths, bounded DFS, dedup, min-cut, sampled betweenness, explanations | Ground-truth path tests pass | ✅ exact match on all datasets; 40 random-graph oracle checks; 20k users analysed in 0.67 s |
| 3.5 | Module 4 — Risk engine | scoring model, configurable weights, `RISK_SCORING.md` | Deterministic score tests | ✅ worked example exact (81.90); analyses and paths persisted |
| 5.1 | HTTP API | snapshots, streaming uploads, import/analysis jobs, paths, evidence, graph views, settings, dashboard | API tests + live run | ✅ 15 API tests; live curl run on corp-medium (33/33 exposed, 130 MB) |
| 5.0 | Security layer | auth, sessions, CSRF, RBAC, rate limit, audit log, headers | AuthN/AuthZ tests per role | ✅ 31 security tests; docs/SECURITY.md |
| 3.6 | Module 6 — Simulation | view-based what-if, all action types | Original graph unchanged (tested) | ✅ ground-truth simulations; monotonicity property; 0.54 s at 20k users |
| 3.7 | Module 7 — Comparison | object/edge/path diffs, change report | Diff tests across two snapshots | ✅ matches corp-small→v2 ground truth; 3.1 s / +0 MB at 114k relationships |
| 3.8 | Module 8 — Reporting | HTML, PDF and JSON with all 13 sections | Reports generate from sample data | ✅ PDF/HTML/JSON, 13 sections + change section; hostile-name tests |
| 4 | Frontend + Module 5 | 10 pages, Cytoscape explorer, filtering and incremental expansion | `tsc`, build, manual walkthrough | ✅ strict tsc + build; headless-Edge walkthrough of all pages, no console or CSP errors |
| 6 | Validation | integration tests, benchmarks with measured time and peak RAM | `BENCHMARKS.md` from real runs | ✅ 326 tests; measured ingestion, graph, analysis, simulation, comparison; browser walkthrough |
| 7 | Docs & GitHub readiness | README, install, API, dev, testing, security, datasets, troubleshooting | Fresh-clone install works | ✅ clone → setup (78 s) → 326 tests → sample data → login & UI |

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

**3.4 Attack-path engine (done 2026-11-18)**
* The algorithms are in `app/graph_engine/algorithms/`: index, shortest, alternatives (Yen + bounded DFS), flow
  (Edmonds–Karp min-cut) and centrality (sampled Brandes). NetworkX's algorithms appear only in tests, as oracles.
* Paths are ranked provisionally by (hops, cost, confidence). Stage 3.5 replaces this with the transparent risk score
  and persists analyses and paths.

**3.5 Risk engine (done 2026-11-18)**
* `docs/RISK_SCORING.md` documents every factor, the default weights, the bands, the conditional cap and the
  environment score, with a worked example that a test keeps exact.
* `AnalysisService` persists analyses and scored paths with self-contained explanations (`attack_paths.details`),
  supports paginated and filtered queries, and handles analyst validation.
* Stage **5.0 security layer** followed, as planned, before any state-changing endpoint.

**5.0 Security layer (done 2026-11-18)**
* Argon2id, server-side hashed sessions, CSRF token + Origin check, RBAC (admin/analyst/viewer), lockout, per-IP,
  per-username and per-user rate limits, audit log, browser first-run setup with a one-time console code (plus `create-user` CLI). No default credentials.
* `/api/system/health` now requires the viewer role.
* Next: **5.1 HTTP API** for snapshots, uploads (streaming `UploadWriter`), imports and analyses as background jobs,
  path browsing, analyst validation, graph neighbourhoods and settings, all behind these controls.

**5.1 HTTP API (done 2026-11-18)**
* Uploads are raw request bodies, so the size limit is enforced while streaming; multipart parsing would spool the
  whole file to disk first. Raw uploads are deleted after import.
* A live run against Uvicorn with curl (real cookies, CSRF, upload, jobs, dashboard) matched the corp-medium ground
  truth.
* Next: 3.6 remediation simulation, 3.7 historical comparison, 3.8 reporting, then the frontend.

**3.6 Remediation simulation (done 2026-11-18)**
* The action types are remove_relationship, remove_step, remove_membership, remove_acl, remove_admin, remove_session,
  disable_identity and apply_min_cut. The baseline and the what-if are computed on the same graph with the same
  parameters.
* The simulation tests exposed a non-monotone environment metric: it used the mean of identity scores, which went up
  after remediation. It was replaced by a capped exposure mass, documented in RISK_SCORING.md §4, and a property test
  now guards it.

**3.7 Historical comparison (done 2026-11-18)**
* `GET /api/comparisons?old_snapshot=&new_snapshot=` covers objects (added, removed, changed incl. renames matched on
  SID), relationships by category, tier-0 changes, attack paths (appeared, resolved, score changes) by signature,
  exposure changes, environment risk change and a plain-language summary.
* Primary-group memberships of created or deleted accounts are reported as implied by the account change, not as
  membership changes.

**3.8 Reporting (done 2026-11-18)**
* One data model (`reporting/model.py`) is the JSON export and feeds both renderers, so the formats cannot disagree.
* The HTML uses Jinja2 with autoescape and StrictUndefined. It is self-contained (no scripts or external resources)
  and is always downloaded as an attachment.
* The PDF uses ReportLab. All directory-derived text is XML-escaped before reaching `Paragraph` markup (tested with
  script, font and img payloads in an account name). A Unicode TTF (Arial/Consolas on Windows, DejaVu on Linux) is
  registered when available, with ASCII fallbacks otherwise.
* Section 12 always includes a fresh minimum-cut simulation, so the headline recommendation is shown to work.
* Rendered pages were inspected visually; that found severity colours not reaching table cells, now fixed.
* **Next: Phase 4, the frontend** (React, TypeScript, Vite, Tailwind, Cytoscape.js), with 10 pages on top of this API.

**Phase 4 Frontend (done 2026-11-18)**
* React 19, TypeScript 7 (strict), Vite 8, Tailwind 4, Cytoscape.js and Recharts. Ten pages plus login, code-split per
  page (initial JS 286 kB, or 91 kB gzipped; Cytoscape and charts load only where used).
* The session cookie is HttpOnly. The CSRF token is held in memory only and re-issued after a reload. The only
  `localStorage` content is the selected snapshot and analysis IDs.
* The backend serves the build from its 404 handler (no catch-all route), so API routes are never shadowed and route
  order does not matter. Assets are cached as `immutable`, and `index.html` and the API use `no-store`.
* Verification: headless Edge, driven over the DevTools protocol, logged in through the real form and visited every
  page with interactions (path selection, identity search and neighbourhood graph, comparison). It reported no
  JavaScript exceptions and no CSP violations. The screenshots led to three visual fixes: graph over-zoom, badge
  alignment and duplicate simulator suggestions.

**Phases 6, 7 and 9 Validation, docs and acceptance (done 2026-11-18)**
* Fresh clone in an empty folder: `scripts\setup.ps1 -Dev` finished in 78 s (exit 0) and handled Smart App Control
  automatically. All 326 tests passed in the new copy. `load_sample_data.ps1` imported and analysed both samples, the
  UI and client routes were served, login worked, health was `ok` with no warnings (the generated secret was in use),
  and RSS was 119 MB.
* Docs: README, INSTALLATION, TESTING, TROUBLESHOOTING, an updated DEVELOPER_GUIDE, and ARCHITECTURE §12 (revised
  decisions).
* Not verified on this machine: the Docker image (no Docker installed) and Linux/macOS installs. These are documented
  as untested.
