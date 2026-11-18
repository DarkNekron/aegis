# AEGIS — Development Roadmap

Each stage ends with passing tests and a Git commit. A stage is not "done" while it has placeholder functions.

Status legend: ✅ done · 🔄 in progress · ⏳ pending

| # | Stage | Deliverables | Exit criteria | Status |
|---|---|---|---|---|
| 0 | System inspection | `SYSTEM_ASSESSMENT.md` | Report written from measured data | ✅ |
| 1 | Architecture | `ARCHITECTURE.md`, `DEPENDENCIES.md`, this roadmap | Reviewed by owner | 🔄 written, awaiting owner review |
| 2 | Environment | venv, pinned requirements, Vite/React/Tailwind scaffold, `.env.example`, install report | Import checks and `tsc` pass | ✅ |
| 3.0 | Backend foundation | settings, DB/ORM models, Alembic, resource manager, job runner, health endpoint | Unit tests for limits, jobs and cancellation | ⏳ |
| 3.1 | Module 1 — Ingestion | BloodHound CE/SharpHound JSON+ZIP, custom JSON, CSV; safe ZIP; normaliser; import summary | Tests: valid, malformed, ZIP traversal, ZIP bomb, duplicates | ⏳ |
| 3.2 | Synthetic datasets | generator + 3 fixed datasets with documented ground truth | Datasets validate against the ingestion engine | ⏳ |
| 3.3 | Module 2 — Graph construction | rules table, builder, tier-0 classifier, DCSync derivation, graph cache | Tests: edge semantics, unknown kinds not traversed | ⏳ |
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
