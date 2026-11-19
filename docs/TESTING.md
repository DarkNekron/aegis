# AEGIS — Testing

```powershell
cd backend
.venv\Scripts\python.exe -m pytest              # 338 tests, about 1 minute
.venv\Scripts\python.exe -m pytest --cov        # with coverage (97%)
.venv\Scripts\ruff.exe check app tests migrations ..\scripts
cd ..\frontend; npm run typecheck; npm run build
```
Use `python -m pytest`, not `pytest.exe`. Windows Smart App Control blocks pip's unsigned launcher executables.

## What the suite covers

| Area | Files | Highlights |
|---|---|---|
| Foundation | `test_config`, `test_resources`, `test_jobs`, `test_database`, `test_api_system` | Limits, RAM guards, job cancellation, timeouts and back-pressure, migrations match models, log redaction |
| Ingestion | `test_ingestion_*` | Every SharpHound field and relationship direction. Traversal, symlink, bomb, encrypted and forged-size ZIPs. Malformed records, rollback, limits, hostile strings. |
| Sample data | `test_sample_datasets` | An **independent reference implementation** (`tests/reference_paths.py`) re-derives the hand-written ground truth. A drift test keeps the files identical to the generator. |
| Graph engine | `test_graph_engine` | Rules per target kind, tier-0 reasons, DCSync derivation, views never mutate the graph, cache single-flight |
| Path engine | `test_path_engine` | Exact ground-truth paths, choke point, unique minimum cut, simulations. **40 random graphs vs NetworkX and brute-force oracles.** |
| Risk | `test_risk_engine` | Worked example exact (81.90), breakdowns sum to scores, conditional cap, validation rescoring |
| Simulation | `test_simulation` | Ground-truth what-ifs, every action type, graph and database unchanged, **environment risk never rises when any relationship is removed** |
| Comparison | `test_comparison` | corp-small → v2 ground truth, symmetry, renames matched on SID |
| Reporting | `test_reporting` | 13 sections, real numbers, hostile names inert in HTML and PDF, attachment downloads, path confinement |
| Security | `test_security`, `test_first_run` | First-run setup code (single use, rate-limited, cross-origin refused, no default accounts), hashing, lockout, rate limits, session expiry and revocation, CSRF and Origin checks, roles for every user, audit |
| API & UI serving | `test_api`, `test_spa` | Upload → job → analysis → paths → evidence → graph → dashboard. Viewer is read-only. SPA never shadows the API. |

## Writing tests
* Fixtures in `tests/conftest.py` give each test a temporary data directory, a deterministic `FakeProbe` for
  resources, and logged-in clients (`viewer_client`, `admin_client`, `add_user`, `login`).
* `tests/bh_builders.py` builds SharpHound-shaped files. Use it instead of hand-writing JSON.
* A new algorithm needs an oracle: a ground-truth dataset or a comparison against an independent implementation.

## Benchmarks
See [BENCHMARKS.md](BENCHMARKS.md). `scripts/bench_ingestion.py` and `scripts/bench_analysis.py` refuse to run when free
RAM is low, and they measure in fresh processes.
