# AEGIS — System Assessment (Phase 0)

**Assessment date:** 2026-11-18
**Method:** read-only inspection with `Get-CimInstance`, `Get-PhysicalDisk`, `Get-Process`, `Get-Counter`, `nvidia-smi` and tool version queries. Nothing was installed or changed during inspection.

> Identifying details (Windows username, device ID, product ID) are deliberately left out of this
> file because it is committed to a public repository.

---

## 1. Hardware

| Component | Value |
|---|---|
| Machine | Dell G15 5530 (laptop) |
| CPU | 13th Gen Intel Core i7-13650HX, base 2.60 GHz |
| Physical cores | 14 (6 Performance + 8 Efficiency) |
| Logical processors | 20 |
| Installed RAM | 16 GB DDR5-4800 (15.7 GB usable) |
| RAM free at idle (measured) | **2.0 – 2.6 GB** |
| Page file | 22 GB on D: |
| Discrete GPU | NVIDIA GeForce RTX 3050 Laptop, 6 GB VRAM (driver 591.59) |
| Integrated GPU | Intel UHD Graphics |
| Disk | SK hynix BC901 1 TB **NVMe SSD** |
| Free space C: | 54.3 GB |
| Free space D: (project drive) | 442.3 GB |
| Architecture | x64 (64-bit) |

## 2. Operating system

| Item | Value |
|---|---|
| OS | Windows 11 Home Single Language |
| Version / build | 10.0.26300 |
| Kernel | Windows NT 10.0.26300 |
| Shells | Windows PowerShell 5.1, Git Bash (PowerShell 7 not installed) |
| Privileges | **Standard user. Not running elevated.** |
| Security software | Kaspersky (active) and Windows Defender |

## 3. Development environment

| Tool | Status |
|---|---|
| Python 3.12.10 (python.org install) | Installed, default `python` on PATH |
| Python 3.13.14 (Microsoft Store build) | Installed, default for the `py` launcher |
| pip | 25.0.1 (for Python 3.12) |
| Global pip packages | About 18. These were not touched. |
| Node.js | v26.13.0 |
| npm | 11.20.0 |
| Git | 2.56.1.windows.1 |
| VS Code | Installed |
| Docker | **Not installed** |
| PostgreSQL | **Not installed** |
| WSL | **Not installed** |
| Neo4j / Redis | Not installed |
| uv / conda | Not installed |
| Existing virtual environments | None in the project tree. The project directory was empty. |

## 4. Resource utilisation at the time of inspection

| Metric | Value |
|---|---|
| CPU utilisation (3 × 1 s samples) | 25 %, 17 %, 12 % |
| Free physical RAM | 2.0 – 2.6 GB |
| Largest consumers | VS Code 2.4 GB (13 procs), Chrome 2.0 GB (13 procs), svchost 1.8 GB, Memory Compression 0.66 GB, Kaspersky 0.42 GB, Edge + WebView2 0.7 GB |

**Key takeaway:** the CPU has plenty of headroom. **Memory is the binding constraint.**
In a normal working session, with an editor, a browser and other development tools open, AEGIS should plan for
roughly **1.0 – 1.5 GB in total** across the backend, the browser tab and any build tooling.

## 5. Potential compatibility issues

1. **Two Python interpreters.** `py` defaults to the Microsoft Store 3.13 build, which has
   sandboxed AppData path redirection. **Decision:** create the venv explicitly with
   `py -3.12 -m venv`. Python 3.12 has the broadest binary-wheel coverage on Windows.
2. **No administrator rights.** Everything must install per-user or inside the project
   (venv, `node_modules`). Nothing in the plan needs elevation.
3. **No Docker or WSL.** Docker Desktop requires WSL2 and admin rights to install, and it would
   reserve 2 GB or more of RAM. **Decision:** local, Docker-free development is the primary mode. A
   Dockerfile and compose file are provided for portability, but they are marked untested on this machine.
4. **Kaspersky / Defender.** Real-world SharpHound *binaries* are flagged as hacktools. AEGIS
   never downloads or runs collectors. It only parses JSON/ZIP output. Synthetic datasets are
   plain JSON, so AV interference is unlikely. Real exports should be stored outside synced folders.
5. **Node 26.** This is a current release. Vite 7 needs Node ≥ 20.19 or ≥ 22.12, so it is compatible.
6. **C: has 54 GB free.** pip and npm caches live on C:. The expected cache growth is under 1 GB.
   Project data lives on D:.
7. **Windows path length.** Deep `node_modules` paths are fine under `D:\Creation\AEGIS`.

## 6. Recommendations derived from this assessment

### Architecture
* Use a **single backend process** (FastAPI + Uvicorn, 1 worker) that serves the API and the
  pre-built frontend. No separate web server, broker or cache.
* Use **SQLite in WAL mode** for persistence. The schema stays PostgreSQL-compatible through SQLAlchemy 2.
* Use **NetworkX** for the in-memory graph, with integer node keys and slim edge attributes. Full evidence
  stays in SQLite and is fetched lazily.
* **Remediation simulation uses filtered graph *views*, not copies.** This costs almost no
  memory, and the original graph cannot be modified.
* **The GPU is not used.** None of the graph algorithms involved benefit enough to justify CUDA dependencies.

### Default resource limits (configurable in `.env`)

| Setting | Default | Rationale |
|---|---|---|
| `AEGIS_MAX_ANALYSIS_WORKERS` | 1 | Graph analysis is CPU-bound Python under the GIL. More workers would duplicate the graph in RAM. |
| `AEGIS_MAX_LIGHT_WORKERS` | 2 | Imports and small jobs. Heavy analysis stays at 1 worker, so two graph traversals never run at once. |
| `AEGIS_MAX_PENDING_JOBS` | 8 | Back-pressure: extra submissions are refused with HTTP 503 |
| `AEGIS_MIN_FREE_DISK_MB` | 1024 | Imports and reports refused below this |
| `AEGIS_JOB_TIMEOUT_SECONDS` | 180 | Long jobs are cancelled cooperatively |
| `AEGIS_MIN_FREE_RAM_MB` | 768 | Heavy jobs are refused (HTTP 503 with an explanation) below this |
| `AEGIS_MAX_GRAPH_NODES` | 150 000 | Roughly a 40k-user domain with computers and groups |
| `AEGIS_MAX_GRAPH_EDGES` | 1 500 000 | About 600 MB of NetworkX at worst |
| `AEGIS_MAX_UPLOAD_MB` | 512 | Per file |
| `AEGIS_MAX_ZIP_UNCOMPRESSED_MB` | 2048 | Guards against ZIP bombs |
| `AEGIS_MAX_ZIP_RATIO` | 100 | Per-member compression-ratio ceiling |
| `AEGIS_MAX_PATH_DEPTH` | 10 hops | |
| `AEGIS_MAX_ALTERNATIVE_PATHS` | 5 per source→target pair | |
| `AEGIS_UI_MAX_ELEMENTS` | 1 500 nodes+edges per render | Keeps the browser tab under about 300 MB |

### Estimated memory use

| Scenario | Backend RSS | Browser tab |
|---|---|---|
| Idle, no dataset loaded | 90 – 140 MB | 80 – 120 MB |
| Synthetic demo set (~500 nodes) | 150 – 200 MB | 120 – 180 MB |
| Mid-size domain (~30k nodes / 300k edges) | 450 – 700 MB | 150 – 300 MB (filtered) |
| Upper limit (150k nodes / 1.5M edges) | 1.2 – 1.6 GB | unchanged (filtered) |

The Vite dev server adds about 150–250 MB, but only during frontend development. For everyday use, the
frontend is built once (`npm run build`) and served by the backend, so no Node process runs.
These are planning estimates. Measured figures will be recorded in `docs/BENCHMARKS.md` during Phase 6.

### Estimated storage
* Python venv: about 250 MB. `node_modules`: about 250 MB. Built frontend: about 3 MB.
* SQLite: about 1–2 KB per relationship with evidence, so about 300–600 MB for a 300k-edge snapshot.
* Generated reports: under 5 MB each.

### CPU
* Uvicorn uses 1 worker process. Analysis uses 1 dedicated thread, and ingestion parsing uses 1 thread.
* Test runs use `pytest` serially (no `-n auto`). That is fast enough and avoids 20 parallel interpreters.

### Recommended development configuration
* Python 3.12 venv at `backend/.venv`
* Run backend: `uvicorn app.main:app --port 8000` (no `--reload` unless editing backend code)
* Frontend: `npm run dev` only while working on the UI; otherwise `npm run build`
* Close unused Chrome tabs before importing very large datasets
