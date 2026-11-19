# AEGIS — Installation

AEGIS runs as **one local process**. FastAPI serves both the API and the built web UI, with a SQLite database
file. Nothing else needs to run.

## Requirements
| Component | Version | Notes |
|---|---|---|
| Python | 3.12 (python.org build recommended) | 3.12 has the broadest binary-wheel coverage |
| Node.js | ≥ 20.19 or ≥ 22.12 | Only to build the UI. Not needed at runtime. |
| Git | any recent | |
| RAM | 1 GB free for typical domains | See [SYSTEM_ASSESSMENT.md](SYSTEM_ASSESSMENT.md) and [BENCHMARKS.md](BENCHMARKS.md) |
| Admin rights | **not required** | Everything installs inside the project folder |

## Windows (tested)
```powershell
git clone <repository-url> aegis
cd aegis
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```
`setup.ps1`:
1. creates `backend\.venv` with Python 3.12 and installs the pinned requirements (`-Dev` adds test tools)
2. detects Windows **Smart App Control** blocking SQLAlchemy's unsigned compiled extension and, if needed, reinstalls
   the same version as pure Python
3. runs `npm ci` and builds the UI into `frontend\dist`
4. creates `.env` from `.env.example` with a randomly generated `AEGIS_SECRET_KEY` (keep `.env` private)
5. optional: `-Admin <name>` creates an administrator from the terminal instead (the password is prompted for, never an argument)

`-ExecutionPolicy Bypass` applies only to that one PowerShell process. It changes no system setting.

Start AEGIS and open <http://127.0.0.1:8000>:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_backend.ps1
```

### First run: create your own administrator
There are **no default credentials**. On a new installation, AEGIS prints a box like this in the server window:
```
================================================================
  AEGIS FIRST-RUN SETUP
  No accounts exist yet. Open AEGIS in your browser and enter this
  one-time setup code to create your administrator account:

      N6ZS-Z2D7-8Y3P-3YWT
================================================================
```
1. Open <http://127.0.0.1:8000>. Instead of the sign-in form you see **Create your administrator account**.
2. Enter the setup code, then choose your own username and password (12+ characters). AEGIS signs you in.
3. Add colleagues under **Settings → Users** as Viewer, Analyst or Admin.

The code is also saved to `data\first-run-setup-code.txt` in case the window is hidden. It works only once and is
deleted after setup. Until setup is done, every restart issues a new code. Once an account exists, this screen never
appears again.

Optional synthetic sample data (two snapshots, analysed):
```powershell
powershell -ExecutionPolicy Bypass -File scripts\load_sample_data.ps1
```

**Measured on the development laptop (fresh clone):** setup took 78 s. The 326 tests passed in the new copy. Sample data loaded,
login worked, the UI was served and the server used 119 MB.

## Linux / macOS
Prerequisites: Python 3.12 (with `venv`), Node.js ≥ 20.19, Git, and on Linux `fonts-dejavu-core` for PDF reports.
The README has copy-paste commands for Ubuntu/Debian, Fedora and macOS.

```bash
git clone https://github.com/DarkNekron/aegis.git && cd aegis
chmod +x scripts/*.sh
./scripts/setup.sh               # venv + pinned deps, UI build, .env with a generated secret key (--dev adds test tools)
./scripts/load_sample_data.sh    # optional: synthetic sample environment
./scripts/run_backend.sh         # http://127.0.0.1:8000  (--port N, --reload)
```
The shell scripts are the counterparts of the PowerShell scripts. They are syntax-checked but have not yet been run
on a real Linux or macOS machine. If one fails, the equivalent manual steps are:
```bash
python3.12 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements.txt
(cd frontend && npm ci && npm run build)
cp .env.example .env    # set AEGIS_SECRET_KEY: python -c "import secrets; print(secrets.token_urlsafe(48))"
cd backend
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Then open the page and complete first-run setup with the code printed in the terminal.

## Docker (optional, untested here)
`deployment/Dockerfile` and `docker-compose.yml` build a non-root, read-only container. It has all capabilities
dropped, DejaVu fonts for PDF reports and a 2 GB memory limit, and is published on `127.0.0.1:8000` only.
```bash
docker compose up --build -d
docker compose logs aegis | grep -A4 "FIRST-RUN SETUP"   # the one-time setup code for the first admin
```
The files were written and reviewed but **not built**, because the development machine has no Docker. Treat the first
build as a test.

## Configuration
All settings are environment variables prefixed `AEGIS_`, read from `.env`. The defaults suit a 16 GB laptop; see
the annotated [`.env.example`](../.env.example). The most important ones:

| Setting | Default | Purpose |
|---|---|---|
| `AEGIS_SECRET_KEY` | (required in production) | At least 32 characters. Setup generates one. |
| `AEGIS_ENV` | development | `production` disables the API docs and requires the secret key |
| `AEGIS_HOST` / `AEGIS_PORT` | 127.0.0.1 / 8000 | Keep loopback unless you add a TLS reverse proxy |
| `AEGIS_COOKIE_SECURE` | false | Set `true` behind HTTPS |
| `AEGIS_DATA_DIR` | `data` | Database, reports and temporary uploads (sensitive) |
| `AEGIS_MIN_FREE_RAM_MB` | 768 | Heavy jobs are refused below this |
| `AEGIS_MAX_GRAPH_NODES` / `_EDGES` | 150 000 / 1 500 000 | Snapshot size limits |
| `AEGIS_MAX_UPLOAD_MB` | 512 | Per upload, enforced while streaming |

## Upgrading
Pull the new version, rerun `scripts\setup.ps1` (it is idempotent) and restart. Database migrations run automatically
at start-up.

## Uninstalling
Stop the server and delete the folder. AEGIS writes nothing outside it except the pip and npm download caches in your
user profile.
