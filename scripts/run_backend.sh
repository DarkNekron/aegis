#!/usr/bin/env bash
# Starts AEGIS (single process, loopback only) on Linux / macOS.
#
#   ./scripts/run_backend.sh              # http://127.0.0.1:8000
#   ./scripts/run_backend.sh --port 8001  # another port
#   ./scripts/run_backend.sh --reload     # auto-reload while editing code (development only)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/backend/.venv/bin/python"
[[ -x "$PY" ]] || { echo "Virtual environment missing. Run ./scripts/setup.sh first." >&2; exit 1; }

PORT=8000
EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --reload) EXTRA+=(--reload --reload-dir app); shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

cd "$ROOT/backend"
exec "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT" ${EXTRA[@]+"${EXTRA[@]}"}
