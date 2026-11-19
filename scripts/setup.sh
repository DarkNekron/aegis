#!/usr/bin/env bash
# One-time setup of AEGIS on Linux / macOS: backend venv + pinned dependencies, frontend build, and a local .env
# with a generated secret key. Runs as a normal user and changes nothing outside the repository folder.
#
#   ./scripts/setup.sh          # normal install
#   ./scripts/setup.sh --dev    # also install test/development tools
#
# There are no default credentials: on first start AEGIS asks you, in the browser, to create your own administrator
# account using a one-time setup code printed in the terminal.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REQ="requirements.txt"
[[ "${1:-}" == "--dev" ]] && REQ="requirements-dev.txt"

echo "== Backend =="
PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
  for candidate in python3.12 python3; do
    if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys; sys.exit(sys.version_info[:2] != (3, 12))'; then
      PYTHON="$candidate"; break
    fi
  done
fi
[[ -n "$PYTHON" ]] || { echo "Python 3.12 is required (e.g. sudo apt install python3.12 python3.12-venv)." >&2; exit 1; }

VENV="$ROOT/backend/.venv"
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "Creating virtual environment with $PYTHON ..."
  "$PYTHON" -m venv "$VENV"
fi
echo "Installing $REQ ..."
"$VENV/bin/python" -m pip install -q --disable-pip-version-check -r "$ROOT/backend/$REQ"
"$VENV/bin/python" -m pip check

echo "== Frontend =="
command -v npm >/dev/null || { echo "Node.js >= 20.19 (with npm) is required: https://nodejs.org" >&2; exit 1; }
(cd "$ROOT/frontend" && npm ci --no-fund --no-audit && npm run build)

echo "== Configuration =="
if [[ ! -f "$ROOT/.env" ]]; then
  SECRET="$("$VENV/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
  sed "s|^AEGIS_SECRET_KEY=.*$|AEGIS_SECRET_KEY=$SECRET|" "$ROOT/.env.example" > "$ROOT/.env"
  chmod 600 "$ROOT/.env"
  echo "Created .env with a generated AEGIS_SECRET_KEY (keep this file private)."
else
  echo ".env already exists; left unchanged."
fi

echo
echo "Done. Start AEGIS with:  ./scripts/run_backend.sh"
echo "Then open http://127.0.0.1:8000 and create your administrator account with the setup code shown in the terminal."
