#!/usr/bin/env bash
# Imports the synthetic sample datasets (corp-small, corp-small-v2) and analyses them, so every page of the UI has
# data to show. Everything created is clearly marked as sample data. Linux / macOS counterpart of load_sample_data.ps1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/backend/.venv/bin/python"
[[ -x "$PY" ]] || { echo "Virtual environment missing. Run ./scripts/setup.sh first." >&2; exit 1; }

cd "$ROOT/backend"
for name in corp-small corp-small-v2; do
  out="$("$PY" -m app.cli create-snapshot "Sample: $name" --sample)"
  id="$(sed -n 's/.*Created snapshot \([0-9]*\).*/\1/p' <<<"$out")"
  [[ -n "$id" ]] || { echo "could not create snapshot" >&2; exit 1; }
  "$PY" -m app.cli import "$id" "../sample_data/$name/$name.zip" >/dev/null
  "$PY" -m app.cli analyze "$id" --top 3
done
