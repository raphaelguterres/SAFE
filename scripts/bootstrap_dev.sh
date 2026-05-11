#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

echo "SAFE bootstrap: validating Python..."
PYTHON_BIN="${PYTHON:-python3}"
"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required")
print(f"Python {sys.version_info.major}.{sys.version_info.minor} OK")
PY

if [ ! -d ".venv" ]; then
  echo "Creating .venv..."
  "$PYTHON_BIN" -m venv .venv
fi

if [ -x ".venv/bin/python" ]; then
  VENV_PY=".venv/bin/python"
else
  VENV_PY=".venv/Scripts/python.exe"
fi

if [ "${SKIP_INSTALL:-0}" != "1" ]; then
  echo "Installing requirements..."
  "$VENV_PY" -m pip install --upgrade pip
  "$VENV_PY" -m pip install -r requirements.txt
fi

test -f ".env.example" || { echo ".env.example is missing"; exit 1; }

echo "Running SAFE quick release checks..."
"$VENV_PY" scripts/release_check.py --quick
"$VENV_PY" scripts/template_check.py
"$VENV_PY" scripts/branding_check.py

echo "SAFE dev environment is ready."
