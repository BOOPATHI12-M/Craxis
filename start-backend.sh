#!/usr/bin/env bash
# Starts the Craxis backend on macOS or Linux.
# Usage: ./start-backend.sh [--intel]
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.10+ is required." >&2
  exit 1
fi

if ! python3 -c "import flask, sklearn, joblib, flask_cors, pandas, numpy" 2>/dev/null; then
  echo "Installing Python dependencies..."
  python3 -m pip install -r ml/requirements.txt
fi

if [ "${1:-}" = "--intel" ]; then
  export AIPHISH_ENABLE_INTEL=1
  echo "Domain intelligence lookups are ENABLED (hostnames are sent to public registries)."
fi

echo "Starting backend on http://127.0.0.1:5000 (Ctrl+C to stop)"
exec python3 ml/app.py
