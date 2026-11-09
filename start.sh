#!/usr/bin/env bash
# CodeShieldAI - Mac/Linux startup script
# FIX (compatibility): pre-flight checks for Python 3.10+, git, and venv errors.
set -euo pipefail

cd "$(dirname "$0")"

echo "=== CodeShieldAI ==="
echo

# --- Check Python ---
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found on PATH."
    echo "        Install Python 3.10 or later and try again."
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(sys.version_info[:2])")
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"; then
    echo "[INFO]  Python OK ($PY_VER)"
else
    echo "[ERROR] Python 3.10+ required (found $PY_VER)."
    exit 1
fi

# --- Check git (optional) ---
if ! command -v git &>/dev/null; then
    echo "[WARN]  git not found. GitHub repo scanning will be disabled."
    echo "        Install Git from https://git-scm.com if you need that feature."
    echo
fi

# --- Move into backend ---
cd backend

# --- Create virtual environment if missing ---
if [ ! -d .venv ]; then
    echo "[INFO]  Creating virtual environment..."
    python3 -m venv .venv || { echo "[ERROR] venv creation failed."; exit 1; }
fi

# --- Activate ---
# shellcheck disable=SC1091
source .venv/bin/activate

# --- Install / update dependencies ---
echo "[INFO]  Installing dependencies..."
pip install -q -r requirements.txt || { echo "[ERROR] pip install failed."; exit 1; }

# --- Create .env from example if not present ---
if [ ! -f .env ]; then
    cp .env.example .env
    echo "[INFO]  Created backend/.env from .env.example."
    echo "        Add your LLM API key to backend/.env to enable AI features."
    echo
fi

echo "[INFO]  Starting server..."
echo "        Open http://localhost:8000 in your browser."
echo "        Press Ctrl+C to stop."
echo

python -m uvicorn app.main:app --port 8000
