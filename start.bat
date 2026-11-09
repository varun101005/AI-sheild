@echo off
setlocal

REM -----------------------------------------------------------------------
REM CodeShieldAI - Windows startup script
REM FIX (compatibility): pre-flight checks for Python, git, and venv errors.
REM -----------------------------------------------------------------------

echo === CodeShieldAI ===
echo.

REM --- Check Python ---
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found on PATH.
    echo         Install Python 3.10 or later from https://python.org and try again.
    pause
    exit /b 1
)

REM --- Check git (optional, only needed for GitHub scanning) ---
git --version >nul 2>&1
if errorlevel 1 (
    echo [WARN]  git not found on PATH. GitHub repo scanning will be disabled.
    echo         Install Git from https://git-scm.com if you need that feature.
    echo.
)

REM --- Move into the backend directory ---
cd /d "%~dp0backend"

REM --- Create virtual environment if missing ---
if not exist .venv (
    echo [INFO]  Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        echo         Make sure the 'venv' module is available (python -m venv --help).
        pause
        exit /b 1
    )
)

REM --- Activate virtual environment ---
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment.
    pause
    exit /b 1
)

REM --- Install / update dependencies ---
echo [INFO]  Installing dependencies...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed. Check your internet connection and try again.
    pause
    exit /b 1
)

REM --- Create .env from example if not present ---
if not exist .env (
    copy .env.example .env >nul
    echo [INFO]  Created backend\.env from .env.example.
    echo         Add your LLM API key to backend\.env to enable AI features.
    echo.
)

echo [INFO]  Starting server...
echo         Open http://localhost:8000 in your browser.
echo         Press Ctrl+C to stop.
echo.

python -m uvicorn app.main:app --port 8000

endlocal
