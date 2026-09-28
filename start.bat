@echo off
REM ─────────────────────────────────────────────────────────────────
REM  Swarm Security Scanner — Full Stack Launcher
REM  Starts: FastAPI backend (port 8000) + Vite dev server (port 5173)
REM ─────────────────────────────────────────────────────────────────

echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║      Antigravity Swarm Security Scanner                  ║
echo ║      Multi-Agent Security Analysis Platform              ║
echo ╚══════════════════════════════════════════════════════════╝
echo.

REM ─── Check Ollama ───
echo [1/3] Checking Ollama availability...
curl -s http://127.0.0.1:11434/api/tags >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARN] Ollama is not running at localhost:11434.
    echo         Run 'ollama serve' in a separate terminal before starting a scan.
    echo.
) else (
    echo  [OK]   Ollama detected.
    echo.
)

REM ─── Load .env if present ───
echo [1.5/3] Loading .env ...
if exist "%~dp0.env" (
    for /f "usebackq tokens=1,* eol=# delims==" %%a in ("%~dp0.env") do (
        set "%%a=%%b"
    )
    echo  [OK]   Loaded .env
) else (
    echo  [INFO] No .env found.
)
echo.

REM ─── Install Python deps if needed ───
echo [2/3] Checking Python dependencies...
pip show fastapi uvicorn >nul 2>&1
if %errorlevel% neq 0 (
    echo  [INFO] Installing Python deps: fastapi uvicorn python-multipart
    pip install fastapi uvicorn python-multipart --quiet
)
echo  [OK]   Python deps ready.
echo.

REM ─── Launch Backend ───
echo [3/3] Starting FastAPI backend on http://localhost:8000 ...
start "Swarm-Backend" /MIN cmd /c "cd /d %~dp0 && python -m uvicorn backend.main:app --reload --port 8000 --log-level info"

timeout /t 2 >nul

REM ─── Launch Frontend ───
echo       Starting Vite dev server on http://localhost:5173 ...
start "Swarm-Frontend" /MIN cmd /c "cd /d %~dp0frontend && npm run dev"

timeout /t 3 >nul

echo.
echo ✓  Both servers are starting up.
echo.
echo    Backend:   http://localhost:8000
echo    Frontend:  http://localhost:5173
echo    API Docs:  http://localhost:8000/docs
echo.
echo    Open http://localhost:5173 in your browser to use the dashboard.
echo    Press any key to open it now...
pause >nul
start http://localhost:5173
