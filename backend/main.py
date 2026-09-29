"""
Swarm Security Scanner — Production FastAPI Backend
===================================================
Production-hardened API with:
  • Authentication & RBAC (Bearer token / X-API-Key / query token)
  • Durable SQLite state persistence across restarts
  • Strict boundary validation (path traversal, SSRF prevention)
  • Hardened Docker sandbox execution with network isolation
  • Strict HMAC-SHA256 GitHub webhook verification
  • Run concurrency control and graceful shutdown handling
"""

from __future__ import annotations

import asyncio
import json
import os
from dotenv import load_dotenv
load_dotenv()
import signal
import subprocess
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, Optional, List, Any

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Header, Security, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# Security & DB modules
from .security import (
    require_api_key,
    validate_scan_target,
    validate_sandbox_target_url,
    verify_github_webhook_signature,
)
from . import database as db

async def _check_models_ready(model: str, challenger_model: str):
    import urllib.request
    import urllib.error
    requested_models = [name for name in (model, challenger_model) if name]
    groq_models = [name for name in requested_models if name.startswith("groq/")]
    missing_groq_key = bool(groq_models and not os.environ.get("GROQ_API_KEY"))
    if missing_groq_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GROQ_API_KEY is required for the selected Groq model. Repository code will be sent to Groq.",
        )
    local_models = [name for name in requested_models if not name.startswith("groq/")]
    ollama_url = os.environ.get("OLLAMA_URL")
    if not ollama_url or not local_models:
        return
    try:
        req = urllib.request.Request(f"{ollama_url}/api/tags")
        def fetch():
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read())
        data = await asyncio.to_thread(fetch)
        models = [m.get("name") for m in data.get("models", [])]
        missing = []
        for required in local_models:
            if required and not any(m == required or m.startswith(f"{required}:") for m in models):
                missing.append(required)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Required models not found in Ollama: {', '.join(missing)}. Please run 'docker compose exec ollama ollama pull <model>' first.",
            )
    except urllib.error.URLError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ollama service is unreachable. Ensure the ollama container is running."
        )

# ---------------------------------------------------------------------------
# Concurrency & State Management
# ---------------------------------------------------------------------------

MAX_CONCURRENT_SCANS = int(os.getenv("SWARM_MAX_CONCURRENT_SCANS", "3"))
_scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

class RunState:
    """Thread-safe in-memory stream buffer and process handle for active runs."""

    def __init__(self, run_id: str, request_meta: dict):
        self.run_id = run_id
        self.meta = request_meta
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.process: Optional[subprocess.Popen] = None
        self.status: str = "running"
        self.started_at: float = time.time()

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "started_at": self.started_at,
            **self.meta,
        }

_runs: Dict[str, RunState] = {}
_runs_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Lifespan: graceful shutdown terminates active subprocesses
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.mark_interrupted_runs()
    yield
    with _runs_lock:
        for state in _runs.values():
            if state.process and state.process.poll() is None:
                try:
                    if sys.platform == "win32":
                        state.process.terminate()
                    else:
                        os.killpg(os.getpgid(state.process.pid), signal.SIGTERM)
                except Exception:
                    pass

# ---------------------------------------------------------------------------
# App Bootstrap & CORS
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Swarm Security Scanner API",
    version="1.0.0",
    description="Multi-Agent AI Security Scanner Platform with Consensus Triage",
    lifespan=lifespan,
)

# CORS configuration
raw_origins = os.getenv("SWARM_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173")
allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    model: str = Field(default="llama3.2", max_length=80)
    challenger_model: str = Field(default="qwen2.5-coder:7b", max_length=80)
    cycle: str = Field(default="22", pattern=r"^(11|13a|13b|14|15|16|17|18|19|20|21|22)$")
    workers: int = Field(default=5, ge=1, le=10)
    challengers: int = Field(default=2, ge=1, le=2)

class RepoScanRequest(BaseModel):
    repo: str = Field(..., min_length=1, max_length=500, description="Git HTTPS URL or validated local path")
    model: str = Field(default="llama3.2", max_length=80)
    challenger_model: str = Field(default="qwen2.5-coder:7b", max_length=80)
    workers: int = Field(default=5, ge=1, le=5)
    challengers: int = Field(default=2, ge=1, le=2)
    sast_tools: list[str] = Field(default=["bandit", "semgrep"])
    no_sast: bool = Field(default=False)
    max_chunks: int = Field(default=20, ge=0, le=1000, description="Discovery chunk limit; 0 scans all eligible chunks")
    sarif_file: Optional[str] = Field(default=None, description="Path to a SARIF file to ingest")

class FeedbackRequest(BaseModel):
    finding_idx: int
    human_verdict: str

class RemediateRequest(BaseModel):
    finding_id: str
    file_path: str
    line_number: int
    severity: str
    description: str
    code_snippet: str
    model: str = "qwen2.5-coder:7b"

class VerifyRequest(BaseModel):
    finding_id: str
    file_path: str
    description: str
    code_snippet: str
    model: str = "qwen2.5-coder:7b"
    target_url: str = "http://localhost:5000"

# ---------------------------------------------------------------------------
# Background Process Runners
# ---------------------------------------------------------------------------

async def _run_swarm(run_id: str, req: ScanRequest, loop: asyncio.AbstractEventLoop):
    state = _runs[run_id]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["SWARM_STRUCTURED_OUTPUT"] = "1"

    script_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "cycle11_ollama_swarm",
        "run_cycle11.py",
    )

    cmd = [
        sys.executable, "-u", script_path,
        "--cycle", req.cycle,
        "--model", req.model,
        "--challenger-model", req.challenger_model,
        "--workers", str(req.workers),
        "--challengers", str(req.challengers),
    ]

    ollama_url = os.environ.get("OLLAMA_URL")
    if ollama_url:
        cmd.extend(["--url", ollama_url])

    def _reader():
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=os.path.dirname(os.path.dirname(__file__)),
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
                start_new_session=True if sys.platform != "win32" else False,
            )
            state.process = process

            for raw_line in iter(process.stdout.readline, ""):
                if not raw_line:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                if not line.startswith("{"):
                    line = json.dumps({"type": "SYSTEM", "agent": "runner", "content": line})
                
                # Preserve original structured JSON
                try:
                    payload = json.loads(line)
                    db.append_log(run_id, payload.get("type", "SYSTEM"), payload.get("agent", "runner"), line)
                except Exception:
                    db.append_log(run_id, "SYSTEM", "runner", line)

                asyncio.run_coroutine_threadsafe(state.queue.put(line), loop)

            process.stdout.close()
            process.wait()
            exit_code = process.returncode
            event_type = "DONE" if exit_code == 0 else "ERROR"
            done_payload = json.dumps({
                "type": event_type,
                "agent": "runner",
                "content": f"Swarm finished — exit code {exit_code}",
                "exit_code": exit_code,
            })
            db.append_log(run_id, event_type, "runner", done_payload)
            db.update_run_status(run_id, "done" if exit_code == 0 else "error", exit_code)
            asyncio.run_coroutine_threadsafe(state.queue.put(done_payload), loop)
            state.status = "done" if exit_code == 0 else "error"

        except Exception as exc:
            err = json.dumps({"type": "ERROR", "agent": "runner", "content": str(exc)})
            db.append_log(run_id, "ERROR", "runner", str(exc))
            db.update_run_status(run_id, "error", -1)
            asyncio.run_coroutine_threadsafe(state.queue.put(err), loop)
            state.status = "error"

    threading.Thread(target=_reader, daemon=True).start()


async def _run_repo_swarm(run_id: str, req: RepoScanRequest, loop: asyncio.AbstractEventLoop):
    state = _runs[run_id]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["SWARM_STRUCTURED_OUTPUT"] = "1"

    script_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "cycle11_ollama_swarm",
        "run_real_world.py",
    )

    cmd = [
        sys.executable, "-u", script_path,
        "--repo", req.repo,
        "--model", req.model,
        "--challenger-model", req.challenger_model,
        "--workers", str(req.workers),
        "--challengers", str(req.challengers),
        "--max-chunks", str(req.max_chunks),
    ]
    if req.sarif_file:
        sarif_path = os.path.abspath(req.sarif_file)
        cmd.extend(["--sarif-file", sarif_path])
    
    if req.no_sast:
        cmd.append("--no-sast")
    elif req.sast_tools:
        cmd += ["--sast"] + req.sast_tools

    ollama_url = os.environ.get("OLLAMA_URL")
    if ollama_url:
        cmd.extend(["--url", ollama_url])

    def _reader():
        try:
            scan_status = "complete"
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=os.path.dirname(os.path.dirname(__file__)),
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
                start_new_session=True if sys.platform != "win32" else False,
            )
            state.process = process

            for raw_line in iter(process.stdout.readline, ""):
                if not raw_line:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                if not line.startswith("{"):
                    line = json.dumps({"type": "SYSTEM", "agent": "runner", "content": line})
                
                try:
                    payload = json.loads(line)
                    if payload.get("type") == "DONE":
                        scan_status = payload.get("scan_status", scan_status)
                    db.append_log(run_id, payload.get("type", "SYSTEM"), payload.get("agent", "runner"), line)
                except Exception:
                    db.append_log(run_id, "SYSTEM", "runner", line)

                asyncio.run_coroutine_threadsafe(state.queue.put(line), loop)

            process.stdout.close()
            process.wait()
            exit_code = process.returncode
            run_status = "error" if exit_code != 0 else ("partial" if scan_status == "partial" else "done")
            event_type = "DONE" if exit_code == 0 else "ERROR"
            done_payload = json.dumps({
                "type": event_type, "agent": "runner",
                "content": f"Real-world scan {run_status} — exit code {exit_code}",
                "exit_code": exit_code,
                "scan_status": scan_status,
            })
            db.append_log(run_id, event_type, "runner", done_payload)
            db.update_run_status(run_id, run_status, exit_code)
            asyncio.run_coroutine_threadsafe(state.queue.put(done_payload), loop)
            state.status = run_status

        except Exception as exc:
            err = json.dumps({"type": "ERROR", "agent": "runner", "content": str(exc)})
            db.append_log(run_id, "ERROR", "runner", str(exc))
            db.update_run_status(run_id, "error", -1)
            asyncio.run_coroutine_threadsafe(state.queue.put(err), loop)
            state.status = "error"

    threading.Thread(target=_reader, daemon=True).start()

# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    """Unauthenticated health check for load balancers."""
    return {"status": "ok", "message": "Swarm API is running"}

@app.get("/api/health/auth", dependencies=[Security(require_api_key)])
def health_auth():
    """Authenticated health check for connection testing."""
    return {"status": "ok", "message": "Authenticated"}


@app.get("/api/models", dependencies=[Security(require_api_key)])
async def list_ollama_models():
    """Return the models currently installed in the configured Ollama service."""
    import urllib.request

    ollama_url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
    request = urllib.request.Request(f"{ollama_url}/api/tags", method="GET")

    def fetch_models():
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    try:
        payload = await asyncio.to_thread(fetch_models)
    except Exception:
        raise HTTPException(status_code=503, detail="Ollama is unavailable. Check the Ollama service and try again.")

    models = payload.get("models", []) if isinstance(payload, dict) else []
    names = sorted({model.get("name") for model in models if isinstance(model, dict) and model.get("name")})
    return {"models": names}


@app.post("/api/scan", dependencies=[Security(require_api_key)])
async def start_scan(request: ScanRequest):
    await _check_models_ready(request.model, request.challenger_model)
    # Check concurrent scans limit
    active_count = sum(1 for s in _runs.values() if s.status == "running")
    if active_count >= MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached. Please wait for an existing scan to finish.",
        )

    run_id = str(uuid.uuid4())
    loop = asyncio.get_running_loop()
    config = {
        "cycle": request.cycle,
        "model": request.model,
        "challenger_model": request.challenger_model,
        "workers": request.workers,
        "challengers": request.challengers,
    }
    db.create_run(run_id, "synthetic", config)
    state = RunState(run_id, config)
    with _runs_lock:
        _runs[run_id] = state
    asyncio.create_task(_run_swarm(run_id, request, loop))
    return {"status": "started", "run_id": run_id}


@app.post("/api/repo-scan", dependencies=[Security(require_api_key)])
async def start_repo_scan(request: RepoScanRequest):
    await _check_models_ready(request.model, request.challenger_model)
    # Validate scan boundary & SSRF protection
    validated_repo = validate_scan_target(request.repo)
    request.repo = validated_repo

    if request.sarif_file:
        safe_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "uploads"))
        sarif_path = os.path.abspath(request.sarif_file)
        if not sarif_path.startswith(safe_dir + os.sep) or not sarif_path.endswith(".sarif"):
            raise HTTPException(status_code=400, detail="sarif_file must be a .sarif file inside the uploads directory")

    active_count = sum(1 for s in _runs.values() if s.status == "running")
    if active_count >= MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached. Please wait for an existing scan to finish.",
        )

    run_id = str(uuid.uuid4())
    loop = asyncio.get_running_loop()
    config = {
        "scan_type": "real_world",
        "repo": request.repo,
        "model": request.model,
        "challenger_model": request.challenger_model,
        "workers": request.workers,
        "challengers": request.challengers,
        "sast_tools": request.sast_tools,
        "no_sast": request.no_sast,
        "max_chunks": request.max_chunks,
    }
    db.create_run(run_id, "real_world", config)
    state = RunState(run_id, config)
    with _runs_lock:
        _runs[run_id] = state
    asyncio.create_task(_run_repo_swarm(run_id, request, loop))
    return {"status": "started", "run_id": run_id, "scan_type": "real_world"}


@app.get("/api/scan/active", dependencies=[Security(require_api_key)])
def list_active_runs():
    """Return all active and recently completed runs from memory and SQLite DB."""
    persisted_runs = {r["run_id"]: r for r in db.list_runs(limit=30)}
    with _runs_lock:
        for s in _runs.values():
            persisted_runs[s.run_id] = s.to_dict()
    return list(persisted_runs.values())


@app.get("/api/scan/{run_id}", dependencies=[Security(require_api_key)])
def get_run(run_id: str):
    """Return metadata + status for a specific run (checks active memory, falls back to DB)."""
    state = _runs.get(run_id)
    if state:
        return state.to_dict()
    db_run = db.get_run(run_id)
    if db_run:
        return db_run
    raise HTTPException(status_code=404, detail="Run not found")

@app.get("/api/findings", dependencies=[Security(require_api_key)])
def get_findings():
    return db.list_findings()

@app.post("/api/findings", dependencies=[Security(require_api_key)])
def post_findings(findings: List[Dict[str, Any]]):
    db.save_findings(findings)
    return {"status": "ok"}

@app.get("/api/repositories", dependencies=[Security(require_api_key)])
def get_repositories():
    return db.list_repositories()

@app.post("/api/repositories", dependencies=[Security(require_api_key)])
def post_repositories(repos: List[Dict[str, Any]]):
    db.save_repositories(repos)
    return {"status": "ok"}

@app.get("/api/frontend_runs", dependencies=[Security(require_api_key)])
def get_frontend_runs():
    return db.list_frontend_runs()

@app.post("/api/frontend_runs", dependencies=[Security(require_api_key)])
def post_frontend_runs(runs: List[Dict[str, Any]]):
    db.save_frontend_runs(runs)
    return {"status": "ok"}


async def _event_stream(run_id: str) -> AsyncGenerator[str, None]:
    state = _runs.get(run_id)
    seen = set()
    
    # Always replay from DB first to prevent lost logs on reconnect
    logs = db.get_logs_for_run(run_id)
    for entry in logs:
        line = entry['content']
        seen.add(line)
        yield f"data: {line}\n\n"
        
    if not state:
        # Check if completed run exists in DB
        db_run = db.get_run(run_id)
        if not db_run:
            payload = json.dumps({"type": "ERROR", "agent": "server", "content": f"Run {run_id} not found"})
            yield f"data: {payload}\n\n"
        elif db_run['status'] in ('done', 'partial', 'error'):
            # Tell client to close so it doesn't reconnect
            payload = json.dumps({"type": "DONE", "agent": "server", "content": "Replay finished"})
            yield f"data: {payload}\n\n"
        return

    while True:
        try:
            line = await asyncio.wait_for(state.queue.get(), timeout=2.0)
            if line is None:  # Sentinel
                break
        except asyncio.TimeoutError:
            if state.status != "running":
                break
            yield ": keepalive\n\n"
            continue

        if line not in seen:
            seen.add(line)
            yield f"data: {line}\n\n"

        try:
            parsed = json.loads(line)
            if parsed.get("type") in ("DONE", "ERROR"):
                break
        except Exception:
            pass

    # Ensure the client always gets a terminal event to stop reconnecting
    payload = json.dumps({"type": "DONE", "agent": "server", "content": "Stream closed"})
    yield f"data: {payload}\n\n"


@app.get("/api/scan/{run_id}/stream", dependencies=[Security(require_api_key)])
async def stream_scan(run_id: str):
    return StreamingResponse(
        _event_stream(run_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/scan/{run_id}/feedback", dependencies=[Security(require_api_key)])
async def submit_feedback(run_id: str, body: FeedbackRequest):
    db.save_feedback(run_id, body.finding_idx, body.human_verdict)
    return {"status": "recorded"}


@app.get("/api/scan/{run_id}/feedback", dependencies=[Security(require_api_key)])
async def get_feedback(run_id: str):
    return db.get_feedback_for_run(run_id)


@app.post("/api/remediate", dependencies=[Security(require_api_key)])
async def generate_remediation(req: RemediateRequest):
    """Generate an automated fix snippet using an LLM coder model."""
    prompt = (
        f"You are a Senior Security Engineer. Provide a fix for this vulnerability.\n"
        f"File: {req.file_path}\n"
        f"Line: {req.line_number}\n"
        f"Severity: {req.severity}\n"
        f"Description: {req.description}\n\n"
        f"Code Snippet:\n```\n{req.code_snippet}\n```\n\n"
        f"Output ONLY the fixed code snippet, followed by a brief explanation."
    )
    
    payload = json.dumps({
        "model": req.model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 1024}
    }).encode("utf-8")
    
    import urllib.request
    req_obj = urllib.request.Request(
        f"{os.environ.get('OLLAMA_URL', 'http://127.0.0.1:11434')}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    try:
        def fetch():
            with urllib.request.urlopen(req_obj, timeout=120) as resp:
                return json.loads(resp.read())
        data = await asyncio.to_thread(fetch)
        raw_response = data.get("response", "")
        
        fix_code = raw_response
        explanation = ""
        if "```" in raw_response:
            parts = raw_response.split("```")
            if len(parts) >= 3:
                fix_code = parts[1].strip()
                if fix_code.startswith("python"):
                    fix_code = fix_code[6:].strip()
                elif fix_code.startswith("javascript"):
                    fix_code = fix_code[10:].strip()
                explanation = parts[2].strip()
        
        return {
            "finding_id": req.finding_id,
            "suggested_fix": fix_code,
            "explanation": explanation
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/verify", dependencies=[Security(require_api_key)])
async def verify_exploitability(req: VerifyRequest):
    """
    Milestone 4.1: Exploit Validation Sandbox
    Validates target URL, generates an exploit script, and executes in isolated Docker container.
    """
    validated_target = validate_sandbox_target_url(req.target_url)

    prompt = (
        f"Write a Python script that exploits the following vulnerability.\n"
        f"File: {req.file_path}\n"
        f"Description: {req.description}\n\n"
        f"Code Snippet:\n```\n{req.code_snippet}\n```\n\n"
        f"The target application is running at {validated_target}.\n"
        f"Your script MUST print exactly 'EXPLOIT_SUCCESS:{req.finding_id}' to stdout if the exploit succeeds.\n"
        f"You MUST verify the vulnerability by checking the response for specific evidence (e.g. leaked data). Do not print the success string unconditionally.\n"
        f"Output ONLY the python code using the requests or urllib library. No markdown wrapping."
    )
    
    payload = json.dumps({
        "model": req.model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1024}
    }).encode("utf-8")
    
    import urllib.request
    req_obj = urllib.request.Request(
        f"{os.environ.get('OLLAMA_URL', 'http://127.0.0.1:11434')}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    try:
        def fetch():
            with urllib.request.urlopen(req_obj, timeout=120) as resp:
                return json.loads(resp.read())
        data = await asyncio.to_thread(fetch)
        exploit_code = data.get("response", "")
        
        if "```" in exploit_code:
            parts = exploit_code.split("```")
            if len(parts) >= 3:
                exploit_code = parts[1].strip()
                if exploit_code.startswith("python"):
                    exploit_code = exploit_code[6:].strip()
        
        from .sandbox_runner import run_exploit_in_sandbox
        
        def run_sandbox_sync():
            return run_exploit_in_sandbox(
                exploit_code,
                req.finding_id,
                target_url=validated_target,
                allow_network=True,
            )
            
        success, output = await asyncio.to_thread(run_sandbox_sync)
        
        return {
            "finding_id": req.finding_id,
            "verified": success,
            "exploit_code": exploit_code,
            "output": output
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def build_attack_surface_graph(repo_map: dict, repo_url: str):
    """
    Constructs a directional Attack Surface & Component Architecture graph
    from repo analysis metadata, mapping external ingress, routing components,
    internal domain modules, persistence, egress, and dangerous execution sinks.
    """
    nodes = []
    edges = []

    # 1. External Ingress / Untrusted Traffic Boundary
    nodes.append({
        "id": "ingress-client",
        "position": {"x": 50, "y": 200},
        "data": {
            "label": "Public Traffic / Untrusted Ingress",
            "type": "external",
            "icon": "Globe",
            "tags": ["External-Surface", "Untrusted-Input"],
        }
    })

    # 2. Entry points & Web Ingress Routers
    entry_points = repo_map.get("entry_points", [])
    frameworks = repo_map.get("framework_signals", [])
    technologies = set(repo_map.get("technology_inventory", []))
    cross_refs = repo_map.get("cross_references", {})

    entry_node_ids = []
    if entry_points:
        for idx, ep in enumerate(entry_points[:3]):
            node_id = f"entry-{idx}"
            entry_node_ids.append(node_id)
            fw_label = f" ({frameworks[0].upper()})" if frameworks else ""
            nodes.append({
                "id": node_id,
                "position": {"x": 300, "y": 100 + idx * 140},
                "data": {
                    "label": f"{ep}{fw_label}",
                    "type": "entrypoint",
                    "icon": "Network",
                    "tags": ["Internet-Facing", "Router", "HTTP-Ingress"],
                }
            })
            edges.append({
                "id": f"e-ingress-{node_id}",
                "source": "ingress-client",
                "target": node_id,
                "animated": True,
            })
    else:
        node_id = "entry-main"
        entry_node_ids.append(node_id)
        label = f"{frameworks[0].upper()} Router" if frameworks else f"{repo_map.get('repo_name', 'App')} Gateway"
        nodes.append({
            "id": node_id,
            "position": {"x": 300, "y": 200},
            "data": {
                "label": label,
                "type": "entrypoint",
                "icon": "Network",
                "tags": ["Internet-Facing", "HTTP-Ingress"],
            }
        })
        edges.append({
            "id": f"e-ingress-{node_id}",
            "source": "ingress-client",
            "target": node_id,
            "animated": True,
        })

    # 3. Internal Application Components & Domain Modules
    has_auth = "jwt" in technologies or "crypto" in technologies or any("auth" in k.lower() or "user" in k.lower() for k in cross_refs)
    if has_auth:
        nodes.append({
            "id": "comp-auth",
            "position": {"x": 600, "y": 80},
            "data": {
                "label": "Auth & Identity Boundary",
                "type": "internal",
                "icon": "Lock",
                "tags": ["Auth-Boundary", "Token-Verification"],
            }
        })
        for eid in entry_node_ids:
            edges.append({
                "id": f"e-{eid}-auth",
                "source": eid,
                "target": "comp-auth",
                "animated": False,
            })

    nodes.append({
        "id": "comp-core",
        "position": {"x": 600, "y": 230},
        "data": {
            "label": f"{repo_map.get('repo_name', 'Application')} Core Logic",
            "type": "internal",
            "icon": "Network",
            "tags": ["Business-Logic", "Data-Flow"],
        }
    })
    for eid in entry_node_ids:
        edges.append({
            "id": f"e-{eid}-core",
            "source": eid,
            "target": "comp-core",
            "animated": True,
        })

    if "file_io" in technologies:
        nodes.append({
            "id": "comp-files",
            "position": {"x": 600, "y": 380},
            "data": {
                "label": "File I/O & Storage Controller",
                "type": "internal",
                "icon": "Database",
                "tags": ["Filesystem-Access", "Path-Surface"],
            }
        })
        edges.append({
            "id": "e-core-files",
            "source": "comp-core",
            "target": "comp-files",
            "animated": False,
        })

    # 4. Storage, Sinks & Egress Layer
    col3_y = 60
    if "sql" in technologies:
        nodes.append({
            "id": "store-sql",
            "position": {"x": 920, "y": col3_y},
            "data": {
                "label": "Relational DB / SQL Store",
                "type": "database",
                "icon": "Database",
                "tags": ["Persistence", "SQL-Injection-Surface"],
            }
        })
        edges.append({
            "id": "e-core-sql",
            "source": "comp-core",
            "target": "store-sql",
            "animated": False,
        })
        col3_y += 120

    if "redis" in technologies:
        nodes.append({
            "id": "store-redis",
            "position": {"x": 920, "y": col3_y},
            "data": {
                "label": "Redis Cache & Session Store",
                "type": "database",
                "icon": "Database",
                "tags": ["In-Memory", "Session-Store"],
            }
        })
        target_src = "comp-auth" if has_auth else "comp-core"
        edges.append({
            "id": f"e-{target_src}-redis",
            "source": target_src,
            "target": "store-redis",
            "animated": False,
        })
        col3_y += 120

    if "network" in technologies or "aws" in technologies:
        nodes.append({
            "id": "egress-network",
            "position": {"x": 920, "y": col3_y},
            "data": {
                "label": "External APIs & Cloud Services",
                "type": "external",
                "icon": "Globe",
                "tags": ["Egress", "SSRF-Surface"],
            }
        })
        edges.append({
            "id": "e-core-network",
            "source": "comp-core",
            "target": "egress-network",
            "animated": False,
        })
        col3_y += 120

    if "subprocess" in technologies:
        nodes.append({
            "id": "sink-subprocess",
            "position": {"x": 920, "y": col3_y},
            "data": {
                "label": "OS Command Execution Sink",
                "type": "internal",
                "icon": "ShieldAlert",
                "isHighRisk": True,
                "tags": ["High-Risk", "RCE-Surface", "Subprocess"],
            }
        })
        edges.append({
            "id": "e-core-subprocess",
            "source": "comp-core",
            "target": "sink-subprocess",
            "animated": True,
        })
        col3_y += 120

    if "deserialization" in technologies:
        nodes.append({
            "id": "sink-deser",
            "position": {"x": 920, "y": col3_y},
            "data": {
                "label": "Object Deserialization Sink",
                "type": "internal",
                "icon": "ShieldAlert",
                "isHighRisk": True,
                "tags": ["High-Risk", "Insecure-Deserialization", "RCE-Risk"],
            }
        })
        edges.append({
            "id": "e-core-deser",
            "source": "comp-core",
            "target": "sink-deser",
            "animated": True,
        })

    return nodes, edges


@app.get("/api/architecture", dependencies=[Security(require_api_key)])
def get_architecture_map(repo: str):
    """Fetch architecture map and attack surface graph for a repository."""
    map_json = db.get_architecture(repo)
    if not map_json:
        raise HTTPException(status_code=404, detail="Architecture map not found for this repository. Run a scan first.")
    
    try:
        repo_map = json.loads(map_json)
        # Ensure sensitive local host paths or source code contents are never exposed in API DTO
        repo_map.pop("root", None)
        repo_map.pop("files", None)
        
        nodes, edges = build_attack_surface_graph(repo_map, repo)
        return {"nodes": nodes, "edges": edges, "raw": repo_map}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/api/webhooks/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None),
):
    """
    GitHub webhook handler with mandatory HMAC-SHA256 signature verification.
    Triggers differential scans safely on pull_request events.
    """
    payload_bytes = await request.body()
    # Mandatory HMAC signature verification (raises 401 if missing/invalid)
    verify_github_webhook_signature(payload_bytes, x_hub_signature_256)

    payload = await request.json()
    action = payload.get("action")
    repo_data = payload.get("repository", {})
    repo_name = repo_data.get("full_name", "unknown/repo")
    
    print(f"[Webhook] Verified GitHub webhook for {repo_name} - action: {action}")
    
    if "pull_request" in payload and action in ("opened", "synchronize", "reopened"):
        pr = payload.get("pull_request", {})
        head_clone_url = pr.get("head", {}).get("repo", {}).get("clone_url")
        head_ref = pr.get("head", {}).get("ref")
        
        if not head_clone_url or not head_ref:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing PR head clone_url or ref in payload.")
        
        # Validate clone_url against SSRF
        validated_clone_url = validate_scan_target(head_clone_url)

        from .diff_extractor import extract_diff_from_pr
        diff = extract_diff_from_pr(payload)
        if diff:
            print(f"[Webhook] Differential changes detected: {len(diff)} files modified.")
            diff_json_str = json.dumps(diff)
            script_path = os.path.join(os.path.dirname(__file__), "..", "cycle11_ollama_swarm", "run_real_world.py")
            cmd = [
                sys.executable, script_path,
                "--repo", validated_clone_url,
                "--branch", head_ref,
                "--diff-json", diff_json_str,
            ]
            def run_webhook_scan():
                run_id = str(uuid.uuid4())
                db.create_run(run_id, "webhook", {"repo": validated_clone_url})
                db.append_log(run_id, "SYSTEM", "webhook", f"Starting webhook scan for {repo_name}")
                try:
                    res = subprocess.run(cmd, timeout=600, capture_output=True, text=True)
                    db.update_run_status(run_id, "done" if res.returncode == 0 else "error", res.returncode)
                except subprocess.TimeoutExpired:
                    db.append_log(run_id, "ERROR", "webhook", "Timeout expired")
                    db.update_run_status(run_id, "error", -1)
                except Exception as e:
                    db.append_log(run_id, "ERROR", "webhook", str(e))
                    db.update_run_status(run_id, "error", -1)
            background_tasks.add_task(run_webhook_scan)
        else:
            print("[Webhook] No differential code changes extracted.")
    
    return {"status": "ok", "message": f"Webhook processed for {repo_name}"}

# Serve the frontend
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")
    
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        safe_base = os.path.abspath(frontend_dist)
        path = os.path.abspath(os.path.join(safe_base, full_path))
        if not path.startswith(safe_base):
            return FileResponse(os.path.join(safe_base, "index.html"))
        if os.path.isfile(path):
            return FileResponse(path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
