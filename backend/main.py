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
import signal
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, Optional, List

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Header, Security, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# Security & DB modules
from security import (
    require_api_key,
    validate_scan_target,
    validate_sandbox_target_url,
    verify_github_webhook_signature,
)
import database as db

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
    max_chunks: int = Field(default=20, ge=5, le=100)
    sarif_file: Optional[str] = Field(default=None, description="Path to a SARIF file to ingest")

class SteerRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=2000)

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
                
                # Parse for DB persistence
                try:
                    payload = json.loads(line)
                    db.append_log(run_id, payload.get("type", "SYSTEM"), payload.get("agent", "runner"), payload.get("content", line))
                except Exception:
                    db.append_log(run_id, "SYSTEM", "runner", line)

                asyncio.run_coroutine_threadsafe(state.queue.put(line), loop)

            process.stdout.close()
            process.wait()
            exit_code = process.returncode
            done_payload = json.dumps({
                "type": "DONE",
                "agent": "runner",
                "content": f"Swarm finished — exit code {exit_code}",
                "exit_code": exit_code,
            })
            db.append_log(run_id, "DONE", "runner", f"Swarm finished — exit code {exit_code}")
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
        cmd.extend(["--sarif-file", req.sarif_file])
    
    if req.no_sast:
        cmd.append("--no-sast")
    elif req.sast_tools:
        cmd += ["--sast"] + req.sast_tools

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
                    db.append_log(run_id, payload.get("type", "SYSTEM"), payload.get("agent", "runner"), payload.get("content", line))
                except Exception:
                    db.append_log(run_id, "SYSTEM", "runner", line)

                asyncio.run_coroutine_threadsafe(state.queue.put(line), loop)

            process.stdout.close()
            process.wait()
            exit_code = process.returncode
            done_payload = json.dumps({
                "type": "DONE", "agent": "runner",
                "content": f"Real-world scan finished — exit code {exit_code}",
                "exit_code": exit_code,
            })
            db.append_log(run_id, "DONE", "runner", f"Real-world scan finished — exit code {exit_code}")
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

# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def health():
    """Unauthenticated health check for load balancers."""
    return {"status": "ok", "message": "Swarm API is running"}


@app.post("/api/scan", dependencies=[Security(require_api_key)])
async def start_scan(request: ScanRequest):
    # Check concurrent scans limit
    active_count = sum(1 for s in _runs.values() if s.status == "running")
    if active_count >= MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached. Please wait for an existing scan to finish.",
        )

    run_id = str(int(time.time() * 1000))
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
    # Validate scan boundary & SSRF protection
    validated_repo = validate_scan_target(request.repo)
    request.repo = validated_repo

    active_count = sum(1 for s in _runs.values() if s.status == "running")
    if active_count >= MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached. Please wait for an existing scan to finish.",
        )

    run_id = str(int(time.time() * 1000))
    loop = asyncio.get_running_loop()
    config = {
        "scan_type": "real_world",
        "repo": request.repo,
        "model": request.model,
        "challenger_model": request.challenger_model,
        "workers": request.workers,
        "challengers": request.challengers,
        "sast_tools": request.sast_tools,
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


async def _event_stream(run_id: str) -> AsyncGenerator[str, None]:
    state = _runs.get(run_id)
    if not state:
        # Check if completed run exists in DB
        db_run = db.get_run(run_id)
        if db_run:
            logs = db.get_logs_for_run(run_id)
            for entry in logs:
                yield f"data: {json.dumps(entry)}\n\n"
            return
        payload = json.dumps({"type": "ERROR", "agent": "server", "content": f"Run {run_id} not found"})
        yield f"data: {payload}\n\n"
        return

    while True:
        try:
            line = await asyncio.wait_for(state.queue.get(), timeout=30.0)
        except asyncio.TimeoutError:
            yield ": keepalive\n\n"
            continue

        yield f"data: {line}\n\n"

        parsed = json.loads(line)
        if parsed.get("type") in ("DONE", "ERROR"):
            break


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


@app.post("/api/scan/{run_id}/steer", dependencies=[Security(require_api_key)])
async def steer_scan(run_id: str, body: SteerRequest):
    state = _runs.get(run_id)
    if not state:
        raise HTTPException(status_code=404, detail="Run not found")
    if state.status != "running":
        raise HTTPException(status_code=409, detail="Run is not active")

    steer_payload = json.dumps({
        "type": "SYSTEM",
        "agent": "human",
        "content": f"[STEER] {body.prompt}",
    })
    db.append_log(run_id, "SYSTEM", "human", f"[STEER] {body.prompt}")
    await state.queue.put(steer_payload)
    return {"status": "injected", "run_id": run_id}


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
        "http://127.0.0.1:11434/api/generate",
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
        f"Output ONLY the python code using the requests library. No markdown wrapping."
    )
    
    payload = json.dumps({
        "model": req.model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1024}
    }).encode("utf-8")
    
    import urllib.request
    req_obj = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
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
        
        from sandbox_runner import run_exploit_in_sandbox
        
        def run_sandbox_sync():
            return run_exploit_in_sandbox(
                exploit_code,
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
        clone_url = repo_data.get("clone_url") or repo_data.get("html_url")
        if not clone_url:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Repository clone_url is missing from payload.")
        
        # Validate clone_url against SSRF
        validated_clone_url = validate_scan_target(clone_url)

        from diff_extractor import extract_diff_from_pr
        diff = extract_diff_from_pr(payload)
        if diff:
            print(f"[Webhook] Differential changes detected: {len(diff)} files modified.")
            diff_json_str = json.dumps(diff)
            script_path = os.path.join(os.path.dirname(__file__), "..", "cycle11_ollama_swarm", "run_real_world.py")
            cmd = [
                sys.executable, script_path,
                "--repo", validated_clone_url,
                "--diff-json", diff_json_str,
            ]
            background_tasks.add_task(subprocess.run, cmd)
        else:
            print("[Webhook] No differential code changes extracted.")
    
    return {"status": "ok", "message": f"Webhook processed for {repo_name}"}
