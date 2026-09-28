"""
Swarm Security Scanner — FastAPI Backend  (Phase 1 + Phase 2)
=============================================================
Improvements over the original:
  • Pydantic field bounds prevent resource exhaustion attacks
  • Lifespan context manager replaces @app.on_event (FastAPI 0.93+)
  • Active subprocess registry tracks PIDs and terminates them on shutdown
  • /api/scan/active   — list running / completed run_ids so UI can reconnect
  • /api/scan/{run_id} — GET run metadata (cycle, model, workers, status)
  • Structured log protocol: lines emitted as JSON with {type, agent, content}
    where type ∈ {PHASE, WORKER, CHALLENGER, VERDICT, SYSTEM, DONE, ERROR}
  • CORS tightened to localhost only in this default config (adjust for prod)
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
import hmac
import hashlib
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Shared run state
# ---------------------------------------------------------------------------

class RunState:
    """Thread-safe bag of state for one swarm run."""

    def __init__(self, run_id: str, request_meta: dict):
        self.run_id = run_id
        self.meta = request_meta          # cycle, model, workers, challengers
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.process: Optional[subprocess.Popen] = None
        self.status: str = "running"      # running | done | error
        self.started_at: float = time.time()

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "started_at": self.started_at,
            **self.meta,
        }


# Global registry:  run_id -> RunState
_runs: Dict[str, RunState] = {}
_runs_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Lifespan: graceful shutdown kills every active subprocess
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield                                   # server running — do nothing
    # Shutdown: terminate orphaned swarm processes
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
# App bootstrap
# ---------------------------------------------------------------------------

app = FastAPI(title="Swarm Security Scanner API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:4173", "http://127.0.0.1:4173"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class RemediateRequest(BaseModel):
    finding_id: str
    file_path: str
    line_number: int
    severity: str
    description: str
    code_snippet: str
    model: str = "qwen2.5-coder:7b"

class WebhookRequest(BaseModel):
    action: Optional[str] = None
    repository: Optional[Dict] = None
    pull_request: Optional[Dict] = None

class VerifyRequest(BaseModel):
    finding_id: str
    file_path: str
    description: str
    code_snippet: str
    model: str = "qwen2.5-coder:7b"
    target_url: str = "http://localhost:5000"


class ScanRequest(BaseModel):
    model: str = Field(default="llama3.2", max_length=80)
    challenger_model: str = Field(default="qwen2.5-coder:7b", max_length=80)
    cycle: str = Field(default="22", pattern=r"^(11|13a|13b|14|15|16|17|18|19|20|21|22)$")
    workers: int = Field(default=5, ge=1, le=10)
    challengers: int = Field(default=2, ge=1, le=2)


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

async def _run_swarm(run_id: str, req: ScanRequest, loop: asyncio.AbstractEventLoop):
    state = _runs[run_id]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["SWARM_STRUCTURED_OUTPUT"] = "1"   # signal script to emit JSON lines

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
                # If the script emits plain text, wrap it so the UI always
                # receives consistent JSON regardless of SWARM_STRUCTURED_OUTPUT.
                if not line.startswith("{"):
                    line = json.dumps({"type": "SYSTEM", "agent": "runner", "content": line})
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
            asyncio.run_coroutine_threadsafe(state.queue.put(done_payload), loop)
            state.status = "done" if exit_code == 0 else "error"

        except Exception as exc:
            err = json.dumps({"type": "ERROR", "agent": "runner", "content": str(exc)})
            asyncio.run_coroutine_threadsafe(state.queue.put(err), loop)
            state.status = "error"

    threading.Thread(target=_reader, daemon=True).start()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def health():
    return {"status": "ok", "message": "Swarm API is running"}


@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    run_id = str(int(time.time() * 1000))        # ms precision avoids collisions
    loop = asyncio.get_running_loop()
    state = RunState(run_id, {
        "cycle": request.cycle,
        "model": request.model,
        "challenger_model": request.challenger_model,
        "workers": request.workers,
        "challengers": request.challengers,
    })
    with _runs_lock:
        _runs[run_id] = state
    asyncio.create_task(_run_swarm(run_id, request, loop))
    return {"status": "started", "run_id": run_id}


@app.get("/api/scan/active")
def list_active_runs():
    """Return all tracked runs — allows the UI to reconnect after a refresh."""
    with _runs_lock:
        return [s.to_dict() for s in _runs.values()]


@app.get("/api/scan/{run_id}")
def get_run(run_id: str):
    """Return metadata + status for a specific run."""
    state = _runs.get(run_id)
    if not state:
        raise HTTPException(status_code=404, detail="Run not found")
    return state.to_dict()


async def _event_stream(run_id: str) -> AsyncGenerator[str, None]:
    state = _runs.get(run_id)
    if not state:
        payload = json.dumps({"type": "ERROR", "agent": "server", "content": f"Run {run_id} not found"})
        yield f"data: {payload}\n\n"
        return

    while True:
        try:
            line = await asyncio.wait_for(state.queue.get(), timeout=30.0)
        except asyncio.TimeoutError:
            # Keep-alive comment so the browser doesn't drop the connection
            yield ": keepalive\n\n"
            continue

        yield f"data: {line}\n\n"

        parsed = json.loads(line)
        if parsed.get("type") in ("DONE", "ERROR"):
            break


@app.get("/api/scan/{run_id}/stream")
async def stream_scan(run_id: str):
    return StreamingResponse(
        _event_stream(run_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",        # disable nginx buffering if behind a proxy
        },
    )


class SteerRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=2000)


@app.post("/api/scan/{run_id}/steer")
async def steer_scan(run_id: str, body: SteerRequest):
    """
    Human-in-the-Loop steering endpoint.
    Injects a prompt into the run's log stream as a SYSTEM event so the UI can
    display it immediately. Phase 3 (WebSocket / stdin IPC) will forward this
    to the live subprocess.
    """
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
    await state.queue.put(steer_payload)
    return {"status": "injected", "run_id": run_id}


class FeedbackRequest(BaseModel):
    finding_idx: int
    human_verdict: str


@app.post("/api/scan/{run_id}/feedback")
async def submit_feedback(run_id: str, body: FeedbackRequest):
    """
    Human-in-the-Loop Feedback endpoint for Triage Engine.
    Records human accept/override decisions on AI verdicts.
    """
    state = _runs.get(run_id)
    if not state:
        raise HTTPException(status_code=404, detail="Run not found")
    
    if not hasattr(state, "feedback"):
        state.feedback = {}
    
    state.feedback[body.finding_idx] = body.human_verdict
    return {"status": "recorded"}

@app.get("/api/scan/{run_id}/feedback")
async def get_feedback(run_id: str):
    state = _runs.get(run_id)
    if not state:
        raise HTTPException(status_code=404, detail="Run not found")
    
    return getattr(state, "feedback", {})


# ---------------------------------------------------------------------------
# Real-World Repository Scan  (Phase 4 — Real-World Pivot)
# ---------------------------------------------------------------------------

class RepoScanRequest(BaseModel):
    repo: str = Field(..., min_length=1, max_length=500,
                      description="Git repository URL or local path to scan")
    model: str = Field(default="llama3.2", max_length=80)
    challenger_model: str = Field(default="qwen2.5-coder:7b", max_length=80)
    workers: int = Field(default=5, ge=1, le=5)
    challengers: int = Field(default=2, ge=1, le=2)
    sast_tools: list[str] = Field(default=["bandit", "semgrep"])
    no_sast: bool = Field(default=False)
    max_chunks: int = Field(default=20, ge=5, le=100)
    sarif_file: Optional[str] = Field(default=None, description="Path to a SARIF file to ingest")


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
                asyncio.run_coroutine_threadsafe(state.queue.put(line), loop)

            process.stdout.close()
            process.wait()
            exit_code = process.returncode
            done_payload = json.dumps({
                "type": "DONE", "agent": "runner",
                "content": f"Real-world scan finished — exit code {exit_code}",
                "exit_code": exit_code,
            })
            asyncio.run_coroutine_threadsafe(state.queue.put(done_payload), loop)
            state.status = "done" if exit_code == 0 else "error"

        except Exception as exc:
            err = json.dumps({"type": "ERROR", "agent": "runner", "content": str(exc)})
            asyncio.run_coroutine_threadsafe(state.queue.put(err), loop)
            state.status = "error"

    threading.Thread(target=_reader, daemon=True).start()


@app.post("/api/repo-scan")
async def start_repo_scan(request: RepoScanRequest):
    """
    Start a real-world repository scan using run_real_world.py.
    Returns the same {run_id} format so the existing SSE stream endpoint works.
    """
    run_id = str(int(time.time() * 1000))
    loop = asyncio.get_running_loop()
    state = RunState(run_id, {
        "scan_type": "real_world",
        "repo": request.repo,
        "model": request.model,
        "challenger_model": request.challenger_model,
        "workers": request.workers,
        "challengers": request.challengers,
        "sast_tools": request.sast_tools,
    })
    with _runs_lock:
        _runs[run_id] = state
    asyncio.create_task(_run_repo_swarm(run_id, request, loop))
    return {"status": "started", "run_id": run_id, "scan_type": "real_world"}


# ---------------------------------------------------------------------------
# Phase 2: Developer Workflow Integration (Remediation & Webhooks)
# ---------------------------------------------------------------------------

@app.post("/api/remediate")
async def generate_remediation(req: RemediateRequest):
    """
    Generate an automated fix snippet using an LLM coder model.
    """
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
        response_text = data.get("response", "Could not generate fix.")
        
        # Split out the code block if it exists
        fix_code = response_text
        explanation = "Automated fix generated by AI."
        
        if "```" in response_text:
            parts = response_text.split("```")
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

@app.post("/api/webhooks/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks, x_hub_signature_256: str = Header(None)):
    """
    Listen to GitHub webhooks (push, pull_request) and trigger differential scans.
    """
    payload_bytes = await request.body()
    payload = await request.json()
    
    # Verify HMAC signature
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if secret and x_hub_signature_256:
        expected_signature = "sha256=" + hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid signature")
            
    action = payload.get("action")
    repo = payload.get("repository", {}).get("full_name", "unknown/repo")
    
    print(f"[Webhook] Received GitHub event for {repo} - action: {action}")
    
    if "pull_request" in payload and action in ("opened", "synchronize", "reopened"):
        from diff_extractor import extract_diff_from_pr
        diff = extract_diff_from_pr(payload)
        if diff:
            print(f"[Webhook] Extracted differential changes: {len(diff)} files modified.")
            import json
            import subprocess
            diff_json_str = json.dumps(diff)
            script_path = os.path.join(os.path.dirname(__file__), "..", "cycle11_ollama_swarm", "run_real_world.py")
            cmd = [
                sys.executable, script_path,
                "--repo", clone_url,
                "--diff-json", diff_json_str
            ]
            background_tasks.add_task(subprocess.run, cmd)
        else:
            print("[Webhook] Could not extract differential changes.")
    
    return {"status": "ok", "message": f"Webhook processed for {repo}"}


# ---------------------------------------------------------------------------
# Phase 4: Active Verification & Closed-Loop (Exploit Sandbox)
# ---------------------------------------------------------------------------

@app.post("/api/verify")
async def verify_exploitability(req: VerifyRequest):
    """
    Milestone 4.1: Exploit Validation Sandbox
    Generates a Python exploit script and executes it against the local sandbox target.
    """
    prompt = (
        f"Write a Python script that exploits the following vulnerability.\n"
        f"File: {req.file_path}\n"
        f"Description: {req.description}\n\n"
        f"Code Snippet:\n```\n{req.code_snippet}\n```\n\n"
        f"The target application is running at {req.target_url}.\n"
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
        
        # Clean up markdown if the LLM leaked it
        if "```" in exploit_code:
            parts = exploit_code.split("```")
            if len(parts) >= 3:
                exploit_code = parts[1].strip()
                if exploit_code.startswith("python"):
                    exploit_code = exploit_code[6:].strip()
        
        # Execute the exploit safely using our secure Docker sandbox environment
        from sandbox_runner import run_exploit_in_sandbox
        
        def run_sandbox_sync():
            return run_exploit_in_sandbox(exploit_code, target_url=getattr(req, 'target_url', 'http://localhost:5173'))
            
        success, output = await asyncio.to_thread(run_sandbox_sync)
        
        return {
            "finding_id": req.finding_id,
            "verified": success,
            "exploit_code": exploit_code,
            "output": output
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
