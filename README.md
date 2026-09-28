<div align="center">

# ⬡ Antigravity Swarm Security Scanner

**A state-of-the-art Multi-Agent AI Security Analysis Platform**

*Evaluates whether collaborative, specialised LLM swarms with adversarial peer-review outperform generalist single agents — now on **real repositories**, not just artificial benchmarks.*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-black?style=flat-square)](https://ollama.com)
[![Build](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)](#quick-start)
[![Cycles](https://img.shields.io/badge/Experiment_Cycles-11--22-8B5CF6?style=flat-square)](#experiment-cycles)

---

</div>

## 📋 Table of Contents

- [What Changed — The Real-World Pivot](#what-changed--the-real-world-pivot)
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Two Operating Modes](#two-operating-modes)
- [Full Architecture](#full-architecture)
- [Project Structure](#project-structure)
- [Real-World Pipeline (5 Phases)](#real-world-pipeline-5-phases)
- [Research Pipeline (Sandbox Cycles)](#research-pipeline-sandbox-cycles)
- [Experiment Cycles](#experiment-cycles)
- [Agent Roles](#agent-roles)
- [API Reference](#api-reference)
- [Frontend Dashboard](#frontend-dashboard)
- [Metrics & Benchmarking](#metrics--benchmarking)
- [Configuration](#configuration)
- [Key Innovations](#key-innovations)
- [Development Guide](#development-guide)

---

## What Changed — The Real-World Pivot

The previous version of this project was a **research harness** — it analysed a single, hand-crafted Python file with 6 deliberately planted vulnerabilities. The static pre-filter already caught 100% of them before the LLM swarm even ran.

This version makes the following critical upgrades to address those gaps:

| Old Limitation | New Capability |
|---|---|
| Single hardcoded Python file | **Any Git URL or local path** — multi-language, multi-file |
| Custom naive regex pre-filter | **Bandit + Semgrep + SARIF** — real industry-standard SAST tools + generic SARIF ingestion |
| Hardcoded technology constraints in prompts | **Dynamic `RepoMap`** — agents told exactly what tech is present in *this* repo |
| `confirmed / refuted` counters for 6 planted flaws | **Precision, Recall, F1, FPR, FNR, Delta-vs-SAST** — real benchmarking |
| No SAST integration | **SAST Triage Mode** — swarm classifies TP / FP for each SAST alert |
| "Research harness only" | **Developer Triage View** — actionable findings for real security work |

> [!IMPORTANT]
> The original sandbox research pipeline (Cycles 11–22) is **fully preserved** and accessible via the `◈ Sandbox` mode in the UI. The new `⬡ Real-World Repo` mode is additive.

---

## Overview

The **Antigravity Swarm Security Scanner** orchestrates multiple local LLMs (via Ollama) in a structured multi-phase pipeline to audit source code for security vulnerabilities. It operates in two modes:

**Real-World Mode** — For analysing real repositories. The platform:
1. Clones or walks any repository (multi-language)
2. Runs Bandit + Semgrep for a SAST baseline
3. Uses LLMs to triage SAST alerts (True/False Positive classification)
4. Hunts for complex logic flaws SAST tools miss
5. Reports Precision, Recall, F1, Delta-vs-SAST, and token efficiency metrics

**Sandbox Mode** — For research experiments. The platform runs 12 validated experiment cycles (11–22) on a controlled benchmark with planted ground-truth flaws, using a 6-axis adversarial challenger rubric to evaluate LLM security audit quality.

---

## Quick Start

### Prerequisites

| Requirement | Check | Install |
|---|---|---|
| **Python 3.11+** | `python --version` | [python.org](https://python.org) |
| **Node.js 18+** | `node --version` | [nodejs.org](https://nodejs.org) |
| **Ollama** | `ollama --version` | [ollama.com](https://ollama.com) |
| `llama3.2` model | `ollama list` | `ollama pull llama3.2` |
| `qwen2.5-coder:7b` | `ollama list` | `ollama pull qwen2.5-coder:7b` |

### Install

```bash
# Python dependencies
pip install fastapi uvicorn python-multipart

# Frontend dependencies
cd frontend
npm install
```

### Launch Options

#### 1. Production Deployment (Recommended for Servers)

Deploy the hardened, containerized stack with non-root containers, internal network isolation, and precompiled Vite assets:

```bash
# 1. Configure environment and generate secure API key
cp .env.example .env
# Edit .env and set SWARM_API_KEY, GITHUB_WEBHOOK_SECRET

# 2. Build and launch with Docker Compose
docker compose -f docker-compose.prod.yml up --build -d
```

The production server starts on `http://localhost:8000` with 4 Uvicorn workers and static asset serving.

#### 2. Local Development

For local research and interactive development:

**Windows — One click:**
```
Double-click: start.bat
```

**Manual — Two terminals:**
```bash
# Terminal 1 — Backend (port 8000)
cd backend
python -m uvicorn main:app --reload --port 8000

# Terminal 2 — Frontend (port 5173)
cd frontend
npm run dev
```

> For local development without authentication, set `SWARM_ALLOW_ANONYMOUS=true` in `.env`.
> Make sure `ollama serve` is running before starting a scan.

Open **http://localhost:5173** in your browser.

---

## 🔒 Production Security Architecture

The Swarm Security Scanner implements Defense-in-Depth AppSec controls across 5 core areas:

| Security Domain | Implementation | Defense Mechanism |
|---|---|---|
| **API Authentication** | `backend/security.py` | Bearer token / `X-API-Key` / query token for SSE. Rejects anonymous access in production. |
| **Boundary & Path Traversal** | `backend/security.py` | Canonical `realpath` resolution, system root blocking (`/etc`, `/proc`, `C:\Windows`), `SWARM_ALLOWED_SCAN_ROOT` jail. |
| **SSRF Prevention** | `backend/security.py` | HTTPS scheme enforcement, DNS resolution check, blocks loopback, link-local, RFC-1918 private IPs, and cloud metadata (`169.254.169.254`). |
| **Exploit Sandbox Isolation** | `backend/sandbox_runner.py` | Docker container runs with `network_mode="none"`, `read_only=True`, `cap_drop=["ALL"]`, `security_opt=["no-new-privileges:true"]`, strict memory/CPU/PID limits, and unprivileged user (`UID 1000`). API runs as an unprivileged user and safely orchestrates containers via a TCP `docker-socket-proxy`. |
| **Webhook Verification** | `backend/main.py` | Mandatory HMAC-SHA256 signature verification (`X-Hub-Signature-256`), rejects unsigned or invalid payloads. |
| **Durable Persistence** | `backend/database.py` | SQLite backing store preserves scan runs, audit logs, and human feedback across service restarts. |
| **Automated CI/CD** | `.github/workflows/ci.yml` | GitHub Actions pipeline running linting, type checks, and full security test suite on all PRs. |

---

## Two Operating Modes

### ◈ Sandbox Mode
*Research harness — artificial benchmark, 12 validated experiment cycles.*

- Target: `cycle11_ollama_swarm/sandbox_target/target_app_cycle13.py` (6 planted vulnerabilities)
- Cycles 11–22, each with a specific research innovation
- Uses the 6-axis adversarial peer-review rubric
- Fully reproducible results for academic benchmarking
- Best for: **evaluating the architecture itself**

### ⬡ Real-World Repo Mode
*Production-oriented — scan any real codebase.*

- Input: any `https://github.com/org/repo` URL or local directory path
- Multi-language (Python, JavaScript, TypeScript, Go, Java, Ruby, and more)
- Integrates Bandit + Semgrep for a SAST baseline
- Dynamic technology-aware prompts (no hardcoded constraints)
- Measures Precision, Recall, F1, Delta-vs-SAST
- Best for: **finding real vulnerabilities in real code**

---

## Full Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    React Dashboard (Vite + TypeScript)              │
│                                                                     │
│  ◈ Sandbox Mode               ⬡ Real-World Repo Mode               │
│  ┌─────────────┐              ┌──────────────────────────┐         │
│  │ Agent Graph │              │ Configure (URL + SAST)    │         │
│  │ React Flow  │              │ Triage (TP / FP table)    │         │
│  │ Live Nodes  │              │ Metrics (P/R/F1/Delta)    │         │
│  └─────────────┘              └──────────────────────────┘         │
│         │                            │                              │
│         └──── Live Log Terminal ─────┘                             │
└─────────────────────┬──────────────────────────────────────────────┘
                      │  SSE stream (structured JSON)
                      │  POST /api/scan            (sandbox)
                      │  POST /api/repo-scan        (real-world)
                      │  GET  /api/scan/{id}/stream (both modes)
                      │  POST /api/scan/{id}/steer  (both modes)
┌─────────────────────┴──────────────────────────────────────────────┐
│                    FastAPI Backend (Uvicorn)                         │
│  RunState registry · lifespan cleanup · keep-alive SSE pings        │
└──────────┬───────────────────────────────────┬─────────────────────┘
           │ subprocess (SWARM_STRUCTURED_OUTPUT=1)
  ┌────────┴──────────┐              ┌──────────┴──────────┐
  │  run_cycle11.py   │              │ run_real_world.py   │
  │  (Sandbox)        │              │ (Real-World)        │
  │                   │              │                     │
  │  Phase 0 Static   │              │  Phase 0 Ingest     │
  │  Phase 1 Swarm    │              │  Phase 1 SAST       │
  │  Phase 2 Challenge│              │  Phase 2 Triage     │
  │  Phase 3 Verdict  │              │  Phase 3 Discovery  │
  │  Phase 4 Report   │              │  Phase 4 Challenge  │
  └───────────────────┘              │  Phase 5 Metrics    │
                                     └──────────┬──────────┘
                                                │
                             ┌──────────────────┼──────────────────┐
                    ┌────────┴──────┐  ┌────────┴──────┐  ┌───────┴──────┐
                    │  repo_ingester│  │  sast_runner   │  │metrics_engine│
                    │  Git clone    │  │  Bandit        │  │  P/R/F1/FPR  │
                    │  AST chunker  │  │  Semgrep       │  │  Delta-SAST  │
                    │  RepoMap      │  │  Dedup + CWE   │  │  Token cost  │
                    └───────────────┘  └────────────────┘  └──────────────┘
                                                │
                                         ┌──────┴──────┐
                                         │   Ollama    │
                                         │  llama3.2   │
                                         │  qwen2.5-   │
                                         │  coder:7b   │
                                         └─────────────┘
```

---

## Project Structure

```
cycle10_swarm_harness/
│
├── start.bat                       ← One-click full-stack launcher (Windows)
├── .env                            ← Environment variables
├── README.md                       ← This file
│
├── backend/
│   └── main.py                     ← FastAPI server
│                                     POST /api/scan            (sandbox)
│                                     POST /api/repo-scan        (real-world)
│                                     GET  /api/scan/active      (reconnect)
│                                     GET  /api/scan/{id}        (metadata)
│                                     GET  /api/scan/{id}/stream (SSE)
│                                     POST /api/scan/{id}/steer  (HITL)
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx                 ← Full dashboard (both modes)
│   │   ├── index.css               ← Design system (glassmorphism, tokens)
│   │   └── main.tsx                ← Entry point
│   ├── tsconfig.app.json           ← App TypeScript config (jsx: react-jsx)
│   ├── tsconfig.node.json          ← Vite config TypeScript config
│   ├── tsconfig.json               ← Project references root
│   ├── vite.config.ts
│   └── package.json
│
└── cycle11_ollama_swarm/
    ├── run_cycle11.py              ← Sandbox orchestrator (Cycles 11–22, 1900+ lines)
    │
    ├── run_real_world.py           ← ★ NEW: Real-world orchestrator (5-phase pipeline)
    │
    ├── agents/
    │   ├── repo_ingester.py        ← ★ NEW: Git clone, file walk, AST chunker, RepoMap
    │   ├── sast_runner.py          ← ★ NEW: Bandit + Semgrep wrapper, unified format
    │   ├── sarif_parser.py         ← ★ NEW: Generic SARIF parser (GitHub, Snyk, SonarQube)
    │   ├── metrics_engine.py       ← ★ NEW: P/R/F1/FPR/FNR/Delta metrics tracker
    │   ├── llm_client.py           ← ★ NEW: Multi-provider router (Ollama + Groq API)
    │   ├── ollama_client.py        ← Ollama REST wrapper
    │   ├── research_agents.py      ← Discovery + Challenger agents, AGENT_ROLES
    │   ├── schema_validator.py     ← Evidence chain gate (tech hallucination filter)
    │   ├── static_filter.py        ← AST/regex pre-filter (sandbox only)
    │   ├── memory.py               ← Per-run SQLite blackboard
    │   └── grounded_parser.py      ← 8-step grounded findings parser
    │
    ├── sandbox_target/
    │   ├── target_app.py           ← Cycle 11 target (hinted, legacy)
    │   └── target_app_cycle13.py   ← Cycles 13A–22 target (blind, 6 planted flaws)
    │
    └── results/                    ← Per-run SQLite DBs + JSON/metrics exports
```

---

## Real-World Pipeline (5 Phases)

```
Phase 0 — INGEST
  └─ Clone/walk repository (git clone --depth 1 or local path walk)
  └─ Discover all security-relevant files (.py .js .ts .go .java etc.)
  └─ Build RepoMap: language distribution, frameworks, technologies detected
  └─ Chunk code by AST boundaries (functions/classes) up to 6,000 chars
  └─ Prioritise security-sensitive chunks (auth, tokens, queries, permissions)

Phase 1 — SAST BASELINE
  └─ Run Bandit (Python-specific rule engine)
  └─ Run Semgrep (multi-language, p/security-audit + p/owasp-top-ten rulesets)
  └─ Ingest external SARIF files (optional: GitHub Code Scanning, Snyk, SonarQube)
  └─ Deduplicate by (file, line, rule_id)
  └─ Sort by severity (CRITICAL → HIGH → MEDIUM → LOW)

Phase 2 — SAST TRIAGE
  └─ For each HIGH/CRITICAL/MEDIUM SAST alert:
      └─ Fetch relevant code chunk for context
      └─ Ask LLM: TRUE_POSITIVE or FALSE_POSITIVE?
      └─ Record: verdict, confidence, rationale
  └─ Compute: SAST false-positive elimination rate

Phase 3 — DISCOVERY (Logic Flaws SAST Misses)
  └─ 5 specialised agents, each with a unique security domain focus
  └─ Dynamic prompts: constrained to technologies DETECTED in this repo
  └─ Schema Gate: all 5 evidence fields required (Location, Path, Property,
      AttackerInput, Consequence)
  └─ Dynamic hallucination filter: per-repo absent-technology detection

Phase 4 — CHALLENGE
  └─ 2 adversarial challenger agents review confirmed discoveries
  └─ 6-axis evaluation rubric (inherited from Cycle 19 research)
  └─ Severity decoupling: factual errors ≠ severity disagreements

Phase 5 — METRICS
  └─ Delta-vs-SAST: how many novel findings did the swarm produce?
  └─ Schema pass rate: what % of raw LLM output survived the gate?
  └─ Precision / Recall / F1 (if ground truth CVEs provided)
  └─ Token efficiency: estimated token consumption vs cloud-API cost
  └─ Export: results/real_world_{run_id}_metrics.json
```

---

## Research Pipeline (Sandbox Cycles)

The original research pipeline is unchanged and fully accessible in the UI's `◈ Sandbox` mode.

```
Phase 0 — Static Pre-Filter  (deterministic, 100% recall on planted GTs)
Phase 1 — Discovery Swarm    (5 specialised LLM agents, serial)
           └─ Schema Gate    (evidence chain validation)
Phase 2 — Adversarial Review (2 challenger agents, 6-axis rubric)
Phase 3 — Verdict Aggregation (CONFIRMED / PARTIAL / REFUTED)
Phase 4 — Measurement        (precision, recall, schema telemetry, report)
```

---

## Experiment Cycles

| Cycle | Focus | Key Innovation |
|---|---|---|
| **11** | Hinted Benchmark | Baseline with inline comment hints |
| **13A** | Blind Vulnerable | No hints; 6 planted ground-truth flaws |
| **13B** | Clean Hardened Target | Zero flaws — measures false positive rate |
| **14** | Evidence-First | Structured hypothesis-evidence chain prompts |
| **15** | Hard Schema Gate | 5-field evidence gate + static pre-filter |
| **16** | Challenger Calibration | Preserves `PARTIAL` verdicts; overrejection diagnostics |
| **17** | Grounded Discovery | 8-step self-rejection prompt; `MECHANISM_ABSENT` filter |
| **18** | Cross-Model A/B | `llama3.2` discovery + `qwen2.5-coder` challengers |
| **19** | **Evaluator Decomposition** | **6-axis rubric** + severity decoupling |
| **20** | Reproducibility | Parameter-frozen Cycle 19 re-run |
| **21** | Schema-Gate Audit | Schema suppression vs. precision analysis |
| **22** | **Evaluator Replication** | Reproducibility validation and architecture freeze of Cycle 21 decomposed evaluator against LLM seed variance |

---

## Agent Roles

### Discovery Workers (both modes)

| Agent | Security Domain |
|---|---|
| `auth_analyst` | Authentication, session management, token security |
| `access_control` | Authorisation, RBAC, privilege escalation, IDOR |
| `injection_analyst` | Injection flaws (SQL, command, LDAP, template, XSS) — *only when relevant tech detected* |
| `crypto_analyst` | Weak hashes, missing encryption, insecure RNG, key management |
| `data_exposure` | PII leakage, excessive data return, secrets in logs |

> **Real-World mode only**: Agent prompts are dynamically constrained to the technology stack detected in *this specific repository*. If SQL is not detected, `injection_analyst` will not claim SQL injection. This eliminates the most common source of LLM hallucination in security scanning.

### Challenger Agents (6-Axis Rubric)

Two independent adversarial reviewers evaluate every finding that passes the Schema Gate:

| Axis | Options |
|---|---|
| **Factual Validity** | `VALID` / `PARTIAL` / `INVALID` — does the described construct exist? |
| **Attack Path** | `SUPPORTED` / `PARTIAL` / `UNSUPPORTED` — viable data-flow to impact? |
| **Security Property** | `SUPPORTED` / `UNSUPPORTED` — is a security invariant violated? |
| **Consequence** | `SUPPORTED` / `UNSUPPORTED` — does the impact actually follow? |
| **Severity** | `AGREE` / `DISAGREE` / `INDETERMINATE` — decoupled from factual validity |
| **Overall Verdict** | `CONFIRMED` / `PARTIALLY_SUPPORTED` / `INVALID` |

> **Severity Decoupling**: A finding that is factually correct but has an overestimated severity is preserved as `PARTIAL_CONFIRMED` rather than being discarded. This was the fix for the catastrophic overrejection rate in Cycles 13–15.

---

## API Reference

Interactive docs: **http://localhost:8000/docs**

### `POST /api/scan` — Sandbox scan

```json
{
  "model": "llama3.2",
  "challenger_model": "qwen2.5-coder:7b",
  "cycle": "22",
  "workers": 5,
  "challengers": 2
}
```

**Response:** `{ "status": "started", "run_id": "1727341234567" }`

---

### `POST /api/repo-scan` — Real-world repository scan *(NEW)*

```json
{
  "repo": "https://github.com/org/repo",
  "model": "llama3.2",
  "challenger_model": "qwen2.5-coder:7b",
  "workers": 5,
  "challengers": 2,
  "sast_tools": ["bandit", "semgrep"],
  "sarif_file": "path/to/report.sarif",
  "no_sast": false,
  "max_chunks": 20
}
```

**Response:** `{ "status": "started", "run_id": "...", "scan_type": "real_world" }`

---

### `GET /api/scan/{run_id}/stream` — Live SSE stream (both modes)

Each `data:` payload is a structured JSON line:

```json
{ "type": "PHASE",      "agent": "orchestrator", "content": "PHASE 0 — INGEST: Cloning..." }
{ "type": "SYSTEM",     "agent": "sast",         "content": "SAST complete: 14 findings..." }
{ "type": "VERDICT",    "agent": "triage",        "content": "[1/14] app.py:42 [HIGH] → ✓ TP" }
{ "type": "WORKER",     "agent": "auth_analyst",  "content": "Found predictable token..." }
{ "type": "CHALLENGER", "agent": "challenger_0",  "content": "CONFIRMED — attack path verified" }
{ "type": "DONE",       "agent": "runner",        "content": "Real-world scan finished — exit code 0" }
```

**Log types:** `PHASE` · `WORKER` · `CHALLENGER` · `VERDICT` · `SYSTEM` · `ERROR` · `DONE`

Keep-alive comments (`: keepalive`) are sent every 30 seconds.

---

### `POST /api/scan/{run_id}/steer` — Human-in-the-Loop

```json
{ "prompt": "Focus more on SQL injection attack vectors in the authentication module" }
```

Immediately echoed to the SSE stream as a `SYSTEM` event.

---

### `GET /api/scan/active` — List active runs (reconnect support)

### `GET /api/scan/{run_id}` — Run metadata

---

## Frontend Dashboard

### Nav — Mode Switcher
```
◈ Sandbox    ⬡ Real-World Repo
```
Toggle between modes at any time. Both modes share the same SSE stream infrastructure and live log terminal.

---

### ⬡ Real-World Repo Mode

**Configure tab**
- Repository URL or local path input
- SAST tool selection (Bandit, Semgrep, or skip entirely)
- Discovery/Challenger model names
- Max chunks per agent slider (5–100, each ~6,000 chars)
- Phase-by-phase explanation cards

**⚔ Triage tab**
- Live TP/FP classification table as SAST alerts are reviewed
- Colour-coded cards (green border = True Positive, red border = False Positive)
- Rationale text from the LLM for each classification
- Summary counts: `✓ N True Positives` · `✗ N False Positives` · `N Pending`

**📊 Metrics tab**
- Live-updating metric cards: SAST Findings, Swarm Confirmed, Novel (Δ vs SAST), SAST FP Removed
- Precision / Recall / F1 cards (displayed if ground truth provided)
- Duration and estimated token count (with GPT-4o cost equivalent for comparison)

---

### ◈ Sandbox Mode

**⬡ Agent Graph tab**
- Live React Flow node graph (Orchestrator → Workers → Challengers → Verdict Engine)
- Nodes pulse and glow in real-time when the corresponding LLM is generating
- Fully interactive: drag, zoom, pan

**◈ Live Logs tab**
- Colour-coded terminal with icons per log type
- Auto-scrolls to latest line, 2,000-line buffer

**🧠 Steer panel** (both modes)
- Inject natural-language guidance mid-scan via `POST /api/scan/{id}/steer`

---

## Metrics & Benchmarking

The `MetricsEngine` tracks the following per run and saves to `results/real_world_{run_id}_metrics.json`:

| Metric | Description |
|---|---|
| `sast_finding_count` | Total raw SAST alerts |
| `swarm_schema_pass_rate` | % of LLM findings surviving the evidence gate |
| `swarm_confirmed` | Findings confirmed after challenge phase |
| `delta_vs_sast` | Novel confirmed findings NOT found by SAST |
| `sast_false_positives_found` | SAST alerts the swarm classified as FP |
| `precision` | TP / (TP + FP) — requires ground truth |
| `recall` | TP / (TP + FN) — requires ground truth |
| `f1` | Harmonic mean of precision and recall |
| `fnr` | False Negative Rate — requires ground truth |
| `severity_accuracy` | % of findings with correct severity (within 1 level) |
| `total_seconds` | Wall-clock runtime |
| `tokens_estimated` | Estimated token consumption (4 chars/token) |
| `cost_usd_estimated` | GPT-4o-equivalent cost for cloud comparison |

### Providing Ground Truth for CVE-based benchmarking

```python
from cycle11_ollama_swarm.agents.metrics_engine import GroundTruthEntry, MetricsEngine

ground_truth = [
    GroundTruthEntry(
        id="CVE-2023-12345",
        cwe="CWE-89",
        severity="high",
        file="src/database.py",
        description="SQL injection in user search",
        match_keywords=["sql injection", "user_search", "unsanitised"],
    ),
]

engine = MetricsEngine(run_id="...", repo_name="my-app", ground_truth=ground_truth)
```

---

## Configuration

### Real-World Mode Constraints (Backend)

```python
class RepoScanRequest(BaseModel):
    repo:             str            # Git URL or local path
    model:            str            # default: "llama3.2"
    challenger_model: str            # default: "qwen2.5-coder:7b"
    workers:          int            # 1–5
    challengers:      int            # 1–2
    sast_tools:       list[str]      # ["bandit", "semgrep"]
    no_sast:          bool           # skip SAST entirely
    max_chunks:       int            # 5–100 chunks per agent
```

### Structured Output Protocol

When `SWARM_STRUCTURED_OUTPUT=1` (set automatically by the backend), all orchestrators emit every log line as a JSON object instead of ANSI-coloured plain text:

```json
{ "type": "WORKER", "agent": "auth_analyst", "content": "..." }
```

To run manually in structured mode:
```bash
SWARM_STRUCTURED_OUTPUT=1 python run_real_world.py --repo ./my-project
```

### Ollama URL

Default: `http://127.0.0.1:11434`. To use a remote Ollama instance:
```bash
python run_real_world.py --repo ... --url http://remote-host:11434
```

---

## Key Innovations

### 1. Dynamic Technology-Aware Prompts
The `repo_ingester.py` builds a `RepoMap` that detects which technologies are actually present in the codebase (SQL, Redis, JWT, subprocess, eval, etc.). Agent prompts are then constrained to only claim vulnerabilities involving detected technologies. **This is the primary mechanism for eliminating technology hallucination at scale.**

### 2. Schema Gate — Anti-Hallucination Enforcement
Every LLM finding must supply all five evidence fields before entering the shared blackboard:

| Field | Requirement |
|---|---|
| `Location` | Exact function/class name |
| `Path` | Concrete data-flow path (attacker input → sensitive operation) |
| `Property` | Security invariant violated |
| `AttackerInput` | Concrete value or pattern the attacker provides |
| `Consequence` | Observable, exploitable outcome |

### 3. AST-Based Code Chunking
Python files are chunked at function and class boundaries using the AST, not raw line count. This ensures each LLM context window contains semantically coherent, complete code units. Non-Python files fall back to character-based chunking at 6,000-char boundaries.

### 4. SAST + LLM Complementarity
- **SAST tools**: deterministic, fast, no false negatives on pattern-matched rules
- **LLM triage**: removes SAST false positives using code context the rule engine lacks
- **LLM discovery**: finds complex logic flaws (authorisation bypasses, race conditions, business logic errors) that SAST cannot express as rules

### 5. Severity Decoupling (Cycle 19+)
Severity disagreements between a worker and a challenger **never cause a factually correct finding to be rejected**. A finding with an accurate factual claim but an overestimated severity is preserved as `PARTIAL_CONFIRMED`, not discarded.

---

## Development Guide

### Run the real-world scanner CLI directly

```bash
cd cycle11_ollama_swarm

# Scan a public GitHub repo
python run_real_world.py \
  --repo https://github.com/pallets/flask \
  --model llama3.2 \
  --challenger-model qwen2.5-coder:7b \
  --sast bandit semgrep \
  --max-chunks 20

# Scan a local project (no SAST)
python run_real_world.py \
  --repo ./path/to/my/project \
  --no-sast \
  --model llama3.2

# Structured JSON output (for backend integration)
SWARM_STRUCTURED_OUTPUT=1 python run_real_world.py --repo ...
```

### Run the sandbox research pipeline directly

```bash
cd cycle11_ollama_swarm

# Cycle 22 (latest)
python -u run_cycle11.py --cycle 22 --model llama3.2 \
    --challenger-model qwen2.5-coder:7b --workers 5

# Cycle 19 — evaluator decomposition baseline
python -u run_cycle11.py --cycle 19 --model llama3.2 --workers 5
```

### Frontend development

```bash
cd frontend
npm run dev       # Dev server with HMR at http://localhost:5173
npm run build     # Production build to frontend/dist/
npm run preview   # Preview the production build
```

### Backend development

```bash
cd backend
python -m uvicorn main:app --reload --port 8000
# Interactive API docs: http://localhost:8000/docs
```

### Adding a new SAST tool

1. Add a `run_<tool>(repo_root)` function to `agents/sast_runner.py` following the unified finding format.
2. Add the tool name to `run_all_sast()` dispatch.
3. Add the tool name to `RepoScanRequest.sast_tools` validation in `backend/main.py`.
4. Add it to the SAST tool checkbox list in `frontend/src/App.tsx`.

### Adding a new experiment cycle

1. Define the cycle key in the `main()` dispatch block of `run_cycle11.py`.
2. Add discovery prompts to `AGENT_ROLES` in `agents/research_agents.py`.
3. Add the key to the `cycle` field pattern in `backend/main.py`.
4. Add it to `CYCLE_OPTIONS` in `frontend/src/App.tsx`.

---

<div align="center">

Built with ⬡ Antigravity · Powered by Ollama · Runs entirely locally · Zero cloud dependency

</div>
