"""
Real-World Repository Security Orchestrator
=============================================
A new top-level orchestrator that performs security analysis on real
repositories rather than the artificial sandbox benchmarks.

Pipeline (Phase 0–5):
  Phase 0 — Ingest: clone/walk repo, build RepoMap, chunk code
  Phase 1 — SAST:   Bandit + Semgrep baseline
  Phase 2 — Triage: Swarm reviews each SAST alert (True/False Positive)
  Phase 3 — Discovery: Swarm hunts for logic flaws SAST missed
  Phase 4 — Challenge: Challenger agents review all Swarm discoveries
  Phase 5 — Metrics: Precision/Recall/Delta-vs-SAST report

Key differences from run_cycle11.py (research harness):
  - Accepts a real repository URL or local path
  - Dynamic technology-aware prompts (no hardcoded "file I/O only" constraints)
  - SAST integration as Phase 1 (not just a regex pre-filter)
  - Structured JSON output (always-on, no env var needed)
  - Full metrics engine for real-world benchmarking

Usage:
  python run_real_world.py --repo https://github.com/org/repo \\
      --model llama3.2 --challenger-model qwen2.5-coder:7b \\
      --workers 5 --sast bandit semgrep

  python run_real_world.py --repo ./path/to/local/repo \\
      --model llama3.2 --no-sast
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Optional

# Force UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from agents.llm_client import LLMClient
from agents.repo_ingester import (
    ingest_repository, repo_map_to_summary, RepoMap, CodeChunk,
)
from agents.sast_runner import run_all_sast, format_sast_finding_for_prompt, format_sast_summary
from agents.metrics_engine import MetricsEngine, GroundTruthEntry
from agents.schema_validator import filter_findings
from agents.memory import get_conn, make_db_path, set_meta, record_finding

# Always emit structured JSON so the backend can parse it
def _EMIT(log_type, agent, content, **kwargs):
    payload = {"type": log_type, "agent": agent, "content": content}
    payload.update(kwargs)
    print(json.dumps(payload), flush=True)


# ---------------------------------------------------------------------------
# Technology-aware schema validator override
# ---------------------------------------------------------------------------

def build_dynamic_hallucination_pattern(tech_inventory: list[str]):
    """
    Build a regex pattern of technologies that are NOT in the repo.
    This replaces the hardcoded pattern from the research harness.
    """
    import re
    # Full technology catalogue
    all_techs = {
        "sql":             r"sql\s+injection|sqli|sqlite3?\.execute|SELECT\s+\*|INSERT\s+INTO",
        "deserialization": r"pickle\.loads|pickle\.load|unpickling|yaml\.load\(",
        "eval":            r"\beval\s*\(|\bexec\s*\(|__import__|compile\s*\(",
        "buffer_overflow": r"buffer\s+overflow|heap\s+spray|stack\s+smashing|shellcode",
        "redis":           r"\bredis\b",
        "mongodb":         r"\bmongodb\b|\bmongoose\b",
        "graphql":         r"\bgraphql\b",
        "ldap":            r"\bldap\b",
        "xpath":           r"\bxpath\b",
        "xxe":             r"\bxxe\b|xml\s+external\s+entity",
    }
    # Keep only techs NOT detected in the repo
    absent_techs = {k: v for k, v in all_techs.items() if k not in tech_inventory}
    if not absent_techs:
        return None
    pattern_str = r"\b(" + "|".join(absent_techs.values()) + r")\b"
    return re.compile(pattern_str, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Dynamic discovery agent system prompts
# ---------------------------------------------------------------------------

def build_investigation_prompt(sast_finding: dict, chunk: CodeChunk, repo_summary: str, agent_focus: str) -> str:
    """Generate a dynamic investigation prompt for a specific SAST finding."""
    return textwrap.dedent(f"""\
        You are an expert security researcher specialising in {agent_focus}.
        You are analysing a REAL codebase. Your job is to investigate a SAST finding.

        {repo_summary}

        === SAST FINDING TO INVESTIGATE ===
        Tool: {sast_finding.get('tool', 'Unknown')}
        Rule: {sast_finding.get('rule_id', 'Unknown')}
        Message: {sast_finding.get('message', 'Unknown')}
        File: {sast_finding.get('file')}
        Line: {sast_finding.get('line')}

        === RELEVANT CODE CONTEXT ===
        File: {chunk.file_path} (lines {chunk.start_line}–{chunk.end_line})
        Type: {chunk.chunk_type} — {chunk.name}

        {chunk.content}

        === INSTRUCTIONS ===
        Investigate the finding based ONLY on your focus area ({agent_focus}).
        Is this finding a TRUE_POSITIVE, a FALSE_POSITIVE, or INCONCLUSIVE?
        If you cannot definitively trace the data flow or prove the sanitization mechanism, you MUST vote INCONCLUSIVE.

        Respond in this EXACT format:
        VERDICT: TRUE_POSITIVE|FALSE_POSITIVE|INCONCLUSIVE
        CONFIDENCE: HIGH|MEDIUM|LOW
        RATIONALE: <1-2 sentence explanation>
    """)


INVESTIGATION_AGENT_ROLES = [
    ("reachability",     "tracing data flows from entry points to sinks. If unreachable, it's a FP."),
    ("exploitability",   "analysing validation, sanitisation, or type constraints that block exploitation."),
    ("context_assessor", "evaluating business logic, impact, and whether the behaviour is intentional."),
]


# ---------------------------------------------------------------------------
# SAST Triage: have the LLM review each SAST alert
# ---------------------------------------------------------------------------

def triage_sast_finding(
    client: LLMClient,
    sast_finding: dict,
    chunk_content: str,
    repo_summary: str,
) -> dict:
    """
    Ask the LLM to classify a SAST alert as True Positive or False Positive.
    Returns: {"verdict": "TP"|"FP", "confidence": "HIGH"|"MEDIUM"|"LOW", "rationale": str}
    """
    prompt = textwrap.dedent(f"""\
        You are a senior security engineer triaging SAST alerts.

        {repo_summary}

        === SAST ALERT ===
        {format_sast_finding_for_prompt(sast_finding)}

        === RELEVANT CODE CONTEXT ===
        {chunk_content[:2000]}

        === YOUR TASK ===
        Classify this SAST alert as either:
          TRUE_POSITIVE  — A real, exploitable vulnerability
          FALSE_POSITIVE — Not exploitable given this context

        Respond in this EXACT format:
        VERDICT: TRUE_POSITIVE|FALSE_POSITIVE
        CONFIDENCE: HIGH|MEDIUM|LOW
        RATIONALE: <1-2 sentence explanation>
    """)

    try:
        response = client.generate(prompt=prompt, temperature=0.1)
    except Exception as e:
        return {"verdict": "TP", "confidence": "LOW", "rationale": f"LLM error: {e}"}

    verdict = "TP"
    confidence = "LOW"
    rationale = response

    for line in (response or "").splitlines():
        if line.startswith("VERDICT:"):
            raw = line.split(":", 1)[1].strip().upper()
            verdict = "FP" if "FALSE" in raw else "TP"
        elif line.startswith("CONFIDENCE:"):
            confidence = line.split(":", 1)[1].strip().upper()
        elif line.startswith("RATIONALE:"):
            rationale = line.split(":", 1)[1].strip()

    return {"verdict": verdict, "confidence": confidence, "rationale": rationale}


# ---------------------------------------------------------------------------
# Discovery phase (real repo)
# ---------------------------------------------------------------------------

def run_swarm_triage(
    client: LLMClient,
    conn,
    sast_findings: list[dict],
    chunks: list[CodeChunk],
    repo_map: RepoMap,
    metrics: MetricsEngine,
    num_workers: int = 3,
) -> list[dict]:
    """
    Run the investigation agents across all high-priority SAST alerts.
    """
    repo_summary = repo_map_to_summary(repo_map)
    priority_sast = [f for f in sast_findings if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")][:30]

    roles_to_use = INVESTIGATION_AGENT_ROLES[:num_workers] if num_workers < len(INVESTIGATION_AGENT_ROLES) else INVESTIGATION_AGENT_ROLES

    _EMIT("PHASE", "orchestrator",
          f"PHASE 2 — SWARM TRIAGE: {len(roles_to_use)} agents × {len(priority_sast)} alerts")

    triage_results = []

    for i, sf in enumerate(priority_sast):
        # Resolve context: try to find the exact chunk, or fallback to the file, or fallback to cross references
        context_chunk = next(
            (c for c in chunks if sf["file"] in c.file_path and c.start_line <= sf["line"] <= c.end_line),
            next((c for c in chunks if sf["file"] in c.file_path), None)
        )
        if not context_chunk:
            continue

        _EMIT("WORKER", "orchestrator", f"[{i+1}/{len(priority_sast)}] Investigating {sf['file']}:{sf['line']}")
        
        agent_verdicts = []
        for agent_key, agent_focus in roles_to_use:
            prompt = build_investigation_prompt(sf, context_chunk, repo_summary, agent_focus)
            metrics.record_token_usage(len(prompt), 0)

            try:
                response = client.generate(prompt=prompt, temperature=0.1)
            except Exception as e:
                _EMIT("ERROR", agent_key, f"LLM error: {e}")
                continue

            metrics.record_token_usage(0, len(response or ""))

            verdict = "TP"
            confidence = "LOW"
            rationale = response

            for line in (response or "").splitlines():
                if line.startswith("VERDICT:"):
                    raw = line.split(":", 1)[1].strip().upper()
                    if "INCONCLUSIVE" in raw:
                        verdict = "INCONCLUSIVE"
                    elif "FALSE" in raw:
                        verdict = "FP"
                    else:
                        verdict = "TP"
                elif line.startswith("CONFIDENCE:"):
                    confidence = line.split(":", 1)[1].strip().upper()
                elif line.startswith("RATIONALE:"):
                    rationale = line.split(":", 1)[1].strip()
            
            agent_verdicts.append({
                "agent": agent_key,
                "verdict": verdict,
                "confidence": confidence,
                "rationale": rationale
            })
            _EMIT("WORKER", agent_key, f"→ {verdict} ({confidence})")

        # Consensus logic: 
        # If any agent votes TP -> TP (Fail safe)
        # If all agents agree on FP with HIGH confidence -> FP
        # Otherwise -> INCONCLUSIVE
        
        has_tp = any(av["verdict"] == "TP" for av in agent_verdicts)
        all_high_fp = len(agent_verdicts) > 0 and all(av["verdict"] == "FP" and av["confidence"] == "HIGH" for av in agent_verdicts)
        
        if has_tp:
            final_verdict = "TP"
        elif all_high_fp:
            final_verdict = "FP"
        else:
            final_verdict = "INCONCLUSIVE"

        consensus_rationale = []
        for av in agent_verdicts:
            consensus_rationale.append(f"{av['agent']}: {av['verdict']} - {av['rationale']}")
        
        triage_results.append({
            "sast_finding": sf,
            "verdict": final_verdict,
            "confidence": "HIGH" if all_high_fp else "LOW",
            "rationale": " | ".join(consensus_rationale),
            "finding_idx": i,
        })
        
        v_str = f"✓ TP" if final_verdict == "TP" else (f"✗ FP" if final_verdict == "FP" else "⋯ INCONCLUSIVE")
        _EMIT("VERDICT", "triage", f"[{i+1}/{len(priority_sast)}] Consensus: {v_str}", finding=sf, verdict=final_verdict, rationale=" | ".join(consensus_rationale))

    return triage_results



def _parse_findings_from_response(response: str, chunk: CodeChunk) -> list[dict]:
    """Parse structured FINDING: blocks from LLM response."""
    findings = []
    current: dict = {}

    for line in response.splitlines():
        line = line.strip()
        if line.upper() == "FINDING:":
            if current and current.get("title"):
                findings.append(current)
            current = {
                "file": chunk.file_path,
                "start_line": chunk.start_line,
                "language": chunk.language,
            }
        elif line.startswith("Title:"):
            current["title"] = line.split(":", 1)[1].strip()
        elif line.startswith("Location:"):
            current["location"] = line.split(":", 1)[1].strip()
        elif line.startswith("Path:"):
            current["path"] = line.split(":", 1)[1].strip()
        elif line.startswith("Property:"):
            current["property"] = line.split(":", 1)[1].strip()
        elif line.startswith("AttackerInput:"):
            current["attacker_input"] = line.split(":", 1)[1].strip()
        elif line.startswith("Consequence:"):
            current["consequence"] = line.split(":", 1)[1].strip()
        elif line.startswith("Severity:"):
            raw_sev = line.split(":", 1)[1].strip().lower()
            if raw_sev in ("critical", "high", "medium", "low", "info"):
                current["severity"] = raw_sev
        elif line == "---":
            if current and current.get("title"):
                findings.append(current)
            current = {}

    if current and current.get("title"):
        findings.append(current)

    return findings


def _dynamic_filter_findings(
    findings: list[dict],
    hallucination_pattern,
    agent_id: str,
) -> tuple[list[dict], list[dict]]:
    """Apply dynamic schema gate using the repo-derived hallucination pattern."""
    valid, rejected = [], []
    for f in findings:
        # Field completeness
        missing = [
            field for field in ("location", "path", "property", "attacker_input", "consequence")
            if not f.get(field, "").strip()
        ]
        if missing:
            f["rejection_reason"] = f"MISSING_FIELDS: {', '.join(missing)}"
            rejected.append(f)
            continue

        # Dynamic hallucination check
        combined = f"{f.get('path','')} {f.get('consequence','')} {f.get('attacker_input','')}".lower()
        if hallucination_pattern and hallucination_pattern.search(combined):
            match = hallucination_pattern.search(combined)
            f["rejection_reason"] = f"TECH_HALLUCINATION: '{match.group(0)}' not detected in repo"
            rejected.append(f)
            _EMIT("SYSTEM", agent_id,
                  f"[SCHEMA-GATE] Dropped: {f.get('title','?')[:60]} — {f['rejection_reason']}")
            continue

        valid.append(f)

    return valid, rejected


# ---------------------------------------------------------------------------
# Discovery & Challenge Passes
# ---------------------------------------------------------------------------

def _chunk_risk_score(chunk: CodeChunk) -> int:
    score = 0
    path = chunk.file_path.lower()
    if any(k in path for k in ["auth", "login", "security", "crypto", ".github", "config", "docker", "jwt", "secret", "password", "oauth"]):
        score += 10
    if chunk.chunk_type in ["config", "module"]:
        score += 5
    return score

def run_swarm_discovery(
    client: LLMClient,
    conn,
    chunks: list[CodeChunk],
    repo_map: RepoMap,
    metrics: MetricsEngine,
    max_chunks: int,
    hallucination_pattern
) -> list[dict]:
    repo_summary = repo_map_to_summary(repo_map)
    
    chunks_to_scan = sorted(chunks, key=_chunk_risk_score, reverse=True)[:max_chunks]
    
    _EMIT("PHASE", "orchestrator", f"PHASE 3 — DISCOVERY: Hunting for novel flaws in {len(chunks_to_scan)} highest-risk chunks")

    discovery_results = []
    
    for i, chunk in enumerate(chunks_to_scan):
        _EMIT("WORKER", "orchestrator", f"[{i+1}/{len(chunks_to_scan)}] Scanning {chunk.file_path}")
        prompt = textwrap.dedent(f"""\\
            You are a senior security researcher looking for complex logic flaws.
            {repo_summary}
            
            === CODE TO ANALYSE ===
            File: {chunk.file_path}
            {chunk.content}
            
            Find exploitable vulnerabilities. Output each finding in this format:
            FINDING:
            Title: <title>
            Location: <line number>
            Path: <file path>
            Property: <vulnerability type>
            AttackerInput: <how attacker reaches this>
            Consequence: <impact>
            Severity: CRITICAL|HIGH|MEDIUM|LOW
            ---
        """)
        try:
            response = client.generate(prompt=prompt, temperature=0.2)
        except Exception as e:
            _EMIT("ERROR", "discovery", f"LLM error: {e}")
            continue

        raw_findings = _parse_findings_from_response(response, chunk)
        metrics.record_llm_raw(len(raw_findings))
        valid_findings, rejected = _dynamic_filter_findings(raw_findings, hallucination_pattern, "discovery")
        metrics.record_schema_results(len(valid_findings), len(rejected))
        for f in valid_findings:
            f["chunk_idx"] = i
            try:
                line_num = int(str(f.get("location")).split()[0])
            except (ValueError, TypeError, IndexError):
                line_num = chunk.start_line
            # Transform to standard triage finding format
            formatted_finding = {
                "file": chunk.file_path,
                "line": line_num,
                "message": f.get("title"),
                "severity": f.get("severity", "MEDIUM"),
                "code": f.get("snippet", chunk.content),
                "tool": "swarm_discovery",
                "rule_id": "discovery-001"
            }
            discovery_results.append(formatted_finding)
            _EMIT("SYSTEM", "discovery", f"Found novel issue: {f.get('title')}")
    return discovery_results

def run_swarm_challenge(
    client: LLMClient,
    conn,
    findings: list[dict],
    chunks: list[CodeChunk],
    metrics: MetricsEngine,
    num_challengers: int = 1,
) -> list[dict]:
    _EMIT("PHASE", "orchestrator", f"PHASE 4 — CHALLENGE: Adversarial peer review of {len(findings)} discovered findings with {num_challengers} challengers")
    confirmed = []
    for i, f in enumerate(findings):
        _EMIT("CHALLENGER", "orchestrator", f"[{i+1}/{len(findings)}] Challenging: {f.get('message')}")
        context_chunk = next((c for c in chunks if f["file"] in c.file_path), None)
        content = context_chunk.content if context_chunk else ""
        prompt = textwrap.dedent(f"""\
            You are an adversarial reviewer. Is this finding a true positive?
            Finding: {f.get('message')}
            Location: {f.get('file')}:{f.get('line')}
            
            Code:
            {content[:2000]}
            
            Reply with EXACTLY:
            VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
            RATIONALE: <reason>
        """)
        
        agent_verdicts = []
        for c_idx in range(num_challengers):
            try:
                response = client.generate(prompt=prompt, temperature=0.1 + (0.1 * c_idx))
                metrics.record_token_usage(len(prompt), len(response or ""))
            except Exception:
                agent_verdicts.append("INCONCLUSIVE")
                continue
                
            if "FALSE_POSITIVE" in response:
                agent_verdicts.append("FALSE_POSITIVE")
            elif "TRUE_POSITIVE" in response:
                agent_verdicts.append("TRUE_POSITIVE")
            else:
                agent_verdicts.append("INCONCLUSIVE")
                
        if any(v == "FALSE_POSITIVE" for v in agent_verdicts):
            _EMIT("VERDICT", "challenger", f"Refuted: {f.get('message')}")
            metrics.record_verdict("FP", f)
        elif all(v == "TRUE_POSITIVE" for v in agent_verdicts) and agent_verdicts:
            _EMIT("VERDICT", "challenger", f"Confirmed: {f.get('message')}")
            metrics.record_verdict("TP", f)
            f["triage_rationale"] = "Confirmed by all challengers"
            confirmed.append(f)
        else:
            _EMIT("VERDICT", "challenger", f"Inconclusive: {f.get('message')}")
            metrics.record_verdict("INCONCLUSIVE", f)
            
    return confirmed


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Real-World Swarm Security Scanner")
    parser.add_argument("--repo", required=True,
                        help="Git repository URL or local path to scan")
    parser.add_argument("--branch", default=None,
                        help="Specific branch to scan for PRs")
    parser.add_argument("--model", default="llama3.2",
                        help="Ollama model for discovery agents")
    parser.add_argument("--challenger-model", default="qwen2.5-coder:7b",
                        help="Ollama model for challenger agents")
    parser.add_argument("--workers", type=int, default=5,
                        help="Number of discovery agent types to use (1-5)")
    parser.add_argument("--challengers", type=int, default=2,
                        help="Number of challenger agents per finding (1-2)")
    parser.add_argument("--sast", nargs="*", default=["bandit", "semgrep"],
                        help="SAST tools to run (bandit, semgrep). Use --no-sast to disable.")
    parser.add_argument("--no-sast", action="store_true",
                        help="Skip SAST phase entirely")
    parser.add_argument("--sarif-file", default=None,
                        help="Path to an external SARIF file to ingest findings from")
    parser.add_argument("--max-chunks", type=int, default=20,
                        help="Max code chunks per discovery agent")
    parser.add_argument("--diff-json", default=None,
                        help="JSON string of modified files and lines for differential scans")
    parser.add_argument("--clone-to", default=None,
                        help="Directory to clone the repo into (default: temp dir)")
    parser.add_argument("--output-dir", default=None,
                        help="Directory for results output (default: ./results/)")
    parser.add_argument("--url", default="http://127.0.0.1:11434",
                        help="Ollama API base URL")
    args = parser.parse_args()

    run_id = str(int(time.time()))
    import tempfile
    output_dir = Path(args.output_dir) if args.output_dir else Path(tempfile.gettempdir()) / "swarm_out"
    output_dir.mkdir(parents=True, exist_ok=True)

    _EMIT("PHASE", "orchestrator", f"Real-World Swarm Scanner — Run {run_id}")
    _EMIT("PHASE", "orchestrator", f"Target: {args.repo}")

    # ── Phase 0: Repository Ingestion ─────────────────────────────────────
    _EMIT("PHASE", "orchestrator", "PHASE 0 — INGEST: Cloning / walking repository")
    diff_filter = json.loads(args.diff_json) if args.diff_json else None
    repo_map, chunks = ingest_repository(args.repo, clone_to=args.clone_to, diff_filter=diff_filter, branch=args.branch)
    _EMIT("SYSTEM", "ingester",
          f"Repo: {repo_map.repo_name} | Files: {repo_map.total_files} | "
          f"Chunks: {len(chunks)} | Frameworks: {repo_map.framework_signals} | "
          f"Tech: {repo_map.technology_inventory}")

    try:
        sys.path.append(str(Path(__file__).parent.parent))
        from backend.database import save_architecture
        from dataclasses import asdict
        map_dict = asdict(repo_map)
        map_dict.pop("files", None)
        map_dict.pop("root", None)
        save_architecture(args.repo, json.dumps(map_dict))
    except Exception as e:
        _EMIT("ERROR", "ingester", f"Failed to save architecture map: {e}")

    # ── Metrics engine setup ───────────────────────────────────────────────
    metrics = MetricsEngine(run_id=run_id, repo_name=repo_map.repo_name)

    # ── Ollama connectivity check ──────────────────────────────────────────
    client = LLMClient(model=args.model, base_url=args.url)
    available = client.list_models()
    if not available:
        _EMIT("ERROR", "runner", f"Cannot reach Ollama at {args.url}. Is 'ollama serve' running?")
        sys.exit(1)
    if args.model not in available:
        _EMIT("ERROR", "runner", f"Model '{args.model}' not found in Ollama. Available: {available}")
        sys.exit(1)
    _EMIT("SYSTEM", "runner", f"Ollama OK — using {args.model}")

    challenger_client = LLMClient(model=args.challenger_model, base_url=args.url)

    # ── Phase 1: SAST Baseline ─────────────────────────────────────────────
    sast_findings: list[dict] = []
    _EMIT("PHASE", "orchestrator", "PHASE 1 — SAST/SARIF: Gathering static analysis baseline")

    if args.sarif_file and os.path.exists(args.sarif_file):
        from agents.sarif_parser import parse_sarif
        _EMIT("SYSTEM", "sast", f"Ingesting external SARIF findings from {args.sarif_file}")
        sarif_results = parse_sarif(args.sarif_file)
        sast_findings.extend(sarif_results)
        _EMIT("SYSTEM", "sast", f"Loaded {len(sarif_results)} findings from SARIF")

    if not args.no_sast and args.sast:
        _EMIT("SYSTEM", "sast", f"Running internal SAST tools: {', '.join(args.sast)}")
        internal_sast = run_all_sast(repo_map.root, tools=args.sast)
        sast_findings.extend(internal_sast)
        
    if sast_findings:
        metrics.record_sast_results(sast_findings)
        _EMIT("SYSTEM", "sast",
              f"Phase 1 complete: {len(sast_findings)} total findings — "
              + format_sast_summary(sast_findings).replace("\n", " "))
    else:
        _EMIT("SYSTEM", "sast", "Phase 1 complete: 0 findings")

    # ── Phase 2: Swarm Investigation ───────────────────────────────────────
    db_path = make_db_path(ROOT, cycle_key="rw")
    conn = get_conn(db_path=db_path)
    set_meta(conn, "repo", args.repo)
    set_meta(conn, "model", args.model)
    set_meta(conn, "run_id", run_id)

    triage_results = []
    if sast_findings:
        triage_results = run_swarm_triage(client, conn, sast_findings, chunks, repo_map, metrics, num_workers=args.workers)
        metrics.compute_sast_triage(triage_results)
    
    # ── Phase 3: Discovery ─────────────────────────────────────────────────
    hallucination_pattern = build_dynamic_hallucination_pattern(repo_map.technology_inventory)
    discovery_findings = run_swarm_discovery(
        client, conn, chunks, repo_map, metrics, args.max_chunks, hallucination_pattern
    )
    
    # ── Phase 4: Challenge ─────────────────────────────────────────────────
    if discovery_findings:
        confirmed_discovery = run_swarm_challenge(
            challenger_client, conn, discovery_findings, chunks, metrics, num_challengers=args.challengers
        )
        # Format the confirmed discovery findings like triage results for metrics/output
        for i, df in enumerate(confirmed_discovery):
            triage_results.append({
                "sast_finding": df,
                "verdict": df["triage_verdict"],
                "confidence": "HIGH",
                "rationale": df["triage_rationale"],
                "finding_idx": 1000 + i, # Offset to distinguish from SAST
            })
            _EMIT("VERDICT", "triage", f"[DISCOVERY {i+1}] Consensus: ✓ TP", finding=df, verdict="TP", rationale=df["triage_rationale"])
    else:
        _EMIT("SYSTEM", "orchestrator", "No novel flaws discovered to challenge.")

    # ── Phase 5: Metrics & Reporting ──────────────────────────────────────
    _EMIT("PHASE", "orchestrator", "PHASE 5 — METRICS: Computing real-world evaluation")
    final_metrics = metrics.finalize()

    for line in final_metrics.summary_lines():
        _EMIT("SYSTEM", "metrics", line)

    metrics_path = output_dir / f"real_world_{run_id}_metrics.json"
    metrics.save(metrics_path)
    _EMIT("SYSTEM", "metrics", f"Metrics saved to {metrics_path}")

    # Save SAST findings
    if sast_findings:
        sast_path = output_dir / f"real_world_{run_id}_sast.json"
        sast_path.write_text(json.dumps(sast_findings, indent=2), encoding="utf-8")
        _EMIT("SYSTEM", "sast", f"SAST findings saved to {sast_path}")

    conn.close()
    _EMIT("DONE", "runner", f"Real-World scan complete — Run {run_id}")


if __name__ == "__main__":
    main()
