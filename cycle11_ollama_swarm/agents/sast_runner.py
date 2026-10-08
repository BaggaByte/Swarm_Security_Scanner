"""
Real-World SAST Runner
========================
Wraps industry-standard SAST tools (Bandit, Semgrep) into a unified
finding format that the Swarm can use as its Phase 0 baseline.

The LLM Swarm then operates in two modes:
  1. TRIAGE MODE   — review each SAST alert and classify as True/False Positive
  2. DISCOVERY MODE — hunt for complex logic flaws SAST tools miss

Unified SAST finding format:
  {
    "tool":      "bandit" | "semgrep",
    "rule_id":   str,           # e.g. "B106" or "python.lang.security.audit...."
    "file":      str,           # relative path
    "line":      int,
    "col":       int,
    "severity":  "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
    "confidence":"HIGH" | "MEDIUM" | "LOW",
    "cwe":       str | None,    # e.g. "CWE-89"
    "message":   str,
    "code":      str,           # snippet of the flagged code
  }
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from .redaction import redact_sensitive_content


# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------

SEVERITY_MAP_BANDIT = {
    "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW",
}

import re

SEVERITY_MAP_SEMGREP = {
    "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
    "CRITICAL": "CRITICAL",
}

CWE_TAGS_SEMGREP = re.compile(r"CWE-\d+")
BENCHMARK_DIRS = {"sandbox_target", "benchmark", "benchmarks", "benchmark_fixtures"}
TEST_FIXTURE_DIRS = {"fixtures", "test_fixtures", "testdata"}


def _source_scope(path: str) -> str:
    parts = {part.lower() for part in path.replace("\\", "/").split("/")}
    if parts & BENCHMARK_DIRS:
        return "benchmark_fixture"
    if parts & TEST_FIXTURE_DIRS:
        return "test_fixture"
    return "application"


class SASTToolError(RuntimeError):
    """A SAST tool could not produce a trustworthy result."""


def _diagnostic(result: subprocess.CompletedProcess, limit: int = 1200) -> str:
    text = (result.stderr or result.stdout or "").strip()
    return text[:limit] if text else "no diagnostic output"


def _parse_tool_json(result: subprocess.CompletedProcess, tool: str) -> dict:
    for raw in (result.stdout or "", result.stderr or ""):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Some CLI versions print a status line before the JSON document.
            first_object = raw.find("{")
            last_object = raw.rfind("}")
            try:
                if first_object < 0 or last_object < first_object:
                    continue
                data = json.loads(raw[first_object:last_object + 1])
            except json.JSONDecodeError:
                continue
        if isinstance(data, dict):
            return data
    raise SASTToolError(
        f"{tool} returned invalid JSON (exit {result.returncode}): {_diagnostic(result)}"
    )

# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------

def _bandit_available() -> bool:
    return shutil.which("bandit") is not None


def run_bandit(repo_root: str) -> list[dict]:
    """
    Run Bandit against the entire repository root.
    Returns a list of unified SAST findings.
    """
    if not _bandit_available():
        raise SASTToolError("Bandit is not installed or is not on PATH.")

    print("  [SAST] Running Bandit …", flush=True)
    result = subprocess.run(
        [
            "bandit",
            "-r", repo_root,
            "-f", "json",
            "--quiet",
            "-x", ".venv,venv,node_modules,dist,build",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )

    # Bandit exits non-zero if it finds issues — that's fine
    data = _parse_tool_json(result, "Bandit")
    if result.returncode not in (0, 1):
        raise SASTToolError(f"Bandit exited with code {result.returncode}: {_diagnostic(result)}")
    if data.get("errors"):
        raise SASTToolError(f"Bandit reported scan errors: {str(data['errors'])[:1200]}")

    findings = []
    for r in data.get("results", []):
        # Extract snippet
        code_snippet = redact_sensitive_content(r.get("code", "").strip()[:400])
        cwe_str = None
        cwe_info = r.get("issue_cwe", {})
        if cwe_info:
            cwe_id = cwe_info.get("id", "")
            if cwe_id:
                cwe_str = f"CWE-{cwe_id}"

        rel_file = os.path.relpath(r.get("filename", ""), repo_root).replace("\\", "/")
        findings.append({
            "tool":       "bandit",
            "rule_id":    r.get("test_id", ""),
            "rule_name":  r.get("test_name", ""),
            "file":       rel_file,
            "source_scope": _source_scope(rel_file),
            "line":       r.get("line_number", 0),
            "col":        r.get("col_offset", 0),
            "severity":   SEVERITY_MAP_BANDIT.get(r.get("issue_severity", "LOW"), "LOW"),
            "confidence": r.get("issue_confidence", "LOW"),
            "cwe":        cwe_str,
            "message":    redact_sensitive_content(r.get("issue_text", "")),
            "code":       code_snippet,
            "more_info":  r.get("more_info", ""),
        })

    print(f"  [SAST] Bandit: {len(findings)} findings.", flush=True)
    return findings


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------

def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(repo_root: str, rulesets: Optional[list[str]] = None) -> list[dict]:
    """
    Run Semgrep with the supplied rulesets (defaults to p/security-audit).
    Returns a list of unified SAST findings.
    """
    if not _semgrep_available():
        raise SASTToolError("Semgrep is not installed or is not on PATH.")

    if rulesets is None:
        rulesets = ["p/security-audit", "p/owasp-top-ten"]

    print(f"  [SAST] Running Semgrep (rulesets: {rulesets}) …", flush=True)

    cmd = [
        "semgrep",
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--timeout", "60",
    ]
    for pattern in (
        ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore",
        ".netrc", "credentials", "credentials.json",
        "node_modules", ".git", "dist", "build", ".venv", "venv", "env",
        "vendor", "third_party", ".pytest_cache", ".mypy_cache", "*.egg-info",
    ):
        cmd += ["--exclude", pattern]
    for rs in rulesets:
        cmd += ["--config", rs]
    cmd.append(repo_root)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )

    data = _parse_tool_json(result, "Semgrep")

    # Semgrep uses exit code 1 when it finds matches. Exit code 2 indicates a
    # scan error, and JSON can still contain partial results in that case.
    if result.returncode not in (0, 1):
        raise SASTToolError(
            f"Semgrep exited with code {result.returncode}: {_diagnostic(result)}"
        )
    errors = data.get("errors", [])
    if errors:
        if not isinstance(errors, list):
            errors = [errors]
        details = "; ".join(
            str(error.get("message", error)) if isinstance(error, dict) else str(error)
            for error in errors[:5]
        )
        raise SASTToolError(f"Semgrep reported {len(errors)} scan error(s): {details[:1200]}")

    findings = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        severity_raw = r.get("extra", {}).get("severity", "INFO")
        severity = SEVERITY_MAP_SEMGREP.get(severity_raw.upper(), "LOW")

        # Extract CWE tags
        cwe_tags = meta.get("cwe", [])
        if isinstance(cwe_tags, str):
            cwe_tags = [cwe_tags]
        cwe_str = ", ".join(cwe_tags) if cwe_tags else None

        # Snippet
        code_snippet = redact_sensitive_content(r.get("extra", {}).get("lines", "").strip()[:400])
        rel_file = os.path.relpath(r.get("path", ""), repo_root).replace("\\", "/")

        findings.append({
            "tool":       "semgrep",
            "rule_id":    r.get("check_id", ""),
            "rule_name":  r.get("check_id", "").split(".")[-1],
            "file":       rel_file,
            "source_scope": _source_scope(rel_file),
            "line":       r.get("start", {}).get("line", 0),
            "col":        r.get("start", {}).get("col", 0),
            "severity":   severity,
            "confidence": meta.get("confidence", "MEDIUM"),
            "cwe":        cwe_str,
            "message":    redact_sensitive_content(r.get("extra", {}).get("message", "")),
            "code":       code_snippet,
            "more_info":  meta.get("references", [None])[0] if meta.get("references") else None,
            "owasp":      meta.get("owasp", None),
        })

    print(f"  [SAST] Semgrep: {len(findings)} findings.", flush=True)
    return findings


# ---------------------------------------------------------------------------
# Unified runner
# ---------------------------------------------------------------------------

def run_all_sast_detailed(repo_root: str, tools: Optional[list[str]] = None) -> tuple[list[dict], dict[str, dict]]:
    """
    Run all selected SAST tools and return findings plus per-tool status.

    Args:
        repo_root: Absolute path to the repository root.
        tools:     List of tools to run. Defaults to ["bandit", "semgrep"].
    """
    if tools is None:
        tools = ["bandit", "semgrep"]

    runners = {"bandit": run_bandit, "semgrep": run_semgrep}
    selected = [(tool, runners.get(tool.lower())) for tool in tools]
    statuses: dict[str, dict] = {}

    def run_tool(runner) -> tuple[Optional[list[dict]], float, Optional[str]]:
        started = time.monotonic()
        try:
            return runner(repo_root), time.monotonic() - started, None
        except Exception as exc:
            return None, time.monotonic() - started, str(exc)

    supported = [(tool, runner) for tool, runner in selected if runner is not None]
    for tool, runner in selected:
        if runner is None:
            statuses[tool] = {
                "status": "failed",
                "finding_count": 0,
                "duration_seconds": 0.0,
                "error": "Unsupported SAST tool",
            }

    # SAST tools operate on the same immutable checkout and are independent.
    # Run them together so total wall time is close to the slowest tool rather
    # than the sum of their individual runtimes. Reassemble results in request
    # order below to keep finding and status output deterministic.
    with ThreadPoolExecutor(max_workers=max(1, len(supported))) as executor:
        futures = {
            executor.submit(run_tool, runner): tool
            for tool, runner in supported
        }
        completed: dict[str, tuple[Optional[list[dict]], float, Optional[str]]] = {}
        for future in as_completed(futures):
            completed[futures[future]] = future.result()

    all_findings: list[dict] = []
    for tool, runner in selected:
        if runner is None:
            continue
        findings, duration, error = completed[tool]
        if error is not None:
            statuses[tool] = {
                "status": "failed",
                "finding_count": 0,
                "duration_seconds": round(duration, 3),
                "error": error,
            }
            print(f"  [SAST] {tool}: FAILED — {error}", flush=True)
            continue
        findings = findings or []
        all_findings.extend(findings)
        statuses[tool] = {
            "status": "complete",
            "finding_count": len(findings),
            "duration_seconds": round(duration, 3),
            "error": None,
        }

    # Deduplicate by (file, line, rule_id)
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in all_findings:
        key = (f["file"], f["line"], f["rule_id"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort by severity, then file
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda x: (sev_order.get(x["severity"], 5), x["file"], x["line"]))

    print(
        f"  [SAST] Combined: {len(all_findings)} raw findings → "
        f"{len(deduped)} after deduplication.",
        flush=True,
    )
    return deduped, statuses


def run_all_sast(repo_root: str, tools: Optional[list[str]] = None) -> list[dict]:
    """Backward-compatible findings-only wrapper."""
    findings, _ = run_all_sast_detailed(repo_root, tools)
    return findings


# ---------------------------------------------------------------------------
# SAST finding formatter for LLM prompts
# ---------------------------------------------------------------------------

def format_sast_finding_for_prompt(finding: dict) -> str:
    """Render a single SAST finding as structured text for an LLM reviewer."""
    lines = [
        f"SAST ALERT — {finding['tool'].upper()} / {finding['rule_id']}",
        f"  File:       {finding['file']}:{finding['line']}",
        f"  Source:     {finding.get('source_scope', 'application')}",
        f"  Severity:   {finding['severity']}  (Confidence: {finding['confidence']})",
        f"  CWE:        {finding.get('cwe') or 'not mapped'}",
        f"  Message:    {finding['message']}",
        f"  Code:",
    ]
    for code_line in finding.get("code", "").splitlines():
        lines.append(f"    {code_line}")
    return "\n".join(lines)


def format_sast_summary(findings: list[dict]) -> str:
    """Produce a compact summary table of all SAST findings."""
    if not findings:
        return "No SAST findings."

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    lines = [
        f"SAST SUMMARY: {len(findings)} findings",
        "  Breakdown: " + " | ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items())),
        "",
        "  Top findings:",
    ]
    for i, f in enumerate(findings[:20]):  # Show first 20 in summary
        cwe = f.get("cwe") or ""
        lines.append(
            f"  [{i+1:2d}] [{f['severity']:8s}] {f['file']}:{f['line']} — "
            f"{f['message'][:70]}  {cwe}"
        )
    if len(findings) > 20:
        lines.append(f"  ... and {len(findings) - 20} more")

    return "\n".join(lines)
