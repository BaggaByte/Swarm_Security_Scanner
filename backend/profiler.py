#!/usr/bin/env python3
"""
Sprint 1.2 — Pipeline Profiler
================================
Profiles each phase of the Swarm real-world scan pipeline and identifies
bottlenecks. Run this before and after optimizations to measure improvement.

Usage:
    python backend/profiler.py --repo ./path/to/local/repo
    python backend/profiler.py --repo ./path/to/local/repo --no-sast
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cycle11_ollama_swarm"))


def _fmt(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f}s"
    return f"{seconds / 60:.1f}m {seconds % 60:.0f}s"


def _bar(pct: float, width: int = 24) -> str:
    filled = int(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)


def profile_pipeline(repo_path: str, no_sast: bool = False, model: str = "llama3.2") -> dict:
    """
    Run the scan pipeline with per-phase timing instrumentation.
    Returns a dict of phase → duration_seconds.
    """
    from cycle11_ollama_swarm.agents.llm_client import LLMClient
    from cycle11_ollama_swarm.agents.repo_ingester import ingest_repository, repo_map_to_summary

    phases: dict[str, float] = {}
    print(f"\n{'═' * 60}")
    print(f"  SWARM PIPELINE PROFILER")
    print(f"  Repo:  {repo_path}")
    print(f"  Model: {model}")
    print(f"{'═' * 60}\n")

    # ── Phase 0: Ingest ──────────────────────────────────────────────────────
    print("▶ Phase 0 — Ingest …", flush=True)
    t0 = time.monotonic()
    repo_map, chunks = ingest_repository(repo_path)
    phases["ingest"] = time.monotonic() - t0
    print(
        f"  ✓ {len(chunks)} chunks from {repo_map.total_files} files "
        f"({repo_map.total_lines:,} lines) [{_fmt(phases['ingest'])}]",
        flush=True,
    )

    # ── Phase 1: SAST ────────────────────────────────────────────────────────
    if not no_sast:
        print("▶ Phase 1 — SAST (Bandit + Semgrep concurrent) …", flush=True)
        t0 = time.monotonic()
        from cycle11_ollama_swarm.agents.sast_runner import run_all_sast_detailed
        sast_findings, sast_statuses = run_all_sast_detailed(repo_path)
        phases["sast"] = time.monotonic() - t0
        for tool, st in sast_statuses.items():
            status_icon = "✓" if st["status"] == "complete" else "✗"
            print(
                f"  {status_icon} {tool}: {st['finding_count']} findings "
                f"[{_fmt(st['duration_seconds'])}]",
                flush=True,
            )
        print(
            f"  ✓ {len(sast_findings)} total SAST findings [{_fmt(phases['sast'])}]",
            flush=True,
        )
    else:
        sast_findings = []
        phases["sast"] = 0.0
        print("  ⊘ SAST skipped (--no-sast)", flush=True)

    # ── Phase 2: Triage (LLM review of SAST alerts) ──────────────────────────
    if sast_findings:
        print(f"▶ Phase 2 — Triage ({len(sast_findings)} alerts via LLM) …", flush=True)
        t0 = time.monotonic()
        client = LLMClient(model=model)
        from cycle11_ollama_swarm.agents.sast_runner import format_sast_finding_for_prompt

        tp_count = fp_count = 0
        batch_size = 5  # Sprint 1.2 batching
        batches = [sast_findings[i: i + batch_size] for i in range(0, len(sast_findings), batch_size)]

        for batch_idx, batch in enumerate(batches[:4]):  # Limit to 4 batches for profiling speed
            alert_text = "\n\n".join(
                f"[ALERT {i+1}]\n{format_sast_finding_for_prompt(f)}"
                for i, f in enumerate(batch)
            )
            prompt = (
                f"You are a security expert reviewing SAST alerts. "
                f"For each alert below, respond with a single line: ALERT <N>: TP or FP and one-sentence rationale.\n\n"
                f"{alert_text}"
            )
            response = client.generate(prompt, temperature=0.1) or ""
            for line in response.splitlines():
                if "TP" in line.upper():
                    tp_count += 1
                elif "FP" in line.upper():
                    fp_count += 1

        phases["triage"] = time.monotonic() - t0
        print(
            f"  ✓ Batch-triaged (first {min(4*batch_size, len(sast_findings))} alerts): "
            f"{tp_count} TP · {fp_count} FP [{_fmt(phases['triage'])}]",
            flush=True,
        )
    else:
        phases["triage"] = 0.0
        print("  ⊘ Triage skipped (no SAST findings)", flush=True)

    # ── Phase 3: Discovery (agent subset for profiling) ──────────────────────
    print(f"▶ Phase 3 — Discovery ({len(chunks)} chunks) …", flush=True)
    t0 = time.monotonic()
    # Just time the chunk enumeration + one small prompt for profiling
    client = LLMClient(model=model)
    sample_chunk = chunks[0] if chunks else None
    if sample_chunk:
        prompt = (
            f"Analyse this code chunk for security vulnerabilities. "
            f"Respond with NONE if there are no findings.\n\n```\n{sample_chunk.content[:500]}\n```"
        )
        _ = client.generate(prompt, temperature=0.2)
    phases["discovery_sample"] = time.monotonic() - t0
    # Extrapolate full discovery time
    phases["discovery_estimated"] = phases["discovery_sample"] * len(chunks)
    print(
        f"  ✓ Sample chunk: {_fmt(phases['discovery_sample'])} → "
        f"~{_fmt(phases['discovery_estimated'])} estimated for {len(chunks)} chunks",
        flush=True,
    )

    # ── Summary ──────────────────────────────────────────────────────────────
    measured = {k: v for k, v in phases.items() if "estimated" not in k}
    total = sum(measured.values())
    estimated_total = (
        total - phases.get("discovery_sample", 0) + phases.get("discovery_estimated", 0)
    )

    print(f"\n{'─' * 60}")
    print(f"  {'Phase':<28} {'Time':>10}  {'% of Total':>10}  Bar")
    print(f"{'─' * 60}")
    for phase, duration in measured.items():
        pct = (duration / total * 100) if total > 0 else 0
        print(f"  {phase:<28} {_fmt(duration):>10}  {pct:>9.1f}%  {_bar(pct, 20)}")
    print(f"{'─' * 60}")
    print(f"  {'MEASURED TOTAL':<28} {_fmt(total):>10}")
    print(f"  {'ESTIMATED FULL SCAN':<28} {_fmt(estimated_total):>10}")
    print(f"{'═' * 60}")

    if estimated_total > 120:
        mins = estimated_total / 60
        print(f"\n⚠️  Estimated full scan: {mins:.1f} min — above 2-min target.")
        print("   Bottleneck suggestions:")
        if phases.get("discovery_estimated", 0) > phases.get("ingest", 0) * 2:
            print("   • Discovery: use --max-chunks to limit chunk count")
            print("   • Discovery: switch to faster model (groq/ or nim/) for agent calls")
        if phases.get("triage", 0) > 20:
            print("   • Triage: batch_size=10 to halve LLM round-trips")
        if phases.get("ingest", 0) > 30:
            print("   • Ingest: check repo size — consider .swarmignore patterns")
    else:
        print(f"\n✅ Estimated full scan: {_fmt(estimated_total)} — within 2-min target.")

    return {
        "phases": phases,
        "total_measured_seconds": total,
        "estimated_full_scan_seconds": estimated_total,
        "chunks": len(chunks),
        "sast_findings": len(sast_findings),
        "model": model,
        "repo": repo_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile Swarm pipeline phases")
    parser.add_argument("--repo", required=True, help="Local repo path to profile")
    parser.add_argument("--no-sast", action="store_true", help="Skip SAST phase")
    parser.add_argument("--model", default=os.getenv("SWARM_PROFILE_MODEL", "llama3.2"))
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON results to file (optional)",
    )
    args = parser.parse_args()

    result = profile_pipeline(
        repo_path=args.repo,
        no_sast=args.no_sast,
        model=args.model,
    )

    if args.output:
        import json as _json
        Path(args.output).write_text(_json.dumps(result, indent=2), encoding="utf-8")
        print(f"\n📄 Profile written to: {args.output}")


if __name__ == "__main__":
    main()
