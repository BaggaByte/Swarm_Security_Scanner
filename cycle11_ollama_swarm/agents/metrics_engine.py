"""
Real-World Metrics Engine
==========================
Tracks Precision, Recall, FPR, FNR, Delta vs SAST, Severity Accuracy,
and Compute Efficiency across real-world scan runs.

When ground truth is available (e.g. from CVE datasets), full PR/RC
metrics are computed. When no ground truth is given, the engine reports
relative metrics (Swarm vs SAST, Swarm vs single-LLM baseline).

Metrics tracked per run:
  - Precision   = TP / (TP + FP)
  - Recall      = TP / (TP + FN)
  - F1          = 2 * (P * R) / (P + R)
  - FPR         = FP / (FP + TN)  [only with full ground truth]
  - FNR         = FN / (TP + FN)  [only with full ground truth]
  - Delta_vs_SAST       = findings in Swarm NOT found by SAST (novel discoveries)
  - Delta_vs_single_LLM = findings in Swarm NOT found by single LLM
  - Severity_accuracy   = % of findings with correct severity (within 1 level)
  - Time_seconds        = total wall-clock runtime
  - Tokens_estimated    = estimated LLM token consumption
  - Schema_pass_rate    = % of LLM findings that passed the Schema Gate
  - Human_verified      = % of confirmed findings that a human verified
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Severity ordering (for distance comparison)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5,
}


def severity_distance(a: str, b: str) -> int:
    """Return the absolute difference in severity level between two findings."""
    return abs(
        SEVERITY_ORDER.get(a.lower(), 5) -
        SEVERITY_ORDER.get(b.lower(), 5)
    )


# ---------------------------------------------------------------------------
# Ground-truth entry
# ---------------------------------------------------------------------------

@dataclass
class GroundTruthEntry:
    """A single known vulnerability used as ground truth for evaluation."""
    id: str                        # e.g. "CVE-2023-12345" or "GT-AUTH-TOKEN"
    cwe: Optional[str]             # e.g. "CWE-89"
    severity: str                  # critical | high | medium | low
    file: Optional[str]            # relevant file (if known)
    description: str
    match_keywords: list[str]      # keywords that identify this finding in LLM output


# ---------------------------------------------------------------------------
# Run-level metrics snapshot
# ---------------------------------------------------------------------------

@dataclass
class RunMetrics:
    """Complete metrics snapshot for a single scan run."""
    run_id: str
    repo_name: str
    timestamp: float = field(default_factory=time.time)

    # ---- SAST baseline ----
    sast_finding_count: int = 0
    sast_severity_breakdown: dict = field(default_factory=dict)

    # ---- LLM Swarm raw output ----
    swarm_raw_findings: int = 0     # Before schema gate
    swarm_schema_pass: int = 0      # After schema gate
    swarm_schema_pass_rate: float = 0.0
    swarm_confirmed: int = 0        # After challenger consensus
    swarm_partial: int = 0
    swarm_refuted: int = 0
    swarm_inconclusive: int = 0

    # ---- Comparative metrics ----
    delta_vs_sast: int = 0          # Swarm-confirmed findings NOT in SAST output
    sast_false_positives_found: int = 0  # SAST alerts Swarm classified as FP

    # ---- ROI / Triage Engine Metrics ----
    triage_fp_reduction_rate: float = 0.0
    triage_time_saved_mins: float = 0.0  # Kept for schema compatibility; not estimated without reviewer data.
    swarm_consensus_rate: float = 0.0
    triage_inconclusive_rate: float = 0.0
    
    # ---- Human-in-the-loop Feedback Metrics ----
    reviewer_override_rate: float = 0.0
    harmful_dismissal_rate: float = 0.0

    # ---- Accuracy metrics (require ground truth) ----
    has_ground_truth: bool = False
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    fpr: float = 0.0
    fnr: float = 0.0
    severity_accuracy: float = 0.0  # % within 1 severity level

    # ---- Compute efficiency ----
    total_seconds: float = 0.0
    tokens_estimated: int = 0       # Rough estimate: avg 4 chars/token
    cost_usd_estimated: float = 0.0 # For cloud API parity comparison

    # ---- Human verification ----
    human_verified: int = 0
    human_confirmed: int = 0
    human_false_positive_rate: float = 0.0

    def finalize(self):
        """Compute derived metrics after all data is in."""
        # Schema pass rate
        if self.swarm_raw_findings > 0:
            self.swarm_schema_pass_rate = round(
                self.swarm_schema_pass / self.swarm_raw_findings, 3
            )

        # Precision / Recall / F1
        if self.has_ground_truth:
            tp, fp, fn = self.true_positives, self.false_positives, self.false_negatives
            self.precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
            self.recall    = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
            p, r = self.precision, self.recall
            self.f1        = round(2 * p * r / (p + r), 3) if (p + r) > 0 else 0.0
            self.fnr       = round(fn / (tp + fn), 3) if (tp + fn) > 0 else 0.0

        # Human FPR
        if self.human_verified > 0:
            self.human_false_positive_rate = round(
                1.0 - (self.human_confirmed / self.human_verified), 3
            )

        # Estimated token cost (Ollama is free, but for comparison with GPT-4 pricing)
        if self.tokens_estimated > 0:
            # GPT-4o: $5/1M input tokens as reference
            self.cost_usd_estimated = round(self.tokens_estimated / 1_000_000 * 5.0, 4)

    def to_dict(self) -> dict:
        self.finalize()
        return asdict(self)

    def summary_lines(self) -> list[str]:
        self.finalize()
        lines = [
            f"  ══════════════════════════════════════════════════════",
            f"  REAL-WORLD METRICS REPORT  ·  Run: {self.run_id}",
            f"  ══════════════════════════════════════════════════════",
            f"  Repository:    {self.repo_name}",
            f"  Duration:      {self.total_seconds:.1f}s",
            f"  Tokens (est.): {self.tokens_estimated:,} (~GPT-4o equiv: ${self.cost_usd_estimated:.4f})",
            f"",
            f"  ── SAST Baseline ─────────────────────────────────────",
            f"  SAST Findings:         {self.sast_finding_count}",
            f"  SAST Severity:         {self.sast_severity_breakdown}",
            f"",
            f"  ── LLM Swarm Output ──────────────────────────────────",
            f"  Raw LLM findings:      {self.swarm_raw_findings}",
            f"  Schema gate pass:      {self.swarm_schema_pass} ({self.swarm_schema_pass_rate:.0%})",
            f"  Confirmed:             {self.swarm_confirmed}",
            f"  Partial:               {self.swarm_partial}",
            f"  Refuted:               {self.swarm_refuted}",
            f"  Inconclusive:          {self.swarm_inconclusive}",
            f"  ── Delta Analysis ────────────────────────────────────",
            f"  Novel Swarm findings (not in SAST):  {self.delta_vs_sast}",
            f"  Alerts classified as false positive: {self.sast_false_positives_found}",
            f"  ── ROI & Triage ──────────────────────────────────────",
            f"  False-positive share of triage:       {self.triage_fp_reduction_rate:.1%}",
            f"  Reviewer Time Saved:                 not measured",
            f"  Unanimous Triage Rate:               {self.swarm_consensus_rate:.1%}",
            f"  Inconclusive Rate:                   {self.triage_inconclusive_rate:.1%}",
            f"",
            f"  ── Human-in-the-Loop Feedback ────────────────────────",
            f"  Reviewer Override Rate:              {self.reviewer_override_rate:.1%}",
            f"  Harmful Dismissal Rate:              {self.harmful_dismissal_rate:.1%}",
        ]
        if self.has_ground_truth:
            lines += [
                f"",
                f"  ── Accuracy (vs Ground Truth) ────────────────────",
                f"  True Positives:  {self.true_positives}",
                f"  False Positives: {self.false_positives}",
                f"  False Negatives: {self.false_negatives}",
                f"  Precision:       {self.precision:.3f}",
                f"  Recall:          {self.recall:.3f}",
                f"  F1 Score:        {self.f1:.3f}",
                f"  FNR:             {self.fnr:.3f}",
                f"  Severity Acc:    {self.severity_accuracy:.0%}",
            ]
        if self.human_verified > 0:
            lines += [
                f"",
                f"  ── Human Verification ────────────────────────────",
                f"  Verified: {self.human_verified}  |  Confirmed: {self.human_confirmed}",
                f"  Human FPR: {self.human_false_positive_rate:.0%}",
            ]
        lines.append(f"  ══════════════════════════════════════════════════════")
        return lines


# ---------------------------------------------------------------------------
# Metrics Engine (stateful, per-run)
# ---------------------------------------------------------------------------

class MetricsEngine:
    """Accumulates metrics during a real-world scan run."""

    def __init__(self, run_id: str, repo_name: str, ground_truth: Optional[list[GroundTruthEntry]] = None):
        self.metrics = RunMetrics(run_id=run_id, repo_name=repo_name)
        self.ground_truth = ground_truth or []
        self.metrics.has_ground_truth = len(self.ground_truth) > 0
        self._start_time = time.time()
        self._confirmed_findings: list[dict] = []  # Accumulated Swarm-confirmed findings
        self._sast_findings: list[dict] = []

    def record_sast_results(self, sast_findings: list[dict]):
        """Record SAST baseline results."""
        self._sast_findings = sast_findings
        self.metrics.sast_finding_count = len(sast_findings)
        sev_breakdown: dict[str, int] = {}
        for f in sast_findings:
            sev = f.get("severity", "LOW")
            sev_breakdown[sev] = sev_breakdown.get(sev, 0) + 1
        self.metrics.sast_severity_breakdown = sev_breakdown

    def record_llm_raw(self, count: int):
        """Record how many raw LLM findings were generated (before schema gate)."""
        self.metrics.swarm_raw_findings += count

    def record_schema_results(self, passed: int, rejected: int):
        """Record schema gate results."""
        self.metrics.swarm_schema_pass += passed

    def record_verdict(self, verdict: str, finding: dict):
        """Record a final verdict for a finding."""
        v = verdict.strip().upper().replace("-", "_").replace(" ", "_")
        if v in {"CONFIRMED", "TRUE_POSITIVE", "TP"}:
            self.metrics.swarm_confirmed += 1
            self._confirmed_findings.append(finding)
        elif v in {"PARTIAL", "PARTIALLY_SUPPORTED", "PARTIAL_CONFIRMED"}:
            self.metrics.swarm_partial += 1
        elif v in {"REFUTED", "FALSE_POSITIVE", "FP", "INVALID", "FULL_INVALID"}:
            self.metrics.swarm_refuted += 1
        else:
            self.metrics.swarm_inconclusive += 1

    def record_token_usage(self, prompt_chars: int, response_chars: int):
        """Accumulate estimated token usage (4 chars per token rough estimate)."""
        self.metrics.tokens_estimated += (prompt_chars + response_chars) // 4

    def record_human_verification(self, finding: dict, is_real: bool):
        """Record a human verification decision."""
        self.metrics.human_verified += 1
        if is_real:
            self.metrics.human_confirmed += 1

    def compute_delta_vs_sast(self):
        """
        Compute how many Swarm-confirmed findings are NOT covered by SAST.
        A SAST finding "covers" a Swarm finding if they share the same file
        and the SAST finding is within ±5 lines of the Swarm finding's location.
        """
        novel = 0
        for cf in self._confirmed_findings:
            finding_file = str(cf.get("file") or "").replace("\\", "/").strip("./").lower()
            try:
                finding_line = int(cf.get("line", 0))
            except (TypeError, ValueError):
                finding_line = 0

            covered = False
            if finding_file and finding_line > 0:
                for sf in self._sast_findings:
                    sast_file = str(sf.get("file") or "").replace("\\", "/").strip("./").lower()
                    try:
                        sast_line = int(sf.get("line", 0))
                    except (TypeError, ValueError):
                        sast_line = 0
                    same_file = (
                        sast_file == finding_file
                        or sast_file.endswith("/" + finding_file)
                        or finding_file.endswith("/" + sast_file)
                    )
                    if same_file and sast_line > 0 and abs(sast_line - finding_line) <= 5:
                        covered = True
                        break
            if not covered:
                novel += 1
        self.metrics.delta_vs_sast = novel

    def compute_sast_triage(self, triage_results: list[dict]):
        """
        Record how many SAST alerts the Swarm classified as False Positives,
        and calculate ROI metrics (FP reduction rate, time saved, consensus rate).
        Each entry in triage_results: {"finding_idx": int, "verdict": "TP"|"FP"|"INCONCLUSIVE", "confidence": "HIGH"|"MEDIUM"|"LOW", "rationale": str}
        """
        total_triaged = len(triage_results)
        if total_triaged == 0:
            return

        fp_count = sum(1 for r in triage_results if r.get("verdict") == "FP")
        inconclusive_count = sum(1 for r in triage_results if r.get("verdict") == "INCONCLUSIVE")
        
        self.metrics.sast_false_positives_found = fp_count
        self.metrics.triage_fp_reduction_rate = fp_count / total_triaged
        self.metrics.triage_inconclusive_rate = inconclusive_count / total_triaged

        # Model confidence is not evidence of agreement; only explicit unanimous
        # role votes count as consensus. This is still one model under role prompts.
        unanimous = sum(1 for r in triage_results if r.get("unanimous") is True)
        self.metrics.swarm_consensus_rate = unanimous / total_triaged

    def compute_ground_truth_accuracy(self):
        """
        Compare confirmed findings against the ground truth list.
        Updates TP, FP, FN, and severity_accuracy.
        """
        if not self.ground_truth:
            return

        matched_gt: set[str] = set()

        for cf in self._confirmed_findings:
            text = (
                cf.get("hypothesis", "") + " " +
                cf.get("evidence", "") + " " +
                cf.get("content", "")
            ).lower()

            is_tp = False
            for gt in self.ground_truth:
                if any(kw.lower() in text for kw in gt.match_keywords):
                    matched_gt.add(gt.id)
                    is_tp = True
                    break

            if is_tp:
                self.metrics.true_positives += 1
            else:
                self.metrics.false_positives += 1

        self.metrics.false_negatives = len(self.ground_truth) - len(matched_gt)

        # Severity accuracy
        correct_sev = 0
        for cf in self._confirmed_findings:
            cf_sev = cf.get("severity", "unknown").lower()
            for gt in self.ground_truth:
                if any(kw.lower() in (cf.get("hypothesis", "") + cf.get("evidence", "")).lower()
                       for kw in gt.match_keywords):
                    if severity_distance(cf_sev, gt.severity) <= 1:
                        correct_sev += 1
                    break
        total = len(self._confirmed_findings)
        self.metrics.severity_accuracy = round(correct_sev / total, 3) if total > 0 else 0.0

    def finalize(self) -> RunMetrics:
        """Compute all derived metrics and return the final RunMetrics."""
        self.metrics.total_seconds = round(time.time() - self._start_time, 2)
        self.compute_delta_vs_sast()
        if self.ground_truth:
            self.compute_ground_truth_accuracy()
        self.metrics.finalize()
        return self.metrics

    def save(self, output_path: Path):
        """Save metrics as JSON."""
        m = self.finalize()
        output_path.write_text(json.dumps(m.to_dict(), indent=2), encoding="utf-8")
        print(f"  [METRICS] Saved to {output_path}", flush=True)
