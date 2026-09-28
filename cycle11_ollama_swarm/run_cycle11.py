"""
Cycle 11/13A/13B/14/15/16 – Main Orchestrator
==============================================
Runs the full experiment:

  [CYCLE 15 – Hard Schema + Static Pre-Filter]
  Phase 0 – STATIC PRE-FILTER : deterministic AST/regex scanner; detects all 6 planted GT flaws
  Phase 1 – DISCOVERY         : 5 specialised agents analyse target code (serial to avoid CPU queue)
  Phase 2 – CHALLENGE         : 2 challenger agents review LLM findings (exactly 2, no drift)
  Phase 3 – VERDICT           : findings classified as confirmed / refuted / inconclusive
  Phase 4 – MEASUREMENT       : rich summary table, schema reject telemetry, infra error log

  [CYCLE 16 – Challenger Calibration]
  Identical discovery to Cycle 15. Challenger prompts IDENTICAL.
  Adds a calibration layer that preserves PARTIAL verdicts and classifies every
  rejection as CORRECT / OVERREJECTION / UNCERTAIN.
  Calibrated aggregation rule:
    FULL_VALID + FULL_VALID   -> STRICT_CONFIRMED
    FULL_VALID + PARTIAL      -> PARTIAL_CONFIRMED
    PARTIAL   + PARTIAL       -> PARTIAL_CONFIRMED
    FULL_INVALID + anything   -> NOT_CONFIRMED
    FULL_INVALID + FULL_INVALID -> REFUTED

Usage:
  # Cycle 16 – challenger calibration (diagnostic)
  python run_cycle11.py --cycle 16 --model llama3.2 --workers 5 --baseline

  # Cycle 15 – hard schema + static pre-filter
  python run_cycle11.py --cycle 15 --model llama3.2 --workers 5 --baseline
"""

import argparse
import json
import shutil
import sys
import textwrap
import time
from pathlib import Path

# Force UTF-8 output on Windows (avoids cp1252 UnicodeEncodeError)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Structured output protocol
# ---------------------------------------------------------------------------
import os
import re as _re
_STRUCTURED = os.environ.get("SWARM_STRUCTURED_OUTPUT", "") == "1"
_ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")


def _emit(log_type: str, agent: str, content: str) -> None:
    """Emit one log line.  In structured mode, always JSON; otherwise plain text."""
    clean = _ANSI_RE.sub("", content).strip()
    if _STRUCTURED:
        import json as _json
        print(_json.dumps({"type": log_type, "agent": agent, "content": clean}), flush=True)
    else:
        print(content, flush=True)

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
import os
import tempfile

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from agents.llm_client import LLMClient
from agents.memory import (
    get_conn, make_db_path, set_meta,
    get_all_findings, get_llm_findings, get_static_findings,
    get_all_verdicts, record_challenge, record_verdict,
    record_static_finding,
    get_duplicate_pairs, get_challenger_breakdown,
    get_schema_rejects, get_infra_errors, get_schema_audit,
)
from agents.research_agents import (
    ResearchAgent, ChallengerAgent, AGENT_ROLES,
)
from agents.static_filter import StaticPreFilter
from agents.schema_validator import HALLUCINATED_TECH_PATTERN


# ---------------------------------------------------------------------------
# Ground Truth Benchmark Definitions
# ---------------------------------------------------------------------------

CYCLE13A_GROUND_TRUTH = [
    {
        "id": "GT-AUTH-TOKEN",
        "name": "Predictable Session Token",
        "patterns": ["session token", "predictable token", "token", "session fixation", "token forgery"],
        "description": "Session tokens generated via MD5(username:time:secret) allowing predictable token forgery.",
    },
    {
        "id": "GT-AUTH-SECRET",
        "name": "Hardcoded SECRET_KEY",
        "patterns": ["secret_key", "hr-portal-internal-2024", "hardcoded secret", "hard-coded secret", "hardcoded key"],
        "description": "Static secret key 'hr-portal-internal-2024' hardcoded in application source.",
    },
    {
        "id": "GT-RBAC-IDOR-PATCH",
        "name": "Unrestricted Profile Updates (IDOR / Broken Auth)",
        "patterns": ["patch_profile", "idor", "caller_username", "arbitrary user", "unauthorized profile", "missing auth"],
        "description": "patch_profile updates any user profile without caller authentication or ownership check.",
    },
    {
        "id": "GT-RBAC-ENUM",
        "name": "Unrestricted Profile Retrieval (PII & Hash Exposure)",
        "patterns": ["get_employee_profile", "profile retrieval", "pii", "password_hash exposure", "user enumeration"],
        "description": "get_employee_profile returns full profile including password_hash without authorization check.",
    },
    {
        "id": "GT-DATA-MASS-EXPORT",
        "name": "Unrestricted Employee Export (Mass Exfiltration)",
        "patterns": ["export_all_records", "bulk export", "mass export", "mass exfiltration", "data dump"],
        "description": "export_all_records allows any caller to dump all employee records and password hashes.",
    },
    {
        "id": "GT-AUTH-MD5",
        "name": "MD5 Password Hashing",
        "patterns": ["md5", "hashlib.md5", "weak hash", "password_hash", "unsalted", "password hash"],
        "description": "Passwords hashed using obsolete, unsalted MD5 in login() and change_password().",
    },
]


def classify_finding(finding: dict, cycle_key: str) -> dict:
    """Classify a finding as known_benchmark or novel_discovery."""
    # Static pre-filter findings are always pre-classified
    if finding.get("source") == "static_pre_filter" or finding.get("pre_confirmed"):
        gt_id = finding.get("ground_truth_id")
        gt_name = next((g["name"] for g in CYCLE13A_GROUND_TRUTH if g["id"] == gt_id), None)
        return {
            "classification": "known_benchmark",
            "ground_truth_id": gt_id,
            "ground_truth_name": gt_name,
            "is_known_planted": True,
        }

    if cycle_key == "13b":
        return {
            "classification": "novel_discovery",
            "ground_truth_id": None,
            "ground_truth_name": None,
            "is_known_planted": False,
        }

    # 13a, 14, 15 all run against the planted-vulnerable target
    text = f"{finding.get('hypothesis', '')} {finding.get('evidence', '')}".lower()
    for gt in CYCLE13A_GROUND_TRUTH:
        if any(pat in text for pat in gt["patterns"]):
            return {
                "classification": "known_benchmark",
                "ground_truth_id": gt["id"],
                "ground_truth_name": gt["name"],
                "is_known_planted": True,
            }

    return {
        "classification": "novel_discovery",
        "ground_truth_id": None,
        "ground_truth_name": None,
        "is_known_planted": False,
    }


def _writable_dir(p: Path) -> Path:
    """Return p if writable, else fall back to TEMP."""
    try:
        p.mkdir(parents=True, exist_ok=True)
        test = p / ".write_test_tmp"
        test.write_text("x")
        test.unlink()
        return p
    except Exception:
        fallback = Path(tempfile.gettempdir()) / p.name
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


RESULTS_DIR = _writable_dir(Path(tempfile.gettempdir()) / "swarm_out")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _colour(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def _bold(t):   return _colour(t, "1")
def _green(t):  return _colour(t, "32")
def _red(t):    return _colour(t, "31")
def _yellow(t): return _colour(t, "33")
def _cyan(t):   return _colour(t, "36")
def _magenta(t):return _colour(t, "35")


def _banner(msg: str):
    width = 72
    if _STRUCTURED:
        _emit("PHASE", "orchestrator", msg)
    else:
        print()
        print("=" * width)
        print(f"  {msg}")
        print("=" * width)


# ---------------------------------------------------------------------------
# Phase 0: Static Pre-Filter  [NEW in Cycle 15]
# ---------------------------------------------------------------------------

def run_static_prefilter(conn, target_src: str) -> list[int]:
    """
    Run deterministic static analysis to detect all 6 planted GT flaws.
    Results are inserted as pre_confirmed=True findings, skipping Phase 2.
    Returns list of inserted finding IDs.
    """
    _banner("PHASE 0: STATIC PRE-FILTER  –  Deterministic ground-truth detection")

    sf = StaticPreFilter(target_src)
    static_findings = sf.run()

    ids = []
    for f in static_findings:
        fid = record_static_finding(conn, f)
        ids.append(fid)
        gt_id = f.get("ground_truth_id", "?")
        sev = f.get("severity", "?")
        colour = _red if sev in ("critical", "high") else _yellow
        print(f"  {_magenta('[STATIC]')}  [{colour(sev.upper().ljust(8))}]  {gt_id}  {f['hypothesis'][:70]}")

    print(f"\n  [OK] Static pre-filter: {_bold(str(len(ids)))} ground-truth flaws detected and pre-confirmed.")
    print(f"  These findings skip Phase 2 — they are deterministic, not probabilistic.")
    return ids


# ---------------------------------------------------------------------------
# Phase 1: Discovery (serial execution)
# ---------------------------------------------------------------------------

def run_discovery(
    client: LLMClient,
    conn,
    num_workers: int,
    target_src: str,
    cycle_key: str = "15",
) -> dict[str, tuple[list[int], int]]:
    """
    Run all specialised research agents SERIALLY.
    cycle_key is forwarded to agent.analyse() to select the correct prompt.
    Cycle 17: uses grounded 8-step prompt + _parse_grounded_findings parser.
    """
    label = "Grounded 8-step" if cycle_key in ("17", "18", "19", "20", "21") else "Evidence-first"
    _banner(f"PHASE 1: DISCOVERY  –  Serial {label} analysis (prevents CPU queue saturation)")

    role_keys = list(AGENT_ROLES.keys())[:num_workers]
    agent_map: dict[str, tuple[list[int], int]] = {}

    total_valid = 0
    total_rejected = 0

    for i, role_key in enumerate(role_keys):
        agent = ResearchAgent(
            agent_id=f"agent-{i+1:02d}-{role_key}",
            role_key=role_key,
            client=client,
            conn=conn,
        )
        role_info = AGENT_ROLES[role_key]
        print(f"\n  [{i+1}/{len(role_keys)}] {_cyan(role_info['name'])} starting ...")

        findings, elapsed = agent.analyse(target_src, cycle_key=cycle_key)
        valid_ids, rejected_count = agent.write_findings(
            findings, discovery_seconds=elapsed, target_src=target_src
        )

        total_valid += len(valid_ids)
        total_rejected += rejected_count
        agent_map[role_key] = (valid_ids, rejected_count)

        status = (
            f"{_bold(str(len(valid_ids)))} valid / "
            f"{_red(str(rejected_count))} schema-rejected"
        )
        print(f"  [{i+1}] {_cyan(role_info['name'])} → {status}  ({elapsed:.1f}s)")

    print(
        f"\n  [OK] Discovery complete. "
        f"Total valid LLM findings: {_bold(str(total_valid))}  |  "
        f"Schema-rejected (dropped): {_red(str(total_rejected))}"
    )
    return agent_map


# ---------------------------------------------------------------------------
# Phase 2: Challenge (LLM findings only, exactly 2 challengers)
# ---------------------------------------------------------------------------

def run_challenge(
    client: LLMClient,
    conn,
    target_src: str,
    num_challengers: int = 2,
    preserve_partial: bool = False,
    challenger_client: LLMClient = None,
    cycle_key: str = "15",
) -> None:
    """
    Two challenger agents independently review every LLM finding.
    Static pre-filter findings are skipped (they are pre-confirmed ground truth).
    Challenger count is strictly enforced at num_challengers (default 2).

    preserve_partial=True (Cycle 16): PARTIAL stays as 'partial' in stored verdict,
      raw_verdict is stored separately as FULL_VALID/PARTIAL/FULL_INVALID.
    preserve_partial=False (Cycle 15): PARTIAL -> 'refuted' (strict behaviour).
    """
    label = "PARTIAL PRESERVED" if preserve_partial else "STRICT"
    _banner(f"PHASE 2: CHALLENGE  –  Adversarial peer review ({label}, exactly {num_challengers} challengers, serial)")

    llm_findings = get_llm_findings(conn)
    if not llm_findings:
        print("  No LLM findings to challenge (all were schema-rejected or none generated).")
        return

    ch_client = challenger_client or client

    # Strictly cap challengers at num_challengers
    challengers = [
        ChallengerAgent(agent_id=f"challenger-{chr(65+j)}", client=ch_client, conn=conn)
        for j in range(min(num_challengers, 2))
    ]

    print(f"  Challenging {len(llm_findings)} LLM findings with {len(challengers)} independent challengers (serial) ...\n")

    for finding in llm_findings:
        votes = []
        raw_votes = []
        for ch in challengers:
            r = ch.challenge(finding, target_src, preserve_partial=preserve_partial, cycle_key=cycle_key)
            record_challenge(
                conn, finding["id"], ch.agent_id,
                r["reasoning"], r["verdict"],
                raw_verdict=r.get("raw_verdict"),
                factual_validity=r.get("factual_validity"),
                attack_path=r.get("attack_path"),
                security_property=r.get("security_property"),
                consequence=r.get("consequence"),
                severity_eval=r.get("severity_eval"),
                overall_verdict=r.get("overall_verdict"),
                related_real_issue=r.get("related_real_issue"),
                stated_claim_valid=r.get("stated_claim_valid"),
            )
            votes.append(r["verdict"])
            raw_votes.append(r.get("raw_verdict", "?"))

        all_confirmed = all(v == "confirmed" for v in votes)
        all_refuted   = all(v == "refuted"   for v in votes)
        has_partial   = any(v == "partial"   for v in votes)

        if all_confirmed:
            icon = _green("[+]")
        elif all_refuted:
            icon = _red("[-]")
        elif has_partial:
            icon = _yellow("[~]")
        else:
            icon = _yellow("[?]")

        raw_label = f"  raw={raw_votes}" if preserve_partial else ""
        print(f"  {icon}  Finding #{finding['id']:02d}  →  {votes}{raw_label}  |  {finding['hypothesis'][:55]}")

    print(f"\n  [OK] Challenge round complete.")


# ---------------------------------------------------------------------------
# Phase 3: Verdict aggregation
# ---------------------------------------------------------------------------

def run_verdict_aggregation(conn) -> None:
    """
    Aggregate per-finding challenge results into a final verdict.
    Static pre-filter findings are auto-confirmed without challenger votes.
    Strict consensus: ALL challengers must agree for confirmed/refuted.
    """
    _banner("PHASE 3: VERDICT AGGREGATION  (strict consensus)")

    all_findings = get_all_findings(conn)
    for f in all_findings:
        fid = f["id"]

        # Static pre-filter findings: auto-confirmed
        if f.get("source") == "static_pre_filter" or f.get("pre_confirmed"):
            record_verdict(
                conn, fid, "confirmed",
                confirmed_by="static_pre_filter",
                refuted_by=None,
                notes="Deterministic static analysis — pre-confirmed ground truth",
            )
            continue

        # LLM findings: strict challenger consensus
        rows = conn.execute(
            "SELECT challenger_id, verdict FROM challenges WHERE finding_id=?", (fid,)
        ).fetchall()
        votes = [r["verdict"] for r in rows]
        confirmed_by = [r["challenger_id"] for r in rows if r["verdict"] == "confirmed"]
        refuted_by   = [r["challenger_id"] for r in rows if r["verdict"] == "refuted"]

        n_challengers = len(votes)
        if n_challengers > 0 and len(confirmed_by) == n_challengers:
            final = "confirmed"
        elif n_challengers > 0 and len(refuted_by) == n_challengers:
            final = "refuted"
        elif n_challengers == 0:
            final = "inconclusive"  # no challenger reviewed this finding
        else:
            final = "inconclusive"  # split vote

        record_verdict(
            conn, fid, final,
            confirmed_by=", ".join(confirmed_by) or None,
            refuted_by=", ".join(refuted_by) or None,
            notes=f"Votes ({n_challengers} challengers): {votes}",
        )

    confirmed = conn.execute("SELECT count(*) FROM verdicts WHERE final_verdict='confirmed'").fetchone()[0]
    refuted   = conn.execute("SELECT count(*) FROM verdicts WHERE final_verdict='refuted'").fetchone()[0]
    inconc    = conn.execute("SELECT count(*) FROM verdicts WHERE final_verdict='inconclusive'").fetchone()[0]

    static_confirmed = conn.execute(
        "SELECT count(*) FROM verdicts v JOIN findings f ON f.id=v.finding_id "
        "WHERE v.final_verdict='confirmed' AND f.source='static_pre_filter'"
    ).fetchone()[0]
    llm_confirmed = confirmed - static_confirmed

    print(
        f"  Confirmed (total): {_green(str(confirmed))}  "
        f"[static: {_magenta(str(static_confirmed))} + LLM: {_green(str(llm_confirmed))}]  |  "
        f"Refuted: {_red(str(refuted))}  |  Inconclusive: {_yellow(str(inconc))}"
    )


# ---------------------------------------------------------------------------
# Phase 3B: Calibrated Verdict Aggregation  [CYCLE 16 ONLY]
# ---------------------------------------------------------------------------

# Ground truth reference for CORRECT/OVERREJECTION diagnostic
_GT_PATTERNS_BY_ID = {gt["id"]: gt["patterns"] for gt in CYCLE13A_GROUND_TRUTH}
_ALL_GT_PATTERNS = [p for gt in CYCLE13A_GROUND_TRUTH for p in gt["patterns"]]


def _finding_matches_any_gt(finding: dict) -> tuple[bool, str | None]:
    """Return (matches, gt_id) — whether this finding touches a known planted issue."""
    text = f"{finding.get('hypothesis', '')} {finding.get('evidence', '')}".lower()
    for gt in CYCLE13A_GROUND_TRUTH:
        if any(p in text for p in gt["patterns"]):
            return True, gt["id"]
    return False, None


def _apply_calibrated_rule(raw_verdicts: list[str]) -> str:
    """
    Apply the Cycle 16 calibrated aggregation rule to a list of raw verdicts.

    raw_verdicts: list of FULL_VALID | PARTIAL | FULL_INVALID

    Rules (in priority order):
      FULL_INVALID + anything       -> NOT_CONFIRMED  (one FULL_INVALID disqualifies)
      FULL_INVALID + FULL_INVALID   -> REFUTED        (both disqualify, special label)
      FULL_VALID   + FULL_VALID     -> STRICT_CONFIRMED
      FULL_VALID   + PARTIAL        -> PARTIAL_CONFIRMED
      PARTIAL      + PARTIAL        -> PARTIAL_CONFIRMED
    """
    if not raw_verdicts:
        return "INCONCLUSIVE"

    invalids  = raw_verdicts.count("FULL_INVALID")
    valids    = raw_verdicts.count("FULL_VALID")
    partials  = raw_verdicts.count("PARTIAL")

    if invalids == len(raw_verdicts):   # all FULL_INVALID
        return "REFUTED"
    if invalids > 0:                    # any FULL_INVALID
        return "NOT_CONFIRMED"
    if valids == len(raw_verdicts):     # all FULL_VALID
        return "STRICT_CONFIRMED"
    if valids > 0 and partials > 0:     # mix of FULL_VALID + PARTIAL
        return "PARTIAL_CONFIRMED"
    if partials == len(raw_verdicts):   # all PARTIAL
        return "PARTIAL_CONFIRMED"
    return "INCONCLUSIVE"


def _determine_overrejection(finding: dict, raw_verdicts: list[str], calibrated: str) -> tuple[str, str]:
    """
    For every Cycle 16 LLM finding that is NOT STRICT_CONFIRMED, determine whether the
    challenger rejection was:
      CORRECT      — no real security issue exists here
      OVERREJECTION — a real planted issue exists but evidence/path was wrong/overstated
      UNCERTAIN    — insufficient information to decide

    Returns (overrejection_status, explanation_note).
    """
    matches_gt, gt_id = _finding_matches_any_gt(finding)

    if calibrated == "STRICT_CONFIRMED":
        return "N/A", "Finding was strict-confirmed; overrejection not applicable."

    if calibrated in ("PARTIAL_CONFIRMED",):
        if matches_gt:
            return "OVERREJECTION", (
                f"Real planted issue {gt_id} exists; challengers partially agreed (PARTIAL). "
                "Evidence/path/consequence was incomplete but the underlying concern is real."
            )
        else:
            return "UNCERTAIN", (
                "Calibrated as PARTIAL_CONFIRMED but does not match a known planted issue. "
                "May be a real emergent finding or an overstated concern."
            )

    # REFUTED or NOT_CONFIRMED
    all_invalid = all(v == "FULL_INVALID" for v in raw_verdicts if v)

    if matches_gt and all_invalid:
        # Challengers said FULL_INVALID but a real planted issue with matching patterns exists
        # Check whether it's actually the right issue description
        return "OVERREJECTION", (
            f"Real planted issue {gt_id} exists in target code. Both challengers returned "
            "FULL_INVALID. The LLM identified the right vulnerability category but provided "
            "an incorrect or overstated evidence path/consequence."
        )
    elif matches_gt:
        return "OVERREJECTION", (
            f"Real planted issue {gt_id} exists. At least one challenger returned FULL_INVALID "
            "but the finding touches a genuine vulnerability. Likely an evidence quality problem."
        )
    else:
        # Does not match any planted GT pattern
        return "CORRECT", (
            "Finding does not match any known planted ground-truth issue. "
            "Challenger rejection appears correct (novel claim with insufficient evidence)."
        )


def run_calibrated_verdict_aggregation(conn) -> dict:
    """
    Cycle 16 calibration pass: aggregate raw_verdict fields using the calibrated rule
    and write both strict_verdict and calibrated_verdict into the verdicts table.
    Also computes per-finding overrejection_status.
    Returns summary counts.
    """
    _banner("PHASE 3: CALIBRATED VERDICT AGGREGATION  (Cycle 16 diagnostic)")

    all_findings = get_all_findings(conn)
    counts = {
        "static_confirmed": 0,
        "strict_confirmed": 0,
        "partial_confirmed": 0,
        "not_confirmed": 0,
        "refuted": 0,
        "inconclusive": 0,
        "overrejections": 0,
        "correct_rejections": 0,
        "uncertain": 0,
    }

    for f in all_findings:
        fid = f["id"]

        # Static pre-filter findings: always auto-confirmed
        if f.get("source") == "static_pre_filter" or f.get("pre_confirmed"):
            record_verdict(
                conn, fid, "confirmed",
                confirmed_by="static_pre_filter",
                notes="Deterministic static analysis — pre-confirmed ground truth",
                calibrated_verdict="STATIC_CONFIRMED",
                overrejection_status="N/A",
                calibration_notes="Static pre-filter finding — not subject to calibration.",
            )
            counts["static_confirmed"] += 1
            continue

        # LLM findings: get raw_verdict from challenges table
        rows = conn.execute(
            "SELECT challenger_id, verdict, raw_verdict FROM challenges WHERE finding_id=?",
            (fid,)
        ).fetchall()

        strict_votes = [r["verdict"] for r in rows]
        raw_votes    = [r["raw_verdict"] for r in rows if r["raw_verdict"] is not None]

        # -- Strict verdict (same rule as Cycle 15, preserved for comparison) --
        confirmed_by = [r["challenger_id"] for r in rows if r["verdict"] == "confirmed"]
        refuted_by   = [r["challenger_id"] for r in rows if r["verdict"] == "refuted"]
        n = len(strict_votes)
        if n > 0 and len(confirmed_by) == n:
            strict_final = "confirmed"
        elif n > 0 and len(refuted_by) == n:
            strict_final = "refuted"
        else:
            strict_final = "inconclusive"

        # -- Calibrated verdict --
        calibrated = _apply_calibrated_rule(raw_votes)

        # -- Overrejection diagnostic --
        overrejection_status, calibration_notes = _determine_overrejection(f, raw_votes, calibrated)

        # Update counts
        key_map = {
            "STRICT_CONFIRMED":  "strict_confirmed",
            "PARTIAL_CONFIRMED": "partial_confirmed",
            "NOT_CONFIRMED":     "not_confirmed",
            "REFUTED":           "refuted",
            "INCONCLUSIVE":      "inconclusive",
        }
        counts[key_map.get(calibrated, "inconclusive")] += 1
        if overrejection_status == "OVERREJECTION":
            counts["overrejections"] += 1
        elif overrejection_status == "CORRECT":
            counts["correct_rejections"] += 1
        elif overrejection_status == "UNCERTAIN":
            counts["uncertain"] += 1

        record_verdict(
            conn, fid, strict_final,
            confirmed_by=", ".join(confirmed_by) or None,
            refuted_by=", ".join(refuted_by) or None,
            notes=f"Strict votes ({n} challengers): {strict_votes}  |  Raw: {raw_votes}",
            calibrated_verdict=calibrated,
            overrejection_status=overrejection_status,
            calibration_notes=calibration_notes,
        )

    # Print summary
    total_llm = sum(1 for f in all_findings if f.get("source") == "llm")
    print(f"  Static pre-confirmed    : {_magenta(str(counts['static_confirmed']))}")
    print(f"  LLM STRICT_CONFIRMED    : {_green(str(counts['strict_confirmed']))}")
    print(f"  LLM PARTIAL_CONFIRMED   : {_yellow(str(counts['partial_confirmed']))}")
    print(f"  LLM NOT_CONFIRMED       : {_yellow(str(counts['not_confirmed']))}")
    print(f"  LLM REFUTED             : {_red(str(counts['refuted']))}")
    print(f"  LLM INCONCLUSIVE        : {_yellow(str(counts['inconclusive']))}")
    print(f"  --- Diagnostic ---")
    print(f"  OVERREJECTIONS          : {_yellow(str(counts['overrejections']))}  (real issue, bad path)")
    print(f"  CORRECT rejections      : {_green(str(counts['correct_rejections']))}  (no real issue)")
    print(f"  UNCERTAIN               : {_yellow(str(counts['uncertain']))}")

    return counts


# ---------------------------------------------------------------------------
# Phase 3C: Decomposed Verdict Aggregation  [CYCLE 19 ONLY]
# ---------------------------------------------------------------------------

def run_cycle19_verdict_aggregation(conn) -> dict:
    """
    Cycle 19 Decomposed Verdict Aggregation:
    Separates stated claim validity from underlying security property.
    Classifies every finding into:
      FULL_VALIDITY
      PARTIAL_VALIDITY
      OVERREJECTION
      CORRECT_REJECTION
    """
    _banner("PHASE 3: DECOMPOSED VERDICT AGGREGATION (Cycle 19)")

    all_findings = get_all_findings(conn)
    counts = {
        "static_confirmed": 0,
        "full_validity": 0,
        "partial_validity": 0,
        "overrejection": 0,
        "correct_rejection": 0,
        "factual_valid": 0,
        "attack_path_valid": 0,
        "security_property_valid": 0,
        "severity_disagreements": 0,
        "confirmed": 0,
        "partial": 0,
        "refuted": 0,
    }

    for f in all_findings:
        fid = f["id"]

        # Static pre-filter findings
        if f.get("source") == "static_pre_filter" or f.get("pre_confirmed"):
            record_verdict(
                conn, fid, "confirmed",
                confirmed_by="static_pre_filter",
                notes="Deterministic static analysis — pre-confirmed ground truth",
                calibrated_verdict="STATIC_CONFIRMED",
                overrejection_status="N/A",
                calibration_notes="Static pre-filter ground-truth flaw.",
                original_claim_verdict="CONFIRMED",
                underlying_assessment="REAL_ISSUE_PRESENT",
                decomposition_classification="FULL_VALIDITY",
            )
            counts["static_confirmed"] += 1
            counts["confirmed"] += 1
            counts["full_validity"] += 1
            counts["factual_valid"] += 1
            counts["attack_path_valid"] += 1
            counts["security_property_valid"] += 1
            continue

        # LLM findings
        rows = conn.execute(
            """SELECT challenger_id, verdict, raw_verdict, factual_validity, attack_path,
                      security_property, consequence, severity_eval, overall_verdict,
                      related_real_issue, stated_claim_valid
               FROM challenges WHERE finding_id=?""",
            (fid,)
        ).fetchall()

        n = len(rows)
        if n == 0:
            continue

        overalls = [r["overall_verdict"] or "INVALID" for r in rows]
        facts = [r["factual_validity"] or "INVALID" for r in rows]
        paths = [r["attack_path"] or "UNSUPPORTED" for r in rows]
        props = [r["security_property"] or "UNSUPPORTED" for r in rows]
        consqs = [r["consequence"] or "UNSUPPORTED" for r in rows]
        sevs = [r["severity_eval"] or "INDETERMINATE" for r in rows]
        related_issues = [bool(r["related_real_issue"]) for r in rows]
        stated_claims = [bool(r["stated_claim_valid"]) for r in rows]

        # Decomposed dimensional metrics (count findings where at least one challenger confirmed the dimension):
        if any(fv == "VALID" for fv in facts):
            counts["factual_valid"] += 1
        if any(ap == "SUPPORTED" for ap in paths):
            counts["attack_path_valid"] += 1
        if any(sp == "SUPPORTED" for sp in props):
            counts["security_property_valid"] += 1
        if any(se == "DISAGREE" for se in sevs):
            counts["severity_disagreements"] += 1

        matches_gt, gt_id = _finding_matches_any_gt(f)
        has_real_underlying = any(related_issues) or matches_gt or any(sp == "SUPPORTED" for sp in props)

        # Consensus evaluation
        all_confirmed = all(ov == "CONFIRMED" for ov in overalls)
        no_invalid = all(ov in ("CONFIRMED", "PARTIALLY_SUPPORTED") for ov in overalls)
        any_partial = any(ov == "PARTIALLY_SUPPORTED" for ov in overalls)

        if all_confirmed:
            classification = "FULL_VALIDITY"
            original_claim = "CONFIRMED"
            underlying = "REAL_ISSUE_PRESENT"
            final_v = "confirmed"
            calib_v = "STRICT_CONFIRMED"
            overrej_stat = "N/A"
            counts["full_validity"] += 1
            counts["confirmed"] += 1
        elif no_invalid and any_partial:
            classification = "PARTIAL_VALIDITY"
            original_claim = "PARTIALLY_SUPPORTED"
            underlying = "REAL_ISSUE_PRESENT"
            final_v = "partial"
            calib_v = "PARTIAL_CONFIRMED"
            overrej_stat = "N/A"
            counts["partial_validity"] += 1
            counts["partial"] += 1
        else:
            final_v = "refuted"
            original_claim = "REFUTED"
            calib_v = "REFUTED"
            counts["refuted"] += 1
            if has_real_underlying:
                classification = "OVERREJECTION"
                underlying = "REAL_ISSUE_PRESENT"
                overrej_stat = "OVERREJECTION"
                counts["overrejection"] += 1
            else:
                classification = "CORRECT_REJECTION"
                underlying = "NO_REAL_ISSUE"
                overrej_stat = "CORRECT"
                counts["correct_rejection"] += 1

        calib_note = (
            f"Factual: {facts} | Path: {paths} | Prop: {props} | "
            f"Cons: {consqs} | Sev: {sevs} | RelatedRealIssue: {related_issues}"
        )

        record_verdict(
            conn, fid, final_v,
            confirmed_by=", ".join(r["challenger_id"] for r in rows if r["overall_verdict"] == "CONFIRMED") or None,
            refuted_by=", ".join(r["challenger_id"] for r in rows if r["overall_verdict"] == "INVALID") or None,
            notes=f"Decomposed Overalls: {overalls}",
            calibrated_verdict=calib_v,
            overrejection_status=overrej_stat,
            calibration_notes=calib_note,
            original_claim_verdict=original_claim,
            underlying_assessment=underlying,
            decomposition_classification=classification,
        )

    print(f"  Static pre-confirmed      : {_magenta(str(counts['static_confirmed']))}")
    print(f"  FULL_VALIDITY (Confirmed) : {_green(str(counts['full_validity']))}")
    print(f"  PARTIAL_VALIDITY          : {_yellow(str(counts['partial_validity']))}")
    print(f"  OVERREJECTION             : {_yellow(str(counts['overrejection']))}  (stated claim invalid, real issue present)")
    print(f"  CORRECT_REJECTION         : {_green(str(counts['correct_rejection']))}  (no real issue)")
    print(f"  --- Decomposed Sub-metrics (LLM) ---")
    print(f"  Factual-valid findings    : {counts['factual_valid']}")
    print(f"  Attack-path-valid         : {counts['attack_path_valid']}")
    print(f"  Security-property-valid   : {counts['security_property_valid']}")
    print(f"  Severity disagreements    : {counts['severity_disagreements']}")

    return counts


# ---------------------------------------------------------------------------
# Phase 4: Baseline (single-agent simulation)
# ---------------------------------------------------------------------------

def run_single_agent_baseline(client: LLMClient, target_src: str) -> list[dict]:
    """Simulate what a single, generalist agent would find."""
    _banner("BASELINE: Single-agent (no collaboration, no schema gate)")

    system = "You are a general-purpose code reviewer. Review the provided Python code and identify any security or quality issues. List them briefly."
    prompt = textwrap.dedent(f"""\
        Review this Python code and list all issues:

        {target_src}

        Format each as:
        ISSUE: <title> – <one sentence description>""")

    try:
        response = client.chat(
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.2,
        )
    except ConnectionError as e:
        print(f"  Ollama unavailable: {e}")
        return []

    issues = []
    if response:
        for line in response.splitlines():
            cleaned = line.strip().lstrip("#*- 0123456789.)").strip().replace("**", "")
            if cleaned.upper().startswith("ISSUE:"):
                issues.append({"title": cleaned[6:].strip()})

    print(f"  Single-agent found: {_bold(str(len(issues)))} issues")
    for iss in issues:
        print(f"    - {iss['title']}")
    return issues


# ---------------------------------------------------------------------------
# Phase 5: Measurement & Report
# ---------------------------------------------------------------------------

def print_report(
    conn,
    baseline_issues: list,
    start_time: float,
    model: str,
    cycle_key: str,
    target_file: str,
    db_path: Path = None,
) -> dict:
    """Print the final measurement table and save results JSON."""
    _banner("PHASE 4: MEASUREMENT  –  Swarm vs Single-Agent & Benchmark Analysis")

    verdicts       = get_all_verdicts(conn)
    all_f          = get_all_findings(conn)
    llm_f          = get_llm_findings(conn)
    static_f       = get_static_findings(conn)
    schema_rejects = get_schema_rejects(conn)
    infra_errors   = get_infra_errors(conn)
    duplicates     = get_duplicate_pairs(conn)
    ch_detail      = get_challenger_breakdown(conn)

    elapsed = time.time() - start_time

    confirmed  = [v for v in verdicts if v.get("final_verdict") == "confirmed"]
    refuted    = [v for v in verdicts if v.get("final_verdict") == "refuted"]
    inconc     = [v for v in verdicts if v.get("final_verdict") == "inconclusive"]

    static_confirmed = [v for v in confirmed if v.get("source") == "static_pre_filter" or v.get("pre_confirmed")]
    llm_confirmed    = [v for v in confirmed if v not in static_confirmed]

    # Per-role breakdown (LLM only)
    role_counts: dict[str, int] = {}
    for f in llm_f:
        role_counts[f["agent_role"]] = role_counts.get(f["agent_role"], 0) + 1

    # Challenger disagreement count
    from collections import defaultdict
    votes_by_finding: dict[int, list[str]] = defaultdict(list)
    for ch in ch_detail:
        votes_by_finding[ch["finding_id"]].append(ch["verdict"])
    disagreements = sum(1 for votes in votes_by_finding.values() if len(set(votes)) > 1)

    # False-positive rate for LLM findings only
    llm_verdicts = [v for v in verdicts if not (v.get("source") == "static_pre_filter" or v.get("pre_confirmed"))]
    llm_refuted  = [v for v in llm_verdicts if v.get("final_verdict") == "refuted"]
    llm_decidable = len(llm_confirmed) + len(llm_refuted)
    llm_fp_rate = round(len(llm_refuted) / llm_decidable, 3) if llm_decidable else None

    # Average discovery time
    disc_times = [f["discovery_seconds"] for f in llm_f if f.get("discovery_seconds")]
    avg_discovery_secs = round(sum(disc_times) / len(disc_times), 2) if disc_times else None

    # Print comparison table
    print(f"\n  {'Metric':<52}  {'Swarm':>8}  {'Single':>8}")
    print(f"  {'-'*52}  {'-'*8}  {'-'*8}")
    print(f"  {'Static pre-filter findings (pre-confirmed)':<52}  {len(static_f):>8}  {'N/A':>8}")
    print(f"  {'LLM raw findings generated':<52}  {len(llm_f):>8}  {'N/A':>8}")
    print(f"  {'LLM findings dropped by schema gate':<52}  {len(schema_rejects):>8}  {'N/A':>8}")
    print(f"  {'Infrastructure errors (NEVER findings)':<52}  {len(infra_errors):>8}  {'N/A':>8}")
    print(f"  {'Confirmed total (static + LLM)':<52}  {len(confirmed):>8}  {len(baseline_issues):>8}")
    print(f"  {'  -> static pre-filter (deterministic)':<52}  {len(static_confirmed):>8}  {'N/A':>8}")
    print(f"  {'  -> LLM confirmed by challengers':<52}  {len(llm_confirmed):>8}  {'N/A':>8}")
    print(f"  {'Refuted LLM findings (noise filtered)':<52}  {len(llm_refuted):>8}  {'N/A':>8}")
    print(f"  {'Inconclusive findings (split vote)':<52}  {len(inconc):>8}  {'N/A':>8}")
    print(f"  {'LLM false-positive rate (refuted/decidable)':<52}  {llm_fp_rate if llm_fp_rate is not None else 'N/A':>8}  {'N/A':>8}")
    print(f"  {'Cross-role duplicate pairs (Jaccard>=0.4)':<52}  {len(duplicates):>8}  {'N/A':>8}")
    print(f"  {'Challenger disagreements (split vote)':<52}  {disagreements:>8}  {'N/A':>8}")
    print(f"  {'Avg discovery time per LLM finding (s)':<52}  {avg_discovery_secs if avg_discovery_secs is not None else 'N/A':>8}  {'N/A':>8}")
    print(f"  {'Total elapsed seconds':<52}  {elapsed:>8.1f}  {'N/A':>8}")

    # Classify all findings
    classified_findings = []
    for f in all_f:
        c = classify_finding(f, cycle_key)
        f_copy = dict(f)
        f_copy.update(c)
        classified_findings.append(f_copy)

    confirmed_ids = {v["id"] for v in confirmed}
    confirmed_classified = [f for f in classified_findings if f["id"] in confirmed_ids]
    known_benchmark_discoveries = [f for f in confirmed_classified if f["is_known_planted"]]
    novel_discoveries = [f for f in confirmed_classified if not f["is_known_planted"]]

    # Benchmark evaluation
    print(f"\n  {_bold('='*70)}")
    if cycle_key in ("13a", "14", "15"):
        if cycle_key == "15":
            title = "CYCLE 15 – HARD SCHEMA + STATIC PRE-FILTER"
            mode = "Static Ground-Truth + Evidence-First LLM + Schema Gate"
        elif cycle_key == "14":
            title = "CYCLE 14 – EVIDENCE-FIRST SWARM"
            mode = "Hypothesis → Trace → Evidence → Challenge → Consensus"
        else:
            title = "CYCLE 13A – BLIND VULNERABLE BENCHMARK"
            mode = "Generic discovery"

        print(f"  {_bold(f'BENCHMARK EVALUATION: {title}')}")
        print(f"  {_bold('='*70)}")
        print(f"  Target: {target_file}   Mode: {mode}")

        discovered_gt_ids = {f["ground_truth_id"] for f in known_benchmark_discoveries}
        print(f"\n  {_bold('Ground Truth Benchmark Vulnerabilities (Planted: 6):')}")
        for gt in CYCLE13A_GROUND_TRUTH:
            gt_id = gt["id"]
            if gt_id in discovered_gt_ids:
                reporters = [f["agent_role"] for f in known_benchmark_discoveries if f["ground_truth_id"] == gt_id]
                tag = _magenta("[STATIC]") if "static_pre_filter" in reporters else _cyan("[LLM]")
                status_str = _green(f"[FOUND] {tag} by {', '.join(set(reporters))}")
            else:
                status_str = _red("[MISSED]")
            print(f"    • {gt_id:<22} {gt['name']:<38} → {status_str}")

        coverage_pct = round((len(discovered_gt_ids) / len(CYCLE13A_GROUND_TRUTH)) * 100, 1)
        print(f"\n  Benchmark Coverage: {_bold(str(len(discovered_gt_ids)))} / {len(CYCLE13A_GROUND_TRUTH)} ({coverage_pct}%)")
        print(f"  LLM Novel Confirmed Findings: {_bold(str(len(novel_discoveries)))}")
        print(f"  LLM Filtered Noise (Refuted):  {_bold(str(len(llm_refuted)))}")
        print(f"  Schema-Gate Drops (pre-Phase2): {_bold(str(len(schema_rejects)))}")
        print(f"  Infrastructure Errors:          {_bold(str(len(infra_errors)))}")

    elif cycle_key == "13b":
        print(f"  {_bold('BENCHMARK EVALUATION: Clean Hardened Target (Zero Planted Flaws)')}")
        print(f"  {_bold('='*70)}")
        print(f"  Target Type: Clean Hardened Target ({target_file})")
        print(f"  Novel / Emergent Confirmed Findings : {_bold(str(len(novel_discoveries)))}")
        print(f"  Filtered Noise (False Positives Prevented): {_bold(str(len(refuted)))}")
    else:
        print(f"  {_bold('CYCLE 11 EVALUATION: Hinted Target')}")

    # Confirmed findings detail
    print(f"\n  {_bold('Confirmed Findings Detail:')}")
    if confirmed_classified:
        for f in sorted(confirmed_classified, key=lambda x: SEVERITY_ORDER.get(x.get("severity", ""), 5)):
            sev = f.get("severity", "?")
            colour = _red if sev in ("critical", "high") else _yellow if sev == "medium" else _green
            if f.get("source") == "static_pre_filter" or f.get("pre_confirmed"):
                tag = _magenta("[STATIC]")
            elif f.get("is_known_planted"):
                tag = _cyan("[KNOWN]")
            else:
                tag = _yellow("[NOVEL]")
            print(f"    {tag} [{colour(sev.upper().ljust(8))}] [{f['agent_role']}] #{f['id']} {f['hypothesis'][:70]}")
    else:
        print("    None.")

    # Schema reject telemetry
    if schema_rejects:
        print(f"\n  {_bold('Schema-Gate Rejects (LLM findings dropped before Phase 2):')}")
        for sr in schema_rejects[:15]:
            print(f"    [{sr['agent_role']}] {sr['hypothesis'][:60]}  →  {sr['rejection_reason']}")
        if len(schema_rejects) > 15:
            print(f"    ... and {len(schema_rejects) - 15} more (see results JSON)")

    # Infrastructure error telemetry
    if infra_errors:
        print(f"\n  {_bold('Infrastructure Errors (logged as telemetry, NOT findings):')}")
        for ie in infra_errors:
            print(f"    [{ie['agent_id']}] {ie['error_type']} — {str(ie.get('detail',''))[:80]}")

    # Per-role breakdown
    print(f"\n  {_bold('LLM Findings per specialised role:')}")
    for role, count in role_counts.items():
        conf_for_role = sum(1 for v in llm_confirmed if v.get("agent_role") == role)
        print(f"    {AGENT_ROLES.get(role, {}).get('name', role):<40} {count:>3} valid  {conf_for_role:>2} confirmed")

    # Advantage calculation
    advantage = len(confirmed) - len(baseline_issues)
    if advantage > 0:
        conclusion = f"Swarm found {advantage} MORE confirmed issues than single-agent (includes static pre-filter)."
        print(f"\n  {_bold(_green('CONCLUSION:'))} {conclusion}")
    elif advantage == 0:
        conclusion = "Swarm and single-agent found the same number of confirmed issues."
        print(f"\n  {_bold(_yellow('CONCLUSION:'))} {conclusion}")
    else:
        conclusion = "Single-agent reported more issues than confirmed by swarm consensus."
        print(f"\n  {_bold(_red('CONCLUSION:'))} {conclusion}")

    # Build JSON export
    finding_detail = []
    for f in classified_findings:
        fid = f["id"]
        ch_votes = votes_by_finding.get(fid, [])
        verdict_row = next((v for v in verdicts if v.get("id") == fid), {})
        finding_detail.append({
            "id": fid,
            "agent_id": f["agent_id"],
            "agent_role": f["agent_role"],
            "source": f.get("source", "llm"),
            "pre_confirmed": bool(f.get("pre_confirmed")),
            "hypothesis": f["hypothesis"],
            "evidence": f["evidence"],
            "severity": f["severity"],
            "discovery_seconds": f.get("discovery_seconds"),
            "challenger_votes": ch_votes,
            "final_verdict": verdict_row.get("final_verdict", "pending"),
            "verdict_notes": verdict_row.get("notes", ""),
            "classification": f["classification"],
            "ground_truth_id": f["ground_truth_id"],
            "ground_truth_name": f["ground_truth_name"],
            "is_known_planted": f["is_known_planted"],
        })

    # Benchmark eval object
    if cycle_key in ("13a", "14", "15"):
        discovered_ids = {f["ground_truth_id"] for f in known_benchmark_discoveries}
        benchmark_eval = {
            "tier": cycle_key.upper(),
            "target_type": "blind_vulnerable_benchmark",
            "mode": {
                "15": "static_prefilter_plus_hard_schema",
                "14": "evidence_first",
                "13a": "standard",
            }.get(cycle_key, "standard"),
            "planted_weaknesses_total": len(CYCLE13A_GROUND_TRUTH),
            "planted_weaknesses_discovered": len(discovered_ids),
            "coverage_pct": round((len(discovered_ids) / len(CYCLE13A_GROUND_TRUTH)) * 100, 1),
            "static_prefilter_findings": len(static_f),
            "llm_raw_findings": len(llm_f),
            "schema_rejects": len(schema_rejects),
            "infra_errors": len(infra_errors),
            "llm_confirmed": len(llm_confirmed),
            "llm_fp_rate": llm_fp_rate,
            "known_benchmark_findings_count": len(known_benchmark_discoveries),
            "novel_confirmed_count": len(novel_discoveries),
            "noise_refuted_count": len(llm_refuted),
        }
    elif cycle_key == "13b":
        benchmark_eval = {
            "tier": "13B",
            "target_type": "clean_hardened_target",
            "planted_weaknesses_total": 0,
            "planted_weaknesses_discovered": 0,
            "coverage_pct": 100.0,
            "known_benchmark_findings_count": 0,
            "novel_confirmed_count": len(novel_discoveries),
            "noise_refuted_count": len(refuted),
            "inconclusive_count": len(inconc),
        }
    else:
        benchmark_eval = {"tier": "11", "target_type": "hinted_target"}

    result_obj = {
        "cycle": cycle_key,
        "target_file": target_file,
        "model": model,
        "db_path": str(db_path) if db_path else None,
        "elapsed_seconds": round(elapsed, 1),
        "benchmark_evaluation": benchmark_eval,
        "swarm": {
            "static_prefilter_findings": len(static_f),
            "llm_raw_findings": len(llm_f),
            "schema_rejects": len(schema_rejects),
            "infra_errors": len(infra_errors),
            "confirmed_total": len(confirmed),
            "confirmed_static": len(static_confirmed),
            "confirmed_llm": len(llm_confirmed),
            "refuted_llm": len(llm_refuted),
            "inconclusive": len(inconc),
            "cross_role_duplicate_pairs": len(duplicates),
            "challenger_disagreements": disagreements,
            "llm_false_positive_rate": llm_fp_rate,
            "avg_discovery_seconds_per_llm_finding": avg_discovery_secs,
            "roles": role_counts,
        },
        "single_agent": {
            "issues_found": len(baseline_issues),
            "titles": [i["title"] for i in baseline_issues],
        },
        "advantage": advantage,
        "findings": finding_detail,
        "schema_rejects": [dict(sr) for sr in schema_rejects],
        "infra_errors": [dict(ie) for ie in infra_errors],
        "duplicates": duplicates,
        "challenger_detail": ch_detail,
    }

    # Save JSON results
    prefix = f"cycle{cycle_key}_results"
    ts = int(time.time())
    out_path = RESULTS_DIR / f"{prefix}_{ts}.json"
    out_path.write_text(json.dumps(result_obj, indent=2), encoding="utf-8")
    print(f"\n  Results saved → {out_path}")

    # Also copy to Desktop and user profile
    for dest_dir in [Path.home() / "Desktop", Path.home()]:
        try:
            dest = dest_dir / f"{prefix}_{ts}.json"
            shutil.copy2(out_path, dest)
            print(f"  Copied        → {dest}")
        except Exception:
            pass

    return result_obj


# ---------------------------------------------------------------------------
# Calibration Report  [CYCLE 16 ONLY]
# ---------------------------------------------------------------------------

def print_calibration_report(
    conn,
    calib_counts: dict,
    start_time: float,
    model: str,
    target_file: str,
    db_path: Path = None,
    cycle_label: str = "16",
    challenger_model: str = None,
) -> dict:
    """Print the calibration report and save cycle<N>_<label>_results_<ts>.json."""
    _banner(f"PHASE 4: CALIBRATION REPORT  –  Cycle {cycle_label} Challenger Calibration")
    if challenger_model and challenger_model != model:
        print(f"  Discovery Model   : {_bold(model)}")
        print(f"  Challenger Model  : {_bold(challenger_model)}")

    all_f      = get_all_findings(conn)
    llm_f      = get_llm_findings(conn)
    static_f   = get_static_findings(conn)
    verdicts   = get_all_verdicts(conn)
    ch_detail  = get_challenger_breakdown(conn)
    schema_rej = get_schema_rejects(conn)
    infra_err  = get_infra_errors(conn)
    elapsed    = time.time() - start_time

    # Build vote map
    from collections import defaultdict
    raw_by_finding: dict[int, list[str]] = defaultdict(list)
    text_by_finding: dict[int, list[str]] = defaultdict(list)
    raw_verd_by_finding: dict[int, list[str]] = defaultdict(list)
    for ch in ch_detail:
        raw_by_finding[ch["finding_id"]].append(ch.get("raw_verdict", "?"))
        text_by_finding[ch["finding_id"]].append(ch["challenge_text"])

    # Cycle 15 strict vs Cycle 16 calibrated comparison
    print(f"\n  {'Finding':<6}  {'Agent Role':<28}  {'Strict':<12}  {'Calibrated':<20}  {'Diagnostic':<14}  Hypothesis")
    print(f"  {'-'*6}  {'-'*28}  {'-'*12}  {'-'*20}  {'-'*14}  {'-'*40}")

    finding_records = []
    for f in all_f:
        fid = f["id"]
        v = next((vv for vv in verdicts if vv.get("id") == fid), {})
        strict  = v.get("final_verdict", "-")
        calib   = v.get("calibrated_verdict", "-")
        overrej = v.get("overrejection_status", "-")
        source  = f.get("source", "llm")

        if source == "static_pre_filter":
            strict_label = _magenta("static")
            calib_label  = _magenta("STATIC_CONFIRMED")
            overrej_label = "N/A"
        else:
            strict_label = _green(strict) if strict == "confirmed" else (_red(strict) if strict == "refuted" else _yellow(strict))
            if calib == "STRICT_CONFIRMED":
                calib_label = _green(calib)
            elif calib in ("PARTIAL_CONFIRMED",):
                calib_label = _yellow(calib)
            elif calib in ("REFUTED", "NOT_CONFIRMED"):
                calib_label = _red(calib)
            else:
                calib_label = _yellow(str(calib))
            overrej_label = _yellow(overrej) if overrej == "OVERREJECTION" else (_green(overrej) if overrej == "CORRECT" else overrej)

        raw_v = raw_by_finding.get(fid, [])
        print(
            f"  #{fid:<5}  {f['agent_role']:<28}  {strict_label:<22}  {calib_label:<30}  "
            f"{overrej_label:<24}  {f['hypothesis'][:50]}"
        )

        # Per-finding challenger explanation
        ch_texts = text_by_finding.get(fid, [])
        for ci, (rv, ct) in enumerate(zip(raw_v, ch_texts)):
            prefix = f"    Challenger-{chr(65+ci)} [{rv}]:"
            wrapped = textwrap.fill(ct, width=100, subsequent_indent=" " * (len(prefix)+1))
            print(f"{prefix} {wrapped[:200]}")

        # Calibration diagnostic note
        calib_note = v.get("calibration_notes", "")
        if calib_note and source == "llm":
            print(f"    → DIAGNOSTIC: {calib_note}")
        print()

        # Correlate with GT
        matches_gt, gt_id = _finding_matches_any_gt(f)
        ch_for_finding = [ch for ch in ch_detail if ch["finding_id"] == fid]
        ch_a = next((ch for ch in ch_for_finding if ch.get("challenger_id") == "challenger-A"), None)
        ch_b = next((ch for ch in ch_for_finding if ch.get("challenger_id") == "challenger-B"), None)

        finding_records.append({
            "finding_id": fid,
            "agent": f["agent_id"],
            "agent_role": f["agent_role"],
            "source": source,
            "claim": f["hypothesis"],
            "evidence": f["evidence"],
            "severity": f.get("severity", "?"),
            "discovery_seconds": f.get("discovery_seconds"),
            "challenger_a_verdict": ch_a.get("verdict") if ch_a else None,
            "challenger_a_raw": ch_a.get("raw_verdict") if ch_a else None,
            "challenger_b_verdict": ch_b.get("verdict") if ch_b else None,
            "challenger_b_raw": ch_b.get("raw_verdict") if ch_b else None,
            "raw_challenger_verdicts": raw_by_finding.get(fid, []),
            "challenger_texts": text_by_finding.get(fid, []),
            "strict_verdict": strict,
            "calibrated_verdict": calib,
            "overrejection_status": overrej,
            "calibration_notes": v.get("calibration_notes", ""),
            "corresponds_to_planted_issue": matches_gt,
            "planted_ground_truth_id": gt_id,
        })

    # Summary metrics
    llm_count = len(llm_f)
    strict_confirmed  = calib_counts.get("strict_confirmed", 0)
    partial_confirmed = calib_counts.get("partial_confirmed", 0)
    not_confirmed     = calib_counts.get("not_confirmed", 0)
    refuted           = calib_counts.get("refuted", 0)
    inconclusive      = calib_counts.get("inconclusive", 0)
    overrejections    = calib_counts.get("overrejections", 0)
    correct_rej       = calib_counts.get("correct_rejections", 0)
    uncertain         = calib_counts.get("uncertain", 0)

    # Planted issues that LLM found (excluding static pre-filter)
    llm_planted = [r for r in finding_records if r["source"] == "llm" and r["corresponds_to_planted_issue"]]
    hallucinated = [r for r in finding_records if r["source"] == "llm" and not r["corresponds_to_planted_issue"]]
    duplicate_claims = len(llm_f) - len({r["planted_ground_truth_id"] for r in llm_planted if r["planted_ground_truth_id"]} | {
        None if not r["corresponds_to_planted_issue"] else "novel" for r in finding_records if r["source"] == "llm"
    })

    # Strict FP rate: refuted / (strict_confirmed + refuted)
    strict_decidable = strict_confirmed + refuted + not_confirmed
    strict_fp = round((refuted + not_confirmed) / strict_decidable, 3) if strict_decidable else None

    # Calibrated FP rate: REFUTED / (STRICT+PARTIAL+REFUTED)
    calib_decidable = strict_confirmed + partial_confirmed + refuted + not_confirmed
    calib_fp = round((refuted + not_confirmed) / calib_decidable, 3) if calib_decidable else None

    planted_llm_confirmed = [r for r in llm_planted if r["calibrated_verdict"] in ("STRICT_CONFIRMED", "PARTIAL_CONFIRMED")]
    planted_llm_missed    = [r for r in llm_planted if r["calibrated_verdict"] not in ("STRICT_CONFIRMED", "PARTIAL_CONFIRMED")]

    print(f"  {_bold('='*70)}")
    print(f"  {_bold('CYCLE 16 CALIBRATION SUMMARY')}")
    print(f"  {_bold('='*70)}")
    print(f"  Raw LLM findings          : {llm_count}")
    print(f"  Schema-gate drops         : {len(schema_rej)}")
    print(f"  Infrastructure errors     : {len(infra_err)}")
    print()
    print(f"  STRICT_CONFIRMED          : {_green(str(strict_confirmed))}")
    print(f"  PARTIAL_CONFIRMED         : {_yellow(str(partial_confirmed))}  ← real issue, incomplete evidence")
    print(f"  NOT_CONFIRMED             : {_yellow(str(not_confirmed))}  ← one FULL_INVALID present")
    print(f"  REFUTED                   : {_red(str(refuted))}  ← both FULL_INVALID")
    print(f"  INCONCLUSIVE              : {_yellow(str(inconclusive))}")
    print()
    print(f"  Strict false-positive rate    : {strict_fp}")
    print(f"  Calibrated false-positive rate: {calib_fp}")
    print()
    print(f"  Planted issues: {len(llm_planted)} touched by LLM  |  {len(planted_llm_confirmed)} calibrated-confirmed  |  {len(planted_llm_missed)} missed")
    print(f"  Hallucinated findings (no GT match): {len(hallucinated)}")
    print()
    print(f"  OVERREJECTIONS (real issue, bad path) : {_yellow(str(overrejections))}")
    print(f"  CORRECT rejections                   : {_green(str(correct_rej))}")
    print(f"  UNCERTAIN                            : {_yellow(str(uncertain))}")
    print(f"  Elapsed                              : {elapsed:.1f}s")

    # Save JSON
    result_obj = {
        "cycle": cycle_label,
        "target_file": target_file,
        "model": model,
        "challenger_model": challenger_model or model,
        "db_path": str(db_path) if db_path else None,
        "elapsed_seconds": round(elapsed, 1),
        "calibration_summary": {
            "raw_llm_findings": llm_count,
            "schema_gate_drops": len(schema_rej),
            "infra_errors": len(infra_err),
            "static_prefilter_confirmed": calib_counts.get("static_confirmed", 0),
            "strict_confirmed": strict_confirmed,
            "partial_confirmed": partial_confirmed,
            "not_confirmed": not_confirmed,
            "refuted": refuted,
            "inconclusive": inconclusive,
            "strict_false_positive_rate": strict_fp,
            "calibrated_false_positive_rate": calib_fp,
            "planted_touched_by_llm": len(llm_planted),
            "planted_calibrated_confirmed": len(planted_llm_confirmed),
            "planted_missed": len(planted_llm_missed),
            "hallucinated_findings": len(hallucinated),
            "overrejections": overrejections,
            "correct_rejections": correct_rej,
            "uncertain": uncertain,
        },
        "findings": finding_records,
        "schema_rejects": [dict(sr) for sr in schema_rej],
        "infra_errors": [dict(ie) for ie in infra_err],
    }

    ts = int(time.time())
    if cycle_label == "18":
        out_fname = f"cycle18_challenger_model_results_{ts}.json"
    elif cycle_label == "17":
        out_fname = f"cycle17_grounded_results_{ts}.json"
    else:
        out_fname = f"cycle16_calibration_results_{ts}.json"
    out_path = RESULTS_DIR / out_fname
    out_path.write_text(json.dumps(result_obj, indent=2), encoding="utf-8")
    print(f"\n  Results saved → {out_path}")

    for dest_dir in [Path.home() / "Desktop", Path.home()]:
        try:
            dest = dest_dir / out_fname
            shutil.copy2(out_path, dest)
            print(f"  Copied        → {dest}")
        except Exception:
            pass

    return result_obj


# ---------------------------------------------------------------------------
# Cycle 19 Report
# ---------------------------------------------------------------------------

def print_cycle19_report(
    conn,
    c19_counts: dict,
    start_time: float,
    model: str,
    target_file: str,
    db_path: Path = None,
    challenger_model: str = None,
    cycle_label: str = "19",
) -> dict:
    """Print the Cycle 19/20 decomposed evaluation report and save json."""
    _banner(f"PHASE 4: EVALUATOR DECOMPOSITION REPORT (Cycle {cycle_label})")
    print(f"  Discovery Model   : {_bold(model)}")
    print(f"  Challenger Model  : {_bold(challenger_model or model)}")

    all_f      = get_all_findings(conn)
    llm_f      = get_llm_findings(conn)
    static_f   = get_static_findings(conn)
    verdicts   = get_all_verdicts(conn)
    ch_detail  = get_challenger_breakdown(conn)
    schema_rej = get_schema_rejects(conn)
    infra_err  = get_infra_errors(conn)
    duplicates = get_duplicate_pairs(conn)
    elapsed    = time.time() - start_time

    from collections import defaultdict
    challenges_by_fid = defaultdict(list)
    for ch in ch_detail:
        challenges_by_fid[ch["finding_id"]].append(ch)

    print(f"\n  {'Finding':<6}  {'Agent Role':<24}  {'Claim Verdict':<15}  {'Underlying':<20}  {'Classification':<18}  Hypothesis")
    print(f"  {'-'*6}  {'-'*24}  {'-'*15}  {'-'*20}  {'-'*18}  {'-'*40}")

    finding_records = []
    for f in all_f:
        fid = f["id"]
        v = next((vv for vv in verdicts if vv.get("id") == fid), {})
        orig_claim = v.get("original_claim_verdict", "-")
        underlying = v.get("underlying_assessment", "-")
        classification = v.get("decomposition_classification", "-")
        source = f.get("source", "llm")

        if source == "static_pre_filter":
            claim_label = _magenta("CONFIRMED (GT)")
            underlying_label = _magenta("REAL_ISSUE")
            class_label = _magenta("FULL_VALIDITY")
        else:
            claim_label = _green(orig_claim) if orig_claim == "CONFIRMED" else (_yellow(orig_claim) if orig_claim == "PARTIALLY_SUPPORTED" else _red(orig_claim))
            underlying_label = _green(underlying) if underlying == "REAL_ISSUE_PRESENT" else _yellow(underlying)
            if classification == "FULL_VALIDITY":
                class_label = _green(classification)
            elif classification == "PARTIAL_VALIDITY":
                class_label = _yellow(classification)
            elif classification == "OVERREJECTION":
                class_label = _yellow(classification)
            else:
                class_label = _red(classification)

        print(
            f"  #{fid:<5}  {f['agent_role']:<24}  {claim_label:<24}  {underlying_label:<28}  "
            f"{class_label:<26}  {f['hypothesis'][:45]}"
        )

        ch_list = challenges_by_fid.get(fid, [])
        for ch in ch_list:
            prefix = f"    {ch['challenger_id']}:"
            dims = (
                f"Factual={ch.get('factual_validity')} | Path={ch.get('attack_path')} | "
                f"Property={ch.get('security_property')} | Impact={ch.get('consequence')} | "
                f"Severity={ch.get('severity_eval')} | Overall={ch.get('overall_verdict')} | "
                f"RelatedRealIssue={bool(ch.get('related_real_issue'))} | StatedValid={bool(ch.get('stated_claim_valid'))}"
            )
            print(f"{prefix} {dims}")
            reason = ch.get("challenge_text", "")
            if reason:
                wrapped = textwrap.fill(reason, width=100, subsequent_indent=" " * 8)
                print(f"        Reason: {wrapped[:200]}")
        print()

        matches_gt, gt_id = _finding_matches_any_gt(f)
        ch_a = next((ch for ch in ch_list if ch.get("challenger_id") == "challenger-A"), None)
        ch_b = next((ch for ch in ch_list if ch.get("challenger_id") == "challenger-B"), None)

        finding_records.append({
            "finding_id": fid,
            "agent": f["agent_id"],
            "agent_role": f["agent_role"],
            "source": source,
            "claim": f["hypothesis"],
            "evidence": f["evidence"],
            "severity": f.get("severity", "?"),
            "discovery_seconds": f.get("discovery_seconds"),
            "original_claim_verdict": orig_claim,
            "underlying_assessment": underlying,
            "decomposition_classification": classification,
            "challenger_a": ch_a,
            "challenger_b": ch_b,
            "corresponds_to_planted_issue": matches_gt,
            "planted_ground_truth_id": gt_id,
        })

    # Summary metrics calculation
    llm_records = [r for r in finding_records if r["source"] == "llm"]
    llm_count = len(llm_records)

    full_validity_count = sum(1 for r in llm_records if r["decomposition_classification"] == "FULL_VALIDITY")
    partial_validity_count = sum(1 for r in llm_records if r["decomposition_classification"] == "PARTIAL_VALIDITY")
    overrejection_count = sum(1 for r in llm_records if r["decomposition_classification"] == "OVERREJECTION")
    correct_rejection_count = sum(1 for r in llm_records if r["decomposition_classification"] == "CORRECT_REJECTION")

    # False positives: LLM confirmed/partial findings that do NOT correspond to planted GT
    false_positives = sum(1 for r in llm_records if r["decomposition_classification"] in ("FULL_VALIDITY", "PARTIAL_VALIDITY") and not r["corresponds_to_planted_issue"])

    # Planted GT coverage (Static + LLM)
    discovered_gt_ids = {r["planted_ground_truth_id"] for r in finding_records if r["corresponds_to_planted_issue"] and r["planted_ground_truth_id"]}
    planted_coverage_pct = round((len(discovered_gt_ids) / len(CYCLE13A_GROUND_TRUTH)) * 100, 1)

    print(f"  {_bold('='*70)}")
    print(f"  {_bold('CYCLE 19 DECOMPOSED METRICS SUMMARY')}")
    print(f"  {_bold('='*70)}")
    print(f"  Raw LLM findings               : {llm_count}")
    print(f"  Schema-gate drops              : {len(schema_rej)}")
    print(f"  Infrastructure errors          : {len(infra_err)}")
    print()
    print(f"  Factual-valid findings         : {c19_counts.get('factual_valid', 0)}")
    print(f"  Attack-path-valid findings     : {c19_counts.get('attack_path_valid', 0)}")
    print(f"  Security-property-valid findings: {c19_counts.get('security_property_valid', 0)}")
    print(f"  Severity disagreements         : {c19_counts.get('severity_disagreements', 0)}")
    print()
    print(f"  FULL_VALIDITY (Confirmed)      : {_green(str(full_validity_count))}")
    print(f"  PARTIAL_VALIDITY (Partial)     : {_yellow(str(partial_validity_count))}")
    print(f"  OVERREJECTIONS                 : {_yellow(str(overrejection_count))}  ← real issue present, stated claim rejected")
    print(f"  CORRECT rejections            : {_green(str(correct_rejection_count))}  ← no real security issue")
    print(f"  False positives (non-GT confirmed): {false_positives}")
    print(f"  Planted GT coverage            : {len(discovered_gt_ids)} / {len(CYCLE13A_GROUND_TRUTH)} ({planted_coverage_pct}%)")
    duplicate_rate = round(len(duplicates) / llm_count, 3) if llm_count else 0.0
    print(f"  Duplicate pairs (Jaccard>=0.4) : {len(duplicates)} (rate: {duplicate_rate})")
    print(f"  Elapsed runtime                : {elapsed:.1f}s")

    # --- Cycle 21 Schema Gate Audit & Rescue Analysis ---
    audit_entries = get_schema_audit(conn) if "get_schema_audit" in globals() else []
    audit_analysis = []
    for entry in audit_entries:
        hyp = entry.get("hypothesis", "")
        path_val = entry.get("path") or ""
        loc = entry.get("location") or ""
        prop = entry.get("security_property") or ""
        status = entry.get("status", "UNKNOWN")
        rej_reason = entry.get("rejection_reason")
        role = entry.get("agent_role", "")
        raw_text = entry.get("raw_text") or ""

        matches_gt, gt_id = _finding_matches_any_gt({"hypothesis": hyp, "evidence": f"{path_val} {loc} {prop}"})
        tech_hallucination = bool(HALLUCINATED_TECH_PATTERN.search(f"{path_val} {prop} {hyp} {raw_text}"))

        if matches_gt:
            correspondence = "planted_gt"
        elif tech_hallucination:
            correspondence = "genuine_false_positive"
        elif any(term in hyp.lower() for term in ["unbounded", "exhaustion", "denial of service", "traversal", "manipulation", "path", "memory", "leak"]):
            correspondence = "non_gt_real"
        else:
            correspondence = "indeterminate"

        if status == "ACCEPTED":
            rescue_class = "SCHEMA_VALID"
            repaired_path = None
            repair_notes = "Finding passed schema gate."
        else:
            if correspondence in ("planted_gt", "non_gt_real"):
                if rej_reason and "PATH_TOO_VAGUE" in rej_reason:
                    rescue_class = "SCHEMA_TOO_VAGUE_BUT_REPAIRABLE"
                    repaired_path = f"User input reaches {loc or 'target function'} triggering unbounded loop or file operations across DATA directory"
                    repair_notes = "Underlying security concern is valid. Path field can be made compliant by adding concrete data-flow context without changing claim."
                elif rej_reason and "MISSING_FIELDS" in rej_reason:
                    rescue_class = "SCHEMA_TOO_VAGUE_BUT_REPAIRABLE"
                    repaired_path = path_val or f"Data flow reaches {loc or 'target function'} without authorization checks"
                    repair_notes = "Missing fields can be populated from existing context."
                else:
                    rescue_class = "SCHEMA_TOO_VAGUE_BUT_REPAIRABLE"
                    repaired_path = path_val
                    repair_notes = f"Rejected for {rej_reason}; valid underlying issue."
            elif tech_hallucination:
                rescue_class = "SCHEMA_INVALID_CLAIM"
                repaired_path = None
                repair_notes = "Finding references absent technology (SQL/DB/pickle/eval); invalid claim."
            else:
                rescue_class = "SCHEMA_FALSE_POSITIVE"
                repaired_path = None
                repair_notes = "Security claim is false for target; genuine false positive."

        audit_analysis.append({
            "agent_role": role,
            "agent_id": entry.get("agent_id"),
            "hypothesis": hyp,
            "path_field": path_val,
            "location": loc,
            "security_property": prop,
            "schema_status": status,
            "rejection_reason": rej_reason,
            "raw_finding_text": raw_text,
            "gt_correspondence": correspondence,
            "planted_gt_id": gt_id if matches_gt else None,
            "rescue_classification": rescue_class,
            "repaired_path": repaired_path,
            "repair_notes": repair_notes,
        })

    total_gen = len(audit_analysis)
    total_acc = sum(1 for a in audit_analysis if a["schema_status"] == "ACCEPTED")
    total_rej = sum(1 for a in audit_analysis if a["schema_status"] == "REJECTED")
    rej_rate = round(total_rej / total_gen, 3) if total_gen else 0.0
    repairable_rej = sum(1 for a in audit_analysis if a["rescue_classification"] == "SCHEMA_TOO_VAGUE_BUT_REPAIRABLE")
    repairable_rate = round(repairable_rej / total_rej, 3) if total_rej else 0.0
    planted_lost = sum(1 for a in audit_analysis if a["schema_status"] == "REJECTED" and a["gt_correspondence"] == "planted_gt")
    non_gt_lost = sum(1 for a in audit_analysis if a["schema_status"] == "REJECTED" and a["gt_correspondence"] == "non_gt_real")
    fp_stopped = sum(1 for a in audit_analysis if a["schema_status"] == "REJECTED" and a["gt_correspondence"] == "genuine_false_positive")

    audit_summary = {
        "raw_findings_generated": total_gen,
        "schema_accepted": total_acc,
        "schema_rejected": total_rej,
        "rejection_rate": rej_rate,
        "repairable_rejections": repairable_rej,
        "repairable_rejection_rate": repairable_rate,
        "planted_gt_lost_at_schema": planted_lost,
        "non_gt_real_lost_at_schema": non_gt_lost,
        "false_positives_stopped_by_schema": fp_stopped,
        "duplicate_rate": duplicate_rate,
    }

    if cycle_label == "21":
        _banner("PHASE 5: CYCLE 21 SCHEMA-GATE AUDIT SUMMARY")
        print(f"  Raw Findings Generated     : {total_gen}")
        print(f"  Schema Accepted            : {_green(str(total_acc))}")
        print(f"  Schema Rejected            : {_red(str(total_rej))} (Rejection Rate: {rej_rate*100:.1f}%)")
        print(f"  Repairable Rejections      : {_yellow(str(repairable_rej))} (Repairable Rate: {repairable_rate*100:.1f}%)")
        print(f"  Planted GT Lost at Schema  : {planted_lost}")
        print(f"  Non-GT Real Lost at Schema : {non_gt_lost}")
        print(f"  False Positives Stopped    : {fp_stopped}")
        print(f"  Duplicate Rate (Accepted)  : {duplicate_rate}")
        print()

    result_obj = {
        "cycle": cycle_label,
        "target_file": target_file,
        "model": model,
        "challenger_model": challenger_model or model,
        "db_path": str(db_path) if db_path else None,
        "elapsed_seconds": round(elapsed, 1),
        "decomposed_metrics": {
            "raw_llm_findings": llm_count,
            "schema_gate_drops": len(schema_rej),
            "infra_errors": len(infra_err),
            "static_prefilter_confirmed": c19_counts.get("static_confirmed", 0),
            "factual_valid_findings": c19_counts.get("factual_valid", 0),
            "attack_path_valid_findings": c19_counts.get("attack_path_valid", 0),
            "security_property_valid_findings": c19_counts.get("security_property_valid", 0),
            "severity_disagreements": c19_counts.get("severity_disagreements", 0),
            "confirmed_findings": full_validity_count,
            "partial_findings": partial_validity_count,
            "overrejections": overrejection_count,
            "correct_rejections": correct_rejection_count,
            "false_positives": false_positives,
            "planted_gt_discovered": len(discovered_gt_ids),
            "planted_gt_total": len(CYCLE13A_GROUND_TRUTH),
            "planted_gt_coverage_pct": planted_coverage_pct,
            "duplicate_pairs_count": len(duplicates),
            "duplicate_rate": duplicate_rate,
        },
        "findings": finding_records,
        "schema_rejects": [dict(sr) for sr in schema_rej],
        "infra_errors": [dict(ie) for ie in infra_err],
        "duplicates": duplicates,
        "schema_audit_summary": audit_summary,
        "schema_audit_records": audit_analysis,
    }

    ts = int(time.time())
    if cycle_label == "22":
        out_fname = f"cycle22_replication_{ts}.json"
    elif cycle_label == "21":
        out_fname = f"cycle21_schema_gate_audit_{ts}.json"
    elif cycle_label == "20":
        out_fname = f"cycle20_reproducibility_{ts}.json"
    else:
        out_fname = f"cycle19_evaluator_decomposition_{ts}.json"
    out_path = RESULTS_DIR / out_fname
    out_path.write_text(json.dumps(result_obj, indent=2), encoding="utf-8")
    print(f"\n  Results saved → {out_path}")

    for dest_dir in [Path.home() / "Desktop", Path.home()]:
        try:
            dest = dest_dir / out_fname
            shutil.copy2(out_path, dest)
            print(f"  Copied        → {dest}")
        except Exception:
            pass

    return result_obj


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def check_ollama(client: LLMClient) -> str:
    """Verify Ollama is reachable and pick a usable model."""
    _banner("PRE-FLIGHT: Checking Ollama")
    models = client.list_models()
    if not models:
        print(_red(
            "  ERROR: Ollama is not running or has no models.\n"
            "  Fix:\n"
            "    1. Open a terminal and run:  ollama serve\n"
            "    2. Pull a model:             ollama pull llama3.2\n"
            "    3. Re-run this script."
        ))
        sys.exit(1)

    print(f"  Ollama reachable. Available models:")
    for m in models:
        print(f"    • {m}")

    matched = next(
        (m for m in models if m == client.model or m == f"{client.model}:latest" or m.startswith(f"{client.model}:")),
        None,
    )
    if matched:
        client.model = matched
        print(f"\n  Using model: {_bold(client.model)}")
    else:
        fallback = models[0]
        print(_yellow(f"\n  Requested model '{client.model}' not found. Using '{fallback}' instead."))
        client.model = fallback

    return client.model


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cycle 11/13A/13B/14/15/16/17/18/19 – Ollama Multi-Agent Swarm Experiment"
    )
    parser.add_argument("--model",            default="llama3.2", help="Ollama model name (default: llama3.2)")
    parser.add_argument("--challenger-model", default=None,       help="Model for Phase 2 challengers (default: same as --model)")
    parser.add_argument("--workers",          type=int, default=5, help="Number of research agents (1-5, default: 5)")
    parser.add_argument("--baseline",         action="store_true", help="Also run single-agent baseline for comparison")
    parser.add_argument("--url",              default="http://127.0.0.1:11434", help="Ollama base URL")
    parser.add_argument(
        "--cycle",
        default="15",
        choices=["11", "13", "13a", "13A", "13b", "13B", "14", "15", "16", "17", "18", "19", "20", "21", "22"],
        help=(
            "22 = decomposed evaluator replication (reproducibility check), "
            "21 = schema-gate audit (telemetry & rescue analysis), "
            "20 = reproducibility validation (repeat Cycle 19), "
            "19 = decomposed evaluator (6-axis rubric & severity decoupling), "
            "18 = challenger model A/B experiment (qwen2.5-coder:7b challengers), "
            "17 = grounded discovery (8-step self-rejection), "
            "16 = challenger calibration (diagnostic), "
            "15 = hard schema + static pre-filter (default), "
            "14 = evidence-first swarm, "
            "13a = blind vulnerable benchmark, "
            "13b = clean hardened, "
            "11 = hinted"
        ),
    )
    parser.add_argument(
        "--challengers",
        type=int, default=2,
        help="Number of adversarial challengers per LLM finding (max 2, default: 2)",
    )
    args = parser.parse_args()

    # Normalize cycle key
    raw_cycle = args.cycle.lower()
    if raw_cycle == "22":
        cycle_key = "22"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 22 – DECOMPOSED-EVALUATOR REPLICATION"
        mode_desc = "Determine whether Cycle 21's result is reproducible. FREEZE architecture."
    elif raw_cycle == "21":
        cycle_key = "21"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 21 – SCHEMA-GATE AUDIT (Telemetry & Rescue Analysis)"
        mode_desc = "Audit schema-gate impact on discovery yield without modifying gate rules"
    elif raw_cycle == "20":
        cycle_key = "20"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 20 – REPRODUCIBILITY VALIDATION (Freeze Everything, Repeat Cycle 19)"
        mode_desc = "Faithful repetition of Cycle 19 to determine whether evaluator decomposition improvement is reproducible"
    elif raw_cycle == "19":
        cycle_key = "19"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 19 – EVALUATOR DECOMPOSITION (6-axis Rubric & Severity Decoupling)"
        mode_desc = "Decomposed challenger evaluation: Factual, Attack Path, Property, Consequence, Severity, Overall"
    elif raw_cycle == "18":
        cycle_key = "18"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 18 – CHALLENGER MODEL A/B EXPERIMENT (qwen2.5-coder:7b challengers)"
        mode_desc = "Grounded discovery (llama3.2) + qwen2.5-coder:7b challengers (prompts unchanged)"
    elif raw_cycle == "17":
        cycle_key = "17"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 17 – GROUNDED DISCOVERY (8-step self-rejection, mechanism verification)"
        mode_desc = "Identical to Cycle 16 except: Phase-1 prompt forces 8-step grounding + MECHANISM_ABSENT self-rejection"
    elif raw_cycle == "16":
        cycle_key = "16"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 16 – CHALLENGER CALIBRATION (PARTIAL preserved, overrejection diagnostic)"
        mode_desc = "Identical to Cycle 15 except: PARTIAL verdict preserved, calibrated aggregation, CORRECT/OVERREJECTION/UNCERTAIN diagnostic"
    elif raw_cycle == "15":
        cycle_key = "15"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 15 – HARD SCHEMA ENFORCEMENT + STATIC GROUND-TRUTH PRE-FILTER"
        mode_desc = "Static pre-filter (GT detection) + Evidence-first LLM + Schema gate + Serial workers"
    elif raw_cycle == "14":
        cycle_key = "14"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 14 – EVIDENCE-FIRST SWARM"
        mode_desc = "Hypothesis → Trace → Evidence → Challenge → Consensus on blind vulnerable benchmark"
    elif raw_cycle in ("13", "13b"):
        cycle_key = "13b"
        target_file = "target_app_cycle13b.py"
        mode_label = "CYCLE 13B – CLEAN HARDENED TARGET"
        mode_desc = "Clean target with zero planted vulnerabilities"
    elif raw_cycle == "13a":
        cycle_key = "13a"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 13A – BLIND VULNERABLE BENCHMARK"
        mode_desc = "Blind target with 6 known-but-undisclosed planted vulnerabilities"
    elif raw_cycle == "11":
        cycle_key = "11"
        target_file = "target_app.py"
        mode_label = "CYCLE 11 – HINTED BENCHMARK"
        mode_desc = "Legacy target with inline hint comments"
    else:
        cycle_key = "15"
        target_file = "target_app_cycle13.py"
        mode_label = "CYCLE 15 – HARD SCHEMA ENFORCEMENT + STATIC GROUND-TRUTH PRE-FILTER"
        mode_desc = "Static pre-filter (GT detection) + Evidence-first LLM + Schema gate + Serial workers"

    # Enforce challenger cap
    num_challengers = min(args.challengers, 2)

    target_path = ROOT / "sandbox_target" / target_file
    if not target_path.exists():
        print(_red(f"  ERROR: Target file not found: {target_path}"))
        sys.exit(1)

    target_src = target_path.read_text(encoding="utf-8")

    print(_bold(f"\n  {'='*70}"))
    print(_bold(f"  {mode_label}"))
    print(_bold(f"  Description: {mode_desc}"))
    print(_bold(f"  Target File: {target_file} ({len(target_src.splitlines())} lines)"))
    print(_bold(f"  Challengers: {num_challengers} (strictly enforced)"))
    print(_bold(f"  Workers:     {args.workers} (serial execution)"))
    print(_bold(f"  {'='*70}"))

    client = LLMClient(model=args.model, base_url=args.url)
    model_used = check_ollama(client)

    if args.challenger_model:
        challenger_client = LLMClient(model=args.challenger_model, base_url=args.url)
        challenger_model_used = check_ollama(challenger_client)
    else:
        challenger_client = client
        challenger_model_used = model_used

    # Per-run scoped DB — eliminates cross-run blackboard pollution
    db_path = make_db_path(ROOT, cycle_key=cycle_key)
    print(f"\n  Run DB: {db_path}")
    conn = get_conn(db_path=db_path)
    set_meta(conn, "model", model_used)
    set_meta(conn, "challenger_model", challenger_model_used)
    set_meta(conn, "workers", str(args.workers))
    set_meta(conn, "cycle", cycle_key)
    set_meta(conn, "challengers", str(num_challengers))

    start = time.time()

    # --- Phase 0: Static Pre-Filter (Cycle 15, 16, 17, 18, 19, 20, 21, 22) ---
    if cycle_key in ("15", "16", "17", "18", "19", "20", "21", "22"):
        run_static_prefilter(conn, target_src)

    # --- Phase 1: Discovery (serial, cycle_key forwarded to select prompt) ---
    run_discovery(client, conn, args.workers, target_src, cycle_key=cycle_key)

    # --- Phase 2: Challenge ---
    # Cycle 16 + 17 + 18 + 19 + 20 + 21 + 22: preserve_partial=True
    preserve_partial = (cycle_key in ("16", "17", "18", "19", "20", "21", "22"))
    run_challenge(
        client, conn, target_src,
        num_challengers=num_challengers,
        preserve_partial=preserve_partial,
        challenger_client=challenger_client,
        cycle_key=cycle_key,
    )

    # --- Phase 3: Aggregation ---
    if cycle_key in ("19", "20", "21", "22"):
        c19_counts = run_cycle19_verdict_aggregation(conn)
    elif cycle_key in ("16", "17", "18"):
        calib_counts = run_calibrated_verdict_aggregation(conn)
    else:
        run_verdict_aggregation(conn)
        calib_counts = None

    # --- Baseline (optional) ---
    baseline = run_single_agent_baseline(client, target_src) if args.baseline else []

    # --- Phase 4: Measurement & Reporting ---
    if cycle_key in ("19", "20", "21", "22"):
        result = print_cycle19_report(
            conn, c19_counts, start, model_used,
            target_file=target_file, db_path=db_path,
            challenger_model=challenger_model_used,
            cycle_label=cycle_key,
        )
    elif cycle_key in ("16", "17", "18"):
        result = print_calibration_report(
            conn, calib_counts, start, model_used,
            target_file=target_file, db_path=db_path,
            cycle_label=cycle_key,
            challenger_model=challenger_model_used,
        )
    else:
        result = print_report(
            conn, baseline, start, model_used,
            cycle_key=cycle_key, target_file=target_file, db_path=db_path,
        )

    conn.close()
    return result


if __name__ == "__main__":
    main()
