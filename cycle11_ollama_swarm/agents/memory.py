"""
Cycle 15 – Shared SQLite Memory (per-run scoped)
==================================================
All agents read and write to a single SQLite database per run.

Changes from Cycle 14:
  - get_conn() now accepts an explicit db_path for per-run isolation.
    DB filename defaults to cycle15_run_<timestamp>.db to prevent cross-run
    blackboard pollution (the root cause of the 33-finding bleed in Cycle 14).
  - findings table has a new 'source' column: 'llm' | 'static_pre_filter'
  - findings table has a new 'pre_confirmed' column: 0 | 1
    Static pre-filter findings skip Phase 2 challenger review.
  - get_all_findings() and get_all_verdicts() filter by run_id by default.
  - record_static_finding() inserts pre-confirmed static findings.

Tables:
  findings     – raw hypotheses emitted by agents (LLM or static)
  challenges   – adversarial challenges from challenger agents
  verdicts     – final confirmed / refuted status after challenge round
  run_meta     – high-level run statistics
  schema_rejects – findings dropped by schema_validator (telemetry)
  infra_errors – infrastructure failures (OLLAMA_UNAVAILABLE, timeouts)
"""
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import tempfile
import time

_DEFAULT_DB_STEM = "cycle15_run"


def _writable_path(p: Path) -> Path:
    """Return p if it's in a writable directory, else fall back to TEMP."""
    try:
        test = p.parent / ".write_test_tmp"
        test.write_text("x")
        test.unlink()
        return p
    except Exception:
        return Path(tempfile.gettempdir()) / p.name


def make_db_path(root: Path, cycle_key: str = "15") -> Path:
    """
    Generate a unique per-run database path.
    Example: <workspace>/cycle15_run_1726123456.db
    """
    ts = int(time.time())
    stem = f"cycle{cycle_key}_run_{ts}.db"
    candidate = root / stem
    return _writable_path(candidate)


def get_conn(db_path: Path = None) -> sqlite3.Connection:
    """
    Open (or create) the SQLite database at db_path.
    If db_path is None, a legacy fallback path is used (for backward compat).
    """
    if db_path is None:
        # Legacy fallback — only used if caller does not supply a path
        _root = Path(__file__).parent.parent
        db_path = _writable_path(_root / "cycle11_memory.db")

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS findings (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id          TEXT NOT NULL,
        agent_role        TEXT NOT NULL,
        hypothesis        TEXT NOT NULL,
        evidence          TEXT NOT NULL,
        severity          TEXT NOT NULL DEFAULT 'unknown',
        discovery_seconds REAL,
        source            TEXT NOT NULL DEFAULT 'llm',
        pre_confirmed     INTEGER NOT NULL DEFAULT 0,
        ground_truth_id   TEXT,
        created_at        TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS challenges (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id          INTEGER NOT NULL REFERENCES findings(id),
        challenger_id       TEXT NOT NULL,
        challenge_text      TEXT NOT NULL,
        verdict             TEXT NOT NULL DEFAULT 'pending',
        raw_verdict         TEXT,  -- FULL_VALID | PARTIAL | FULL_INVALID (Cycle 16 calibration)
        factual_validity    TEXT,  -- VALID | PARTIAL | INVALID (Cycle 19)
        attack_path         TEXT,  -- SUPPORTED | PARTIAL | UNSUPPORTED (Cycle 19)
        security_property   TEXT,  -- SUPPORTED | UNSUPPORTED (Cycle 19)
        consequence         TEXT,  -- SUPPORTED | OVERSTATED | UNSUPPORTED (Cycle 19)
        severity_eval       TEXT,  -- AGREE | DISAGREE | INDETERMINATE (Cycle 19)
        overall_verdict     TEXT,  -- CONFIRMED | PARTIALLY_SUPPORTED | INVALID (Cycle 19)
        related_real_issue  INTEGER, -- 1 | 0 (Cycle 19)
        stated_claim_valid  INTEGER, -- 1 | 0 (Cycle 19)
        created_at          TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS verdicts (
        finding_id                   INTEGER PRIMARY KEY REFERENCES findings(id),
        final_verdict                TEXT NOT NULL,  -- confirmed | refuted | inconclusive
        calibrated_verdict           TEXT,           -- STRICT_CONFIRMED | PARTIAL_CONFIRMED | NOT_CONFIRMED | REFUTED
        overrejection_status         TEXT,           -- CORRECT | OVERREJECTION | UNCERTAIN
        original_claim_verdict       TEXT,           -- CONFIRMED | PARTIALLY_SUPPORTED | REFUTED | INCONCLUSIVE (Cycle 19)
        underlying_assessment        TEXT,           -- REAL_ISSUE_PRESENT | NO_REAL_ISSUE (Cycle 19)
        decomposition_classification TEXT,           -- FULL_VALIDITY | PARTIAL_VALIDITY | OVERREJECTION | CORRECT_REJECTION (Cycle 19)
        confirmed_by                 TEXT,
        refuted_by                   TEXT,
        notes                        TEXT,
        calibration_notes            TEXT,
        resolved_at                  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS run_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS schema_rejects (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id      TEXT NOT NULL,
        agent_role    TEXT NOT NULL,
        hypothesis    TEXT NOT NULL,
        rejection_reason TEXT NOT NULL,
        created_at    TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS infra_errors (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id    TEXT NOT NULL,
        error_type  TEXT NOT NULL,
        detail      TEXT,
        created_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS schema_audit (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id          TEXT NOT NULL,
        agent_role        TEXT NOT NULL,
        hypothesis        TEXT NOT NULL,
        status            TEXT NOT NULL,
        rejection_reason  TEXT,
        path              TEXT,
        location          TEXT,
        security_property TEXT,
        raw_text          TEXT,
        created_at        TEXT NOT NULL
    );
    """)
    conn.commit()


def record_finding(
    conn,
    agent_id: str,
    role: str,
    hypothesis: str,
    evidence: str,
    severity: str = "medium",
    discovery_seconds: float = None,
    source: str = "llm",
    pre_confirmed: bool = False,
    ground_truth_id: str = None,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """INSERT INTO findings
               (agent_id, agent_role, hypothesis, evidence, severity,
                discovery_seconds, source, pre_confirmed, ground_truth_id, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (agent_id, role, hypothesis, evidence, severity,
         discovery_seconds, source, int(pre_confirmed), ground_truth_id, now),
    )
    conn.commit()
    return cur.lastrowid


def record_static_finding(conn, finding: dict) -> int:
    """Insert a pre-confirmed static pre-filter finding directly."""
    return record_finding(
        conn,
        agent_id="static_pre_filter",
        role="static_pre_filter",
        hypothesis=finding["hypothesis"],
        evidence=finding["evidence"],
        severity=finding.get("severity", "high"),
        discovery_seconds=0.0,
        source="static_pre_filter",
        pre_confirmed=True,
        ground_truth_id=finding.get("ground_truth_id"),
    )


def record_schema_reject(conn, agent_id: str, role: str, hypothesis: str, rejection_reason: str):
    """Log a finding that was rejected by the schema validator."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO schema_rejects (agent_id, agent_role, hypothesis, rejection_reason, created_at) VALUES (?,?,?,?,?)",
        (agent_id, role, hypothesis, rejection_reason, now),
    )
    conn.commit()


def record_infra_error(conn, agent_id: str, error_type: str, detail: str = None):
    """Log an infrastructure failure (timeout, Ollama unavailable) as telemetry."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO infra_errors (agent_id, error_type, detail, created_at) VALUES (?,?,?,?)",
        (agent_id, error_type, detail, now),
    )
    conn.commit()


def record_challenge(
    conn,
    finding_id: int,
    challenger_id: str,
    challenge_text: str,
    verdict: str = "pending",
    raw_verdict: str = None,
    factual_validity: str = None,
    attack_path: str = None,
    security_property: str = None,
    consequence: str = None,
    severity_eval: str = None,
    overall_verdict: str = None,
    related_real_issue: bool = None,
    stated_claim_valid: bool = None,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    rri_val = int(related_real_issue) if related_real_issue is not None else None
    scv_val = int(stated_claim_valid) if stated_claim_valid is not None else None
    cur = conn.execute(
        """INSERT INTO challenges (
            finding_id, challenger_id, challenge_text, verdict, raw_verdict,
            factual_validity, attack_path, security_property, consequence,
            severity_eval, overall_verdict, related_real_issue, stated_claim_valid,
            created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            finding_id, challenger_id, challenge_text, verdict, raw_verdict,
            factual_validity, attack_path, security_property, consequence,
            severity_eval, overall_verdict, rri_val, scv_val,
            now,
        ),
    )
    conn.commit()
    return cur.lastrowid


def record_verdict(
    conn,
    finding_id: int,
    final_verdict: str,
    confirmed_by: str = None,
    refuted_by: str = None,
    notes: str = "",
    calibrated_verdict: str = None,
    overrejection_status: str = None,
    calibration_notes: str = None,
    original_claim_verdict: str = None,
    underlying_assessment: str = None,
    decomposition_classification: str = None,
):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT OR REPLACE INTO verdicts
               (finding_id, final_verdict, calibrated_verdict, overrejection_status,
                original_claim_verdict, underlying_assessment, decomposition_classification,
                confirmed_by, refuted_by, notes, calibration_notes, resolved_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (finding_id, final_verdict, calibrated_verdict, overrejection_status,
         original_claim_verdict, underlying_assessment, decomposition_classification,
         confirmed_by, refuted_by, notes, calibration_notes, now),
    )
    conn.commit()


def get_all_findings(conn, source_filter: str = None) -> list:
    """
    Return all findings, optionally filtered by source.
    source_filter: 'llm' | 'static_pre_filter' | None (all)
    """
    if source_filter:
        rows = conn.execute(
            "SELECT * FROM findings WHERE source=? ORDER BY id", (source_filter,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
    return [dict(row) for row in rows]


def get_llm_findings(conn) -> list:
    """Return only LLM-generated findings (excludes static pre-filter)."""
    return get_all_findings(conn, source_filter="llm")


def get_static_findings(conn) -> list:
    """Return only static pre-filter findings."""
    return get_all_findings(conn, source_filter="static_pre_filter")


def get_all_verdicts(conn) -> list:
    return [dict(row) for row in conn.execute(
        """SELECT f.id, f.agent_id, f.agent_role, f.hypothesis, f.severity,
                  f.discovery_seconds, f.source, f.pre_confirmed, f.ground_truth_id,
                  v.final_verdict, v.calibrated_verdict, v.overrejection_status,
                  v.notes, v.calibration_notes,
                  v.original_claim_verdict, v.underlying_assessment, v.decomposition_classification
           FROM findings f
           LEFT JOIN verdicts v ON v.finding_id = f.id
           ORDER BY f.id"""
    ).fetchall()]


def get_challenger_breakdown(conn) -> list:
    """Return per-finding challenger vote detail (includes raw_verdict and Cycle 19 decomposition)."""
    return [dict(row) for row in conn.execute(
        """SELECT * FROM challenges ORDER BY finding_id, challenger_id"""
    ).fetchall()]


def get_schema_rejects(conn) -> list:
    """Return all schema-rejected findings (telemetry)."""
    return [dict(row) for row in conn.execute(
        "SELECT * FROM schema_rejects ORDER BY id"
    ).fetchall()]


def record_schema_audit(
    conn,
    agent_id: str,
    role: str,
    hypothesis: str,
    status: str,
    rejection_reason: str = None,
    path: str = None,
    location: str = None,
    security_property: str = None,
    raw_text: str = None,
) -> int:
    """Log an audit entry for every discovery output (accepted or rejected)."""
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """INSERT INTO schema_audit
           (agent_id, agent_role, hypothesis, status, rejection_reason, path, location, security_property, raw_text, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (agent_id, role, hypothesis, status, rejection_reason, path, location, security_property, raw_text, now),
    )
    conn.commit()
    return cur.lastrowid


def get_schema_audit(conn) -> list:
    """Return all schema audit records."""
    return [dict(row) for row in conn.execute(
        "SELECT * FROM schema_audit ORDER BY id"
    ).fetchall()]


def get_infra_errors(conn) -> list:
    """Return all infrastructure errors (telemetry)."""
    return [dict(row) for row in conn.execute(
        "SELECT * FROM infra_errors ORDER BY id"
    ).fetchall()]


def get_duplicate_pairs(conn, similarity_threshold: float = 0.40) -> list:
    """
    Detect semantically overlapping findings across different agents.
    Only considers LLM findings (not static pre-filter).
    """
    findings = get_llm_findings(conn)

    def _tokens(text: str) -> set:
        return set(text.lower().split())

    pairs = []
    for i, fa in enumerate(findings):
        for fb in findings[i+1:]:
            if fa["agent_role"] == fb["agent_role"]:
                continue
            ta = _tokens(fa["hypothesis"])
            tb = _tokens(fb["hypothesis"])
            union = ta | tb
            if not union:
                continue
            score = len(ta & tb) / len(union)
            if score >= similarity_threshold:
                pairs.append({
                    "id_a": fa["id"], "id_b": fb["id"],
                    "role_a": fa["agent_role"], "role_b": fb["agent_role"],
                    "similarity": round(score, 3),
                    "hypothesis_a": fa["hypothesis"],
                    "hypothesis_b": fb["hypothesis"],
                })
    return sorted(pairs, key=lambda x: -x["similarity"])


def set_meta(conn, key: str, value: str):
    conn.execute("INSERT OR REPLACE INTO run_meta (key,value) VALUES (?,?)", (key, value))
    conn.commit()


def get_meta(conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM run_meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None
