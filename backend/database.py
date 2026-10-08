"""
Swarm Security Scanner — SQLite Persistence & State Storage
===========================================================
Replaces purely volatile in-memory state with durable SQLite storage:
  - Preserves run history, findings, and logs across server restarts
  - Provides thread-safe concurrency for multi-worker writes
  - Enables audit trails and post-scan analysis
"""

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

_db_lock = threading.Lock()
_mem_conn = None

import tempfile

def _get_db_path() -> str:
    default_path = os.path.join(os.path.dirname(__file__), "data", "swarm_runs.db")
    try:
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
        # Test if we can write to it
        test_file = os.path.join(os.path.dirname(default_path), ".test_write")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
    except Exception:
        # Fallback to temp dir due to Windows Defender / permissions
        default_path = os.path.join(tempfile.gettempdir(), "swarm_runs.db")
    return os.getenv("SWARM_DB_PATH", default_path)

def _get_connection() -> sqlite3.Connection:
    global _mem_conn
    path = _get_db_path()
    if path == ":memory:":
        if _mem_conn is None:
            _mem_conn = sqlite3.connect("file:swarm_mem_db?mode=memory&cache=shared", uri=True, check_same_thread=False, timeout=30.0)
            _mem_conn.row_factory = sqlite3.Row
        return _mem_conn

    conn = sqlite3.connect(path, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def _release_connection(conn: sqlite3.Connection):
    path = _get_db_path()
    if path != ":memory:":
        try:
            conn.close()
        except Exception:
            pass

def init_db():
    """Initializes tables and indexes if they do not exist."""
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS runs (
                        run_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        config_json TEXT NOT NULL,
                        started_at REAL NOT NULL,
                        completed_at REAL,
                        exit_code INTEGER
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_id TEXT NOT NULL,
                        type TEXT NOT NULL,
                        agent TEXT NOT NULL,
                        content TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        FOREIGN KEY (run_id) REFERENCES runs(run_id)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_run_id ON logs(run_id)")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS feedback (
                        run_id TEXT NOT NULL,
                        finding_idx INTEGER NOT NULL,
                        human_verdict TEXT NOT NULL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY (run_id, finding_idx)
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS architecture (
                        repo_url TEXT PRIMARY KEY,
                        map_json TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY,
                        repository TEXT NOT NULL,
                        file TEXT NOT NULL,
                        line INTEGER NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        cwe TEXT,
                        owasp TEXT,
                        status TEXT NOT NULL,
                        owner TEXT,
                        ai_verdict TEXT NOT NULL,
                        swarm_rationale TEXT NOT NULL,
                        code_snippet TEXT,
                        exploit_path TEXT,
                        exploit_verified INTEGER,
                        exploit_output TEXT,
                        remediation_suggestion TEXT,
                        tool TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        first_detected REAL NOT NULL,
                        last_detected REAL NOT NULL,
                        scan_id TEXT NOT NULL,
                        fixed_at REAL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS repositories (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        url TEXT NOT NULL,
                        type TEXT NOT NULL,
                        last_scanned REAL,
                        open_findings INTEGER NOT NULL,
                        critical_count INTEGER NOT NULL,
                        high_count INTEGER NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS frontend_runs (
                        id TEXT PRIMARY KEY,
                        run_json TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS notification_settings (
                        id TEXT PRIMARY KEY,
                        webhook_url TEXT NOT NULL,
                        channel_type TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        notify_on_critical INTEGER NOT NULL DEFAULT 1,
                        notify_on_complete INTEGER NOT NULL DEFAULT 1,
                        updated_at REAL NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        name TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'analyst',
                        api_key_hash TEXT,
                        created_at REAL NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_email TEXT NOT NULL,
                        action TEXT NOT NULL,
                        resource_type TEXT NOT NULL,
                        resource_id TEXT,
                        details TEXT,
                        timestamp REAL NOT NULL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)")
        finally:
            _release_connection(conn)

# Auto-initialize DB on module load
init_db()

def create_run(run_id: str, scan_type: str, config: Dict[str, Any], started_at: Optional[float] = None) -> Dict[str, Any]:
    started_at = started_at or time.time()
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO runs (run_id, status, scan_type, config_json, started_at) VALUES (?, ?, ?, ?, ?)",
                    (run_id, "running", scan_type, json.dumps(config), started_at),
                )
        finally:
            _release_connection(conn)
    return {"run_id": run_id, "status": "running", "scan_type": scan_type, **config, "started_at": started_at}

def update_run_status(run_id: str, status: str, exit_code: Optional[int] = None):
    completed_at = time.time() if status in ("done", "partial", "error") else None
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute(
                    "UPDATE runs SET status = ?, exit_code = ?, completed_at = ? WHERE run_id = ?",
                    (status, exit_code, completed_at, run_id),
                )
        finally:
            _release_connection(conn)

def mark_interrupted_runs():
    """Mark any 'running' scans as 'error' after a server restart."""
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute(
                    "UPDATE runs SET status = 'error', exit_code = -2, completed_at = ? WHERE status = 'running'",
                    (time.time(),)
                )
        finally:
            _release_connection(conn)

def get_run(run_id: str) -> Optional[Dict[str, Any]]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            config = json.loads(res.pop("config_json", "{}"))
            return {**res, **config}
        finally:
            _release_connection(conn)

def list_runs(limit: int = 50) -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,))
            runs = []
            for row in cur.fetchall():
                res = dict(row)
                config = json.loads(res.pop("config_json", "{}"))
                runs.append({**res, **config})
            return runs
        finally:
            _release_connection(conn)

def append_log(run_id: str, log_type: str, agent: str, content: str, timestamp: Optional[float] = None):
    timestamp = timestamp or time.time()
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO logs (run_id, type, agent, content, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (run_id, log_type, agent, content, timestamp),
                )
        finally:
            _release_connection(conn)

def get_logs_for_run(run_id: str) -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT type, agent, content, timestamp FROM logs WHERE run_id = ? ORDER BY id ASC", (run_id,))
            return [dict(row) for row in cur.fetchall()]
        finally:
            _release_connection(conn)

def save_feedback(run_id: str, finding_idx: int, human_verdict: str):
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO feedback (run_id, finding_idx, human_verdict, updated_at) VALUES (?, ?, ?, ?)",
                    (run_id, finding_idx, human_verdict, time.time()),
                )
        finally:
            _release_connection(conn)

def get_feedback_for_run(run_id: str) -> Dict[int, str]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT finding_idx, human_verdict FROM feedback WHERE run_id = ?", (run_id,))
            return {row["finding_idx"]: row["human_verdict"] for row in cur.fetchall()}
        finally:
            _release_connection(conn)

def save_architecture(repo_url: str, map_json: str):
    # Ensure neither host root path nor raw file contents are ever persisted
    try:
        data = json.loads(map_json)
        if isinstance(data, dict):
            data.pop("root", None)
            data.pop("files", None)
            map_json = json.dumps(data)
    except Exception:
        pass

    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO architecture (repo_url, map_json, updated_at) VALUES (?, ?, ?)",
                    (repo_url, map_json, time.time())
                )
        finally:
            _release_connection(conn)

def get_architecture(repo_url: str) -> Optional[str]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT map_json FROM architecture WHERE repo_url = ?", (repo_url,))
            row = cur.fetchone()
            if row:
                raw = row["map_json"]
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict) and ("root" in data or "files" in data):
                        data.pop("root", None)
                        data.pop("files", None)
                        return json.dumps(data)
                except Exception:
                    pass
                return raw
            return None
        finally:
            _release_connection(conn)

def save_findings(findings: List[Dict[str, Any]]):
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM findings")
                for f in findings:
                    conn.execute("""
                        INSERT INTO findings (
                            id, repository, file, line, title, description, severity,
                            cwe, owasp, status, owner, ai_verdict, swarm_rationale,
                            code_snippet, exploit_path, exploit_verified, exploit_output,
                            remediation_suggestion, tool, rule_id, first_detected,
                            last_detected, scan_id, fixed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        f.get("id"), f.get("repository"), f.get("file"), f.get("line"),
                        f.get("title"), f.get("description"), f.get("severity"),
                        f.get("cwe"), f.get("owasp"), f.get("status"), f.get("owner"),
                        f.get("aiVerdict"), f.get("swarmRationale"), f.get("codeSnippet"),
                        f.get("exploitPath"), 1 if f.get("exploitVerified") else 0,
                        f.get("exploitOutput"), f.get("remediationSuggestion"),
                        f.get("tool"), f.get("ruleId"), f.get("firstDetected"),
                        f.get("lastDetected"), f.get("scanId"), f.get("fixedAt")
                    ))
        finally:
            _release_connection(conn)

def list_findings() -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT * FROM findings")
            res = []
            for row in cur.fetchall():
                d = dict(row)
                res.append({
                    "id": d["id"], "repository": d["repository"], "file": d["file"], "line": d["line"],
                    "title": d["title"], "description": d["description"], "severity": d["severity"],
                    "cwe": d["cwe"], "owasp": d["owasp"], "status": d["status"], "owner": d["owner"],
                    "aiVerdict": d["ai_verdict"], "swarmRationale": d["swarm_rationale"],
                    "codeSnippet": d["code_snippet"], "exploitPath": d["exploit_path"],
                    "exploitVerified": bool(d["exploit_verified"]), "exploitOutput": d["exploit_output"],
                    "remediationSuggestion": d["remediation_suggestion"], "tool": d["tool"],
                    "ruleId": d["rule_id"], "firstDetected": d["first_detected"],
                    "lastDetected": d["last_detected"], "scanId": d["scan_id"], "fixedAt": d["fixed_at"]
                })
            return res
        finally:
            _release_connection(conn)

def save_repositories(repos: List[Dict[str, Any]]):
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM repositories")
                for r in repos:
                    conn.execute("""
                        INSERT INTO repositories (
                            id, name, url, type, last_scanned, open_findings, critical_count, high_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        r.get("id"), r.get("name"), r.get("url"), r.get("type"),
                        r.get("lastScanned"), r.get("openFindings", 0),
                        r.get("criticalCount", 0), r.get("highCount", 0)
                    ))
        finally:
            _release_connection(conn)

def list_repositories() -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT * FROM repositories")
            res = []
            for row in cur.fetchall():
                d = dict(row)
                res.append({
                    "id": d["id"], "name": d["name"], "url": d["url"], "type": d["type"],
                    "lastScanned": d["last_scanned"], "openFindings": d["open_findings"],
                    "criticalCount": d["critical_count"], "highCount": d["high_count"]
                })
            return res
        finally:
            _release_connection(conn)

def save_frontend_runs(runs: List[Dict[str, Any]]):
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM frontend_runs")
                for r in runs:
                    conn.execute("INSERT INTO frontend_runs (id, run_json) VALUES (?, ?)", (r.get("id"), json.dumps(r)))
        finally:
            _release_connection(conn)

def list_frontend_runs() -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT run_json FROM frontend_runs")
            return [json.loads(row["run_json"]) for row in cur.fetchall()]
        finally:
            _release_connection(conn)


# ---------------------------------------------------------------------------
# Notification Settings Persistence
# ---------------------------------------------------------------------------

def save_notification_setting(setting_id: str, webhook_url: str, channel_type: str, enabled: bool, notify_on_critical: bool, notify_on_complete: bool):
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT OR REPLACE INTO notification_settings (
                        id, webhook_url, channel_type, enabled, notify_on_critical, notify_on_complete, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    setting_id, webhook_url, channel_type,
                    1 if enabled else 0,
                    1 if notify_on_critical else 0,
                    1 if notify_on_complete else 0,
                    time.time()
                ))
        finally:
            _release_connection(conn)


def get_notification_settings() -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT * FROM notification_settings")
            return [
                {
                    "id": row["id"],
                    "webhook_url": row["webhook_url"],
                    "channel_type": row["channel_type"],
                    "enabled": bool(row["enabled"]),
                    "notify_on_critical": bool(row["notify_on_critical"]),
                    "notify_on_complete": bool(row["notify_on_complete"]),
                    "updated_at": row["updated_at"],
                }
                for row in cur.fetchall()
            ]
        finally:
            _release_connection(conn)


# ---------------------------------------------------------------------------
# Users & RBAC Team Management
# ---------------------------------------------------------------------------

def create_user(user_id: str, email: str, name: str, role: str = "analyst", api_key_hash: Optional[str] = None) -> Dict[str, Any]:
    now = time.time()
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT OR REPLACE INTO users (id, email, name, role, api_key_hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, email, name, role, api_key_hash, now))
        finally:
            _release_connection(conn)
    return {"id": user_id, "email": email, "name": name, "role": role, "created_at": now}


def list_users() -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT id, email, name, role, created_at FROM users ORDER BY created_at ASC")
            return [dict(row) for row in cur.fetchall()]
        finally:
            _release_connection(conn)


def delete_user(user_id: str):
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        finally:
            _release_connection(conn)


# ---------------------------------------------------------------------------
# Audit Logs
# ---------------------------------------------------------------------------

def log_audit_event(user_email: str, action: str, resource_type: str, resource_id: Optional[str] = None, details: Optional[str] = None):
    with _db_lock:
        conn = _get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO audit_logs (user_email, action, resource_type, resource_id, details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_email, action, resource_type, resource_id, details, time.time()))
        finally:
            _release_connection(conn)


def list_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    with _db_lock:
        conn = _get_connection()
        try:
            cur = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cur.fetchall()]
        finally:
            _release_connection(conn)

