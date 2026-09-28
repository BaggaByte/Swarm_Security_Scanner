import sqlite3, json

def query_db(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    d = {}

    meta = {r["key"]: r["value"] for r in conn.execute("SELECT * FROM run_meta").fetchall()}
    d["meta"] = meta

    d["findings_total"] = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]

    # Try source column; fall back to agent_role heuristic
    try:
        d["findings_llm"] = conn.execute("SELECT COUNT(*) as c FROM findings WHERE source = 'llm'").fetchone()["c"]
        d["findings_static"] = conn.execute("SELECT COUNT(*) as c FROM findings WHERE source = 'static_pre_filter' OR source = 'static'").fetchone()["c"]
    except Exception:
        d["findings_llm"] = conn.execute("SELECT COUNT(*) as c FROM findings WHERE agent_role != 'static_pre_filter'").fetchone()["c"]
        d["findings_static"] = conn.execute("SELECT COUNT(*) as c FROM findings WHERE agent_role = 'static_pre_filter'").fetchone()["c"]

    d["schema_rejects"] = conn.execute("SELECT COUNT(*) as c FROM schema_rejects").fetchone()["c"]
    d["infra_errors"] = conn.execute("SELECT COUNT(*) as c FROM infra_errors").fetchone()["c"]
    d["challenges"] = conn.execute("SELECT COUNT(*) as c FROM challenges").fetchone()["c"]

    d["verdicts"] = {r[0]: r[1] for r in conn.execute("SELECT verdict, COUNT(*) as c FROM challenges GROUP BY verdict").fetchall()}
    d["raw_verdicts"] = {r[0]: r[1] for r in conn.execute("SELECT raw_verdict, COUNT(*) as c FROM challenges GROUP BY raw_verdict").fetchall()}
    d["factual_validity"] = {r[0]: r[1] for r in conn.execute("SELECT factual_validity, COUNT(*) as c FROM challenges GROUP BY factual_validity").fetchall()}
    d["attack_path"] = {r[0]: r[1] for r in conn.execute("SELECT attack_path, COUNT(*) as c FROM challenges GROUP BY attack_path").fetchall()}
    d["security_property"] = {r[0]: r[1] for r in conn.execute("SELECT security_property, COUNT(*) as c FROM challenges GROUP BY security_property").fetchall()}
    d["severity_eval"] = {r[0]: r[1] for r in conn.execute("SELECT severity_eval, COUNT(*) as c FROM challenges GROUP BY severity_eval").fetchall()}
    d["overall_verdict"] = {r[0]: r[1] for r in conn.execute("SELECT overall_verdict, COUNT(*) as c FROM challenges GROUP BY overall_verdict").fetchall()}

    d["findings_by_agent"] = {r[0]: r[1] for r in conn.execute("SELECT agent_role, COUNT(*) as c FROM findings GROUP BY agent_role").fetchall()}

    # GT coverage
    try:
        d["gt_covered"] = conn.execute("SELECT COUNT(DISTINCT ground_truth_id) as c FROM findings WHERE ground_truth_id IS NOT NULL AND ground_truth_id != ''").fetchone()["c"]
    except Exception:
        d["gt_covered"] = "N/A"

    # Unique LLM findings challenged
    d["unique_findings_challenged"] = conn.execute("SELECT COUNT(DISTINCT finding_id) as c FROM challenges").fetchone()["c"]

    # OVERREJECTION / CORRECT_REJECTION via classification
    try:
        d["overrejections"] = conn.execute("SELECT COUNT(*) as c FROM findings WHERE decomposition_classification = 'OVERREJECTION'").fetchone()["c"]
        d["correct_rejections"] = conn.execute("SELECT COUNT(*) as c FROM findings WHERE decomposition_classification = 'CORRECT_REJECTION'").fetchone()["c"]
        d["full_validity"] = conn.execute("SELECT COUNT(*) as c FROM findings WHERE decomposition_classification = 'FULL_VALIDITY' AND source != 'static_pre_filter' AND source != 'static'").fetchone()["c"]
        d["partial_validity"] = conn.execute("SELECT COUNT(*) as c FROM findings WHERE decomposition_classification = 'PARTIAL_VALIDITY'").fetchone()["c"]
    except Exception:
        d["overrejections"] = "N/A"
        d["correct_rejections"] = "N/A"
        d["full_validity"] = "N/A"
        d["partial_validity"] = "N/A"

    conn.close()
    return d

print("=== CYCLE 19 ===")
c19 = query_db(r"C:\Users\Lenovo\AppData\Local\Temp\cycle19_run_1789929313.db")
print(json.dumps(c19, indent=2, default=str))

print("\n=== CYCLE 20 ===")
c20 = query_db(r"C:\Users\Lenovo\AppData\Local\Temp\cycle20_run_1790005719.db")
print(json.dumps(c20, indent=2, default=str))
