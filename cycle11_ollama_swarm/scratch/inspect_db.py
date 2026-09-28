import sqlite3
import json

def inspect_run(label, db_path):
    print("=" * 35, label, "=" * 35)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    print("--- RUN META ---")
    for r in conn.execute("SELECT * FROM run_meta"):
        print(f"  {r['key']}: {r['value']}")

    print("\n--- FINDINGS & VERDICTS ---")
    rows = conn.execute("""
        SELECT f.id, f.agent_role, f.source, f.hypothesis, f.severity, f.ground_truth_id,
               v.final_verdict, v.calibrated_verdict, v.overrejection_status,
               v.original_claim_verdict, v.underlying_assessment, v.decomposition_classification
        FROM findings f
        LEFT JOIN verdicts v ON f.id = v.finding_id
        ORDER BY f.id
    """).fetchall()
    for r in rows:
        print(f"ID={r['id']:<2} | Role={r['agent_role']:<20} | Src={r['source']:<16} | GT={str(r['ground_truth_id']):<20} | Final={str(r['final_verdict']):<10} | DecompClass={str(r['decomposition_classification']):<18} | OverrejStat={str(r['overrejection_status'])}")
        print(f"     Hypothesis: {r['hypothesis'][:100]}...")

    print("\n--- CHALLENGES ---")
    ch_rows = conn.execute("""
        SELECT id, finding_id, challenger_id, factual_validity, attack_path,
               security_property, consequence, severity_eval, overall_verdict,
               related_real_issue, stated_claim_valid, raw_verdict, verdict
        FROM challenges
        ORDER BY finding_id, id
    """).fetchall()
    for c in ch_rows:
        print(f"CH {c['id']:<2} | Finding {c['finding_id']:<2} | Ch={c['challenger_id']} | Fact={c['factual_validity']:<7} | Atk={c['attack_path']:<11} | Sec={c['security_property']:<11} | Sev={c['severity_eval']:<13} | Overall={c['overall_verdict']:<19} | Claim={c['stated_claim_valid']} | Rel={c['related_real_issue']} | Raw={c['raw_verdict']}")

    print("\n--- SCHEMA REJECTS ---")
    sr_rows = conn.execute("SELECT * FROM schema_rejects").fetchall()
    for sr in sr_rows:
        print(f"Agent={sr['agent_role']} | Reason={sr['rejection_reason']}")
        print(f"  Hyp: {sr['hypothesis'][:120]}...")

    print("\n--- SUMMARY COUNTS ---")
    total_findings = len(rows)
    llm_findings = [r for r in rows if r['source'] == 'llm']
    static_findings = [r for r in rows if r['source'] != 'llm']
    print(f"Total findings: {total_findings}")
    print(f"Static findings: {len(static_findings)}")
    print(f"LLM findings: {len(llm_findings)}")
    print(f"Schema rejects: {len(sr_rows)}")

    decomp_counts = {}
    for r in rows:
        dc = r['decomposition_classification']
        decomp_counts[dc] = decomp_counts.get(dc, 0) + 1
    print("Decomposition classifications (all):", decomp_counts)

    decomp_llm = {}
    for r in llm_findings:
        dc = r['decomposition_classification']
        decomp_llm[dc] = decomp_llm.get(dc, 0) + 1
    print("Decomposition classifications (LLM only):", decomp_llm)

    conn.close()

inspect_run("CYCLE 19", r"C:\Users\Lenovo\AppData\Local\Temp\cycle19_run_1789929313.db")
inspect_run("CYCLE 20", r"C:\Users\Lenovo\AppData\Local\Temp\cycle20_run_1790005719.db")
