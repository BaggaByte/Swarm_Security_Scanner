import sqlite3
import json

def analyze(name, path):
    print("=" * 40, name, "=" * 40)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    
    meta = {r["key"]: r["value"] for r in conn.execute("SELECT * FROM run_meta").fetchall()}
    print("Meta:", meta)
    
    findings = conn.execute("SELECT * FROM findings").fetchall()
    print(f"\nTotal findings: {len(findings)}")
    for f in findings:
        d = dict(f)
        print(f"ID={d.get('id')}, Role={d.get('agent_role')}, Source={d.get('source')}, Title={d.get('title')}, Severity={d.get('severity')}, GT={d.get('ground_truth_id')}, DecompClass={d.get('decomposition_classification')}, Consensus={d.get('consensus_verdict')}")
    
    challenges = conn.execute("SELECT * FROM challenges").fetchall()
    print(f"\nTotal challenges: {len(challenges)}")
    for ch in challenges:
        cd = dict(ch)
        print(f"CH_ID={cd.get('id')} Finding={cd.get('finding_id')} Ch={cd.get('challenger_name')} Fact={cd.get('factual_validity')} Atk={cd.get('attack_path')} Sec={cd.get('security_property')} Sev={cd.get('severity_eval')} Raw={cd.get('raw_verdict')} Verd={cd.get('verdict')} StatedClaim={cd.get('stated_claim_valid')} RelIssue={cd.get('related_real_issue')}")

    schema_rejects = conn.execute("SELECT * FROM schema_rejects").fetchall()
    print(f"\nSchema rejects: {len(schema_rejects)}")
    for sr in schema_rejects:
        srd = dict(sr)
        print(f"Agent={srd.get('agent_role')}, Reason={srd.get('rejection_reason')}")

    infra_errors = conn.execute("SELECT * FROM infra_errors").fetchall()
    print(f"\nInfra errors: {len(infra_errors)}")
    for ie in infra_errors:
        print(dict(ie))

    conn.close()

analyze("Cycle 19", r"C:\Users\Lenovo\AppData\Local\Temp\cycle19_run_1789929313.db")
analyze("Cycle 20", r"C:\Users\Lenovo\AppData\Local\Temp\cycle20_run_1790005719.db")
