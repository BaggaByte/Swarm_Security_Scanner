import sqlite3
import time
from pathlib import Path
import sys

# Ensure project root is in pythonpath
sys.path.insert(0, r'c:\Users\Lenovo\Documents\cycle10_swarm_harness\cycle11_ollama_swarm')

from run_cycle11 import run_cycle19_verdict_aggregation, print_cycle19_report
from agents.research_agents import _parse_cycle19_challenge

db_path = Path(r'C:\Users\Lenovo\AppData\Local\Temp\cycle19_run_1789929313.db')
conn = sqlite3.connect(str(db_path))
conn.row_factory = sqlite3.Row

# 1. Re-parse all challenges using updated _parse_cycle19_challenge
challenges = conn.execute('SELECT * FROM challenges').fetchall()
for ch in challenges:
    parsed = _parse_cycle19_challenge(ch['challenge_text'])
    conn.execute('''
        UPDATE challenges
        SET factual_validity = ?,
            attack_path = ?,
            security_property = ?,
            consequence = ?,
            severity_eval = ?,
            overall_verdict = ?,
            related_real_issue = ?,
            stated_claim_valid = ?,
            verdict = ?,
            raw_verdict = ?
        WHERE id = ?
    ''', (
        parsed['factual_validity'],
        parsed['attack_path'],
        parsed['security_property'],
        parsed['consequence'],
        parsed['severity_eval'],
        parsed['overall_verdict'],
        1 if parsed['related_real_issue'] else 0,
        1 if parsed['stated_claim_valid'] else 0,
        parsed['verdict'],
        parsed['raw_verdict'],
        ch['id']
    ))
conn.commit()
print("All challenges re-parsed with updated parser.")

# 2. Re-aggregate verdicts
counts = run_cycle19_verdict_aggregation(conn)
print(f"Aggregation counts: {counts}")

# 3. Print report and save JSON
result = print_cycle19_report(
    conn=conn,
    c19_counts=counts,
    start_time=time.time() - 40631.7,
    model="llama3.2:latest",
    target_file="target_app_cycle13.py",
    db_path=db_path,
    challenger_model="qwen2.5-coder:7b",
)

conn.close()
print("Cycle 19 final report complete!")
