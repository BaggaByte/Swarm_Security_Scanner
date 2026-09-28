import json
from pathlib import Path

p19 = Path(r"C:\Users\Lenovo\AppData\Local\Temp\results\cycle19_evaluator_decomposition_1789970140.json")
p20 = Path(r"C:\Users\Lenovo\AppData\Local\Temp\results\cycle20_reproducibility_1790008924.json")

d19 = json.loads(p19.read_text(encoding="utf-8"))
d20 = json.loads(p20.read_text(encoding="utf-8"))

print("=== CYCLE 19 DECOMPOSED METRICS ===")
print(json.dumps(d19["decomposed_metrics"], indent=2))
print("Elapsed seconds C19:", d19.get("elapsed_seconds"))

print("\n=== CYCLE 20 DECOMPOSED METRICS ===")
print(json.dumps(d20["decomposed_metrics"], indent=2))
print("Elapsed seconds C20:", d20.get("elapsed_seconds"))

print("\n=== C19 FINDINGS ===")
for f in d19["findings"]:
    print(f"#{f['finding_id']} [{f['source']}] {f['agent_role']}: {f['original_claim_verdict']} | {f['underlying_assessment']} | {f['decomposition_classification']} | GT: {f['corresponds_to_planted_issue']} ({f['planted_ground_truth_id']})")
    print(f"   Claim: {f['claim']}")

print("\n=== C20 FINDINGS ===")
for f in d20["findings"]:
    print(f"#{f['finding_id']} [{f['source']}] {f['agent_role']}: {f['original_claim_verdict']} | {f['underlying_assessment']} | {f['decomposition_classification']} | GT: {f['corresponds_to_planted_issue']} ({f['planted_ground_truth_id']})")
    print(f"   Claim: {f['claim']}")

print("\n=== C20 SCHEMA REJECTS ===")
for sr in d20.get("schema_rejects", []):
    print(sr)

print("\n=== C20 DUPLICATES ===")
print(d20.get("duplicates", []))
