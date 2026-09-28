import json
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

with open(r'C:\Users\Lenovo\AppData\Local\Temp\results\cycle21_schema_gate_audit_1790028625.json', 'r', encoding='utf-8') as f:
    d = json.load(f)

print('Cycle:', d.get('cycle'))
print('Elapsed:', d.get('elapsed_seconds'))
print('\nDecomposed metrics:')
print(json.dumps(d.get('decomposed_metrics'), indent=2))

print('\nSchema audit summary:')
print(json.dumps(d.get('schema_audit_summary'), indent=2))

print('\nFindings:')
for f in d.get('findings', []):
    fid = f.get('finding_id')
    src = f.get('source')
    role = f.get('agent_role')
    claim_v = f.get('original_claim_verdict')
    decomp = f.get('decomposition_classification')
    gt = f.get('planted_ground_truth_id')
    claim = f.get('claim', '')[:60]
    print(f"#{fid:<2} [{src:<16}] {role:<22}: {claim_v:<19} | {decomp:<16} | GT: {str(gt):<20} | Claim: {claim}")

print('\nSchema audit records count:', len(d.get('schema_audit_records', [])))
for a in d.get('schema_audit_records', []):
    role = a.get('agent_role')
    status = a.get('schema_status')
    hyp = a.get('hypothesis', '')[:50]
    r_class = a.get('rescue_classification')
    corr = a.get('gt_correspondence')
    path = a.get('path_field', '')[:40]
    print(f"Role: {role:<22} | Status: {status:<10} | Class: {r_class:<32} | Corr: {corr:<22} | Path: {path}")

print('\nSchema rejects count:', len(d.get('schema_rejects', [])))
print('Infra errors:', d.get('infra_errors'))
