import json
import glob
import os
from pathlib import Path
import sys

def get_latest_file(patterns):
    files = []
    for pattern in patterns:
        files.extend(glob.glob(pattern))
    if not files:
        return None
    return max(files, key=os.path.getctime)

def main():
    search_dirs = [
        Path(r"C:\Users\Lenovo\AppData\Local\Temp\results"),
        Path(__file__).parent.parent / "results",
    ]
    c21_patterns = [str(d / "cycle21_schema_gate_audit_*.json") for d in search_dirs]
    c22_patterns = [str(d / "cycle22_replication_*.json") for d in search_dirs]
    c21_file = get_latest_file(c21_patterns)
    c22_file = get_latest_file(c22_patterns)

    if not c21_file:
        print("Could not find Cycle 21 results.")
        sys.exit(1)
    if not c22_file:
        print("Could not find Cycle 22 results.")
        sys.exit(1)

    print(f"Loaded Cycle 21: {c21_file}")
    print(f"Loaded Cycle 22: {c22_file}")

    with open(c21_file, "r", encoding="utf-8") as f:
        c21_data = json.load(f)
    
    with open(c22_file, "r", encoding="utf-8") as f:
        c22_data = json.load(f)

    # Generate Markdown Report
    report_lines = []
    report_lines.append("# Cycle 22 Replication Report\n")
    report_lines.append("This report compares the decomposed-evaluator replication (Cycle 22) against the original findings (Cycle 21).\n")
    
    m21 = c21_data.get("decomposed_metrics", {})
    m22 = c22_data.get("decomposed_metrics", {})

    report_lines.append("## Comparison Metrics\n")
    report_lines.append("| Metric | Cycle 21 | Cycle 22 (Replication) | Delta |")
    report_lines.append("|---|---|---|---|")
    
    keys_to_compare = [
        "raw_llm_findings",
        "schema_gate_drops",
        "infra_errors",
        "factual_valid_findings",
        "attack_path_valid_findings",
        "security_property_valid_findings",
        "severity_disagreements",
        "confirmed_findings",
        "partial_findings",
        "overrejections",
        "correct_rejections",
        "false_positives",
        "planted_gt_discovered",
        "duplicate_rate"
    ]
    
    for k in keys_to_compare:
        v21 = m21.get(k, 0)
        v22 = m22.get(k, 0)
        delta = v22 - v21 if isinstance(v21, (int, float)) else "N/A"
        if isinstance(delta, float):
            delta = f"{delta:+.3f}"
        elif isinstance(delta, int):
            delta = f"{delta:+d}"
        
        name = k.replace("_", " ").title()
        report_lines.append(f"| {name} | {v21} | {v22} | {delta} |")

    report_lines.append("\n## Partial Validities\n")
    report_lines.append("Analysis of findings that preserved as PARTIAL rather than FULL_VALIDITY:\n")
    report_lines.append("| Finding ID | Agent | Hypothesis | Rejected Axes |")
    report_lines.append("|---|---|---|---|")
    
    for finding in c22_data.get("findings", []):
        if finding.get("decomposition_classification") == "PARTIAL_VALIDITY":
            # Determine which axis rejected it
            ch_a = finding.get("challenger_a", {}) or {}
            ch_b = finding.get("challenger_b", {}) or {}
            
            axes = ["factual_validity", "attack_path", "security_property", "consequence", "severity_eval"]
            rejected = []
            for axis in axes:
                # If either challenger says FALSE
                val_a = ch_a.get(axis, "")
                val_b = ch_b.get(axis, "")
                if str(val_a).upper() == "FALSE" or str(val_b).upper() == "FALSE":
                    rejected.append(axis)
            
            # severity doesn't prevent full validity in cycle19 logic if it's decoupled, but just to list it
            hyp = finding.get("claim", "")[:60]
            fid = finding.get("finding_id")
            agent = finding.get("agent_role")
            report_lines.append(f"| {fid} | {agent} | {hyp} | {', '.join(rejected)} |")
            
    report_lines.append("\n## Rejections\n")
    report_lines.append("Analysis of rejected findings:\n")
    report_lines.append("| Finding ID | Agent | Hypothesis | GT Match | Classification |")
    report_lines.append("|---|---|---|---|---|")
    for finding in c22_data.get("findings", []):
        cls = finding.get("decomposition_classification", "")
        if cls in ["CORRECT_REJECTION", "OVERREJECTION"]:
            hyp = finding.get("claim", "")[:60]
            fid = finding.get("finding_id")
            agent = finding.get("agent_role")
            gt_match = finding.get("corresponds_to_planted_issue")
            report_lines.append(f"| {fid} | {agent} | {hyp} | {gt_match} | {cls} |")

    report_text = "\n".join(report_lines)
    out_md = Path(r"C:\Users\Lenovo\Documents\cycle10_swarm_harness\cycle11_ollama_swarm\cycle22_replication_report.md")
    out_md.write_text(report_text, encoding="utf-8")
    
    print(f"\nSuccessfully generated {out_md}")
    
if __name__ == "__main__":
    main()
