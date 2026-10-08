"""
Swarm Security Scanner — Export & Scan Diff Module
==================================================
Sprint 1.3: Deliver structured exports (SARIF v2.1.0, CSV, JSON, HTML Audit Reports)
and multi-scan comparison/differential analysis.
"""

from __future__ import annotations

import csv
import io
import json
import time
from typing import Any, Dict, List, Optional


def export_to_sarif(findings: List[Dict[str, Any]], run_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Export findings to OASIS SARIF v2.1.0 format (compatible with GitHub Code Scanning,
    SonarQube, VS Code SARIF Viewer, and CI/CD pipelines).
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    sev_to_level = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none",
    }

    for f in findings:
        rule_id = f.get("ruleId") or f.get("rule_id") or f.get("cwe") or "SWARM-GENERIC"
        title = f.get("title") or "Security Finding"
        severity = str(f.get("severity", "MEDIUM")).upper()
        level = sev_to_level.get(severity, "warning")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": title[:64],
                "shortDescription": {"text": title},
                "fullDescription": {"text": f.get("description") or title},
                "help": {
                    "text": f.get("remediationSuggestion") or f.get("remediation_suggestion") or f.get("swarmRationale") or f.get("swarm_rationale") or "No remediation provided.",
                    "markdown": f"### Remediation\n{f.get('remediationSuggestion') or f.get('remediation_suggestion') or 'Review source code.'}\n\n**Swarm AI Rationale:**\n{f.get('swarmRationale') or f.get('swarm_rationale') or 'Consensus verdict.'}"
                },
                "properties": {
                    "problem.severity": level,
                    "security-severity": "9.0" if severity == "CRITICAL" else ("7.5" if severity == "HIGH" else ("5.0" if severity == "MEDIUM" else "2.5")),
                    "cwe": f.get("cwe", ""),
                    "owasp": f.get("owasp", ""),
                },
            }

        file_uri = str(f.get("file", "unknown")).replace("\\", "/").removeprefix("./")
        line_num = int(f.get("line") or 1)

        result_item = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"{title} — {f.get('description', '')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, line_num),
                            "startColumn": 1,
                        },
                    }
                }
            ],
            "properties": {
                "aiVerdict": f.get("aiVerdict") or f.get("ai_verdict") or "TP",
                "status": f.get("status", "new"),
                "tool": f.get("tool", "swarm"),
                "swarmRationale": f.get("swarmRationale") or f.get("swarm_rationale", ""),
            },
        }
        results.append(result_item)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Swarm Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/BaggaByte/Swarm_Security_Scanner",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                ],
                "results": results,
            }
        ],
    }
    return sarif_doc


def export_to_csv(findings: List[Dict[str, Any]]) -> str:
    """
    Export findings to RFC 4180 compliant CSV format.
    """
    output = io.StringIO()
    fieldnames = [
        "id", "repository", "file", "line", "title", "severity",
        "cwe", "owasp", "ai_verdict", "status", "tool", "rule_id",
        "remediation_suggestion", "first_detected"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for f in findings:
        writer.writerow({
            "id": f.get("id", ""),
            "repository": f.get("repository", ""),
            "file": f.get("file", ""),
            "line": f.get("line", 1),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "cwe": f.get("cwe", ""),
            "owasp": f.get("owasp", ""),
            "ai_verdict": f.get("aiVerdict") or f.get("ai_verdict", ""),
            "status": f.get("status", ""),
            "tool": f.get("tool", ""),
            "rule_id": f.get("ruleId") or f.get("rule_id", ""),
            "remediation_suggestion": (f.get("remediationSuggestion") or f.get("remediation_suggestion") or "").replace("\n", " "),
            "first_detected": f.get("firstDetected") or f.get("first_detected", ""),
        })

    return output.getvalue()


def export_to_html(findings: List[Dict[str, Any]], run_meta: Optional[Dict[str, Any]] = None) -> str:
    """
    Generate an executive & technical security audit HTML report.
    Self-contained with embedded CSS styling.
    """
    meta = run_meta or {}
    total = len(findings)
    crit = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
    high = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")
    med = sum(1 for f in findings if str(f.get("severity", "")).upper() == "MEDIUM")
    low = sum(1 for f in findings if str(f.get("severity", "")).upper() == "LOW")
    tps = sum(1 for f in findings if str(f.get("aiVerdict") or f.get("ai_verdict", "")).upper() == "TP")
    fps = sum(1 for f in findings if str(f.get("aiVerdict") or f.get("ai_verdict", "")).upper() == "FP")

    rows_html = []
    for f in findings:
        sev = str(f.get("severity", "MEDIUM")).upper()
        sev_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#84cc16",
            "INFO": "#94a3b8"
        }.get(sev, "#94a3b8")

        verdict = f.get("aiVerdict") or f.get("ai_verdict") or "TP"
        file_path = f.get("file", "unknown")
        line = f.get("line", 1)
        title = f.get("title", "Untitled Finding")
        cwe = f.get("cwe") or "-"
        rationale = f.get("swarmRationale") or f.get("swarm_rationale") or "-"
        remediation = f.get("remediationSuggestion") or f.get("remediation_suggestion") or "-"

        rows_html.append(f"""
        <tr class="finding-row">
            <td><span class="badge" style="background:{sev_color}22;color:{sev_color};border-color:{sev_color}66">{sev}</span></td>
            <td><strong>{title}</strong><br><small style="color:#64748b">CWE: {cwe}</small></td>
            <td><code>{file_path}:{line}</code></td>
            <td><span class="badge" style="background:#0284c722;color:#38bdf8;border-color:#0284c766">{verdict}</span></td>
            <td>
                <div style="font-size:12px;color:#94a3b8;margin-bottom:4px"><strong>Rationale:</strong> {rationale}</div>
                <div style="font-size:12px;color:#34d399"><strong>Remediation:</strong> {remediation}</div>
            </td>
        </tr>
        """)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Swarm Security Scanner — Security Audit Report</title>
<style>
  :root {{
    --bg: #0b0f19;
    --card: #111827;
    --border: #1f2937;
    --text: #f3f4f6;
    --muted: #9ca3af;
    --accent: #38bdf8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  body {{ background: var(--bg); color: var(--text); padding: 32px 24px; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 28px; }}
  .title {{ font-size: 28px; font-weight: 800; letter-spacing: -0.02em; background: linear-gradient(135deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  .subtitle {{ color: var(--muted); font-size: 14px; margin-top: 4px; }}
  .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .metric-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; text-align: center; }}
  .metric-val {{ font-size: 28px; font-weight: 800; font-family: monospace; }}
  .metric-lbl {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; font-size: 13px; }}
  th {{ background: #1e293b; color: var(--muted); text-align: left; padding: 12px 16px; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
  td {{ padding: 14px 16px; border-top: 1px solid var(--border); vertical-align: top; }}
  code {{ font-family: "JetBrains Mono", Consolas, monospace; font-size: 12px; color: #cbd5e1; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; border: 1px solid transparent; font-family: monospace; }}
  .footer {{ margin-top: 40px; text-align: center; color: #475569; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1 class="title">Swarm Security Scanner</h1>
      <div class="subtitle">Multi-Agent Consensus Security Audit Report &bull; Generated {time.strftime("%B %d, %Y at %H:%M UTC", time.gmtime())}</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:12px;color:var(--muted)">Target: <strong>{meta.get('repo', 'All Projects')}</strong></div>
      <div style="font-size:12px;color:var(--muted)">Run ID: <code>{meta.get('run_id', 'N/A')}</code></div>
    </div>
  </div>

  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-val" style="color:#f3f4f6">{total}</div>
      <div class="metric-lbl">Total Findings</div>
    </div>
    <div class="metric-card">
      <div class="metric-val" style="color:#ef4444">{crit}</div>
      <div class="metric-lbl">Critical</div>
    </div>
    <div class="metric-card">
      <div class="metric-val" style="color:#f97316">{high}</div>
      <div class="metric-lbl">High</div>
    </div>
    <div class="metric-card">
      <div class="metric-val" style="color:#eab308">{med}</div>
      <div class="metric-lbl">Medium</div>
    </div>
    <div class="metric-card">
      <div class="metric-val" style="color:#34d399">{tps}</div>
      <div class="metric-lbl">True Positives</div>
    </div>
    <div class="metric-card">
      <div class="metric-val" style="color:#94a3b8">{fps}</div>
      <div class="metric-lbl">False Positives (Filtered)</div>
    </div>
  </div>

  <h2 style="font-size:18px;margin-bottom:14px;font-weight:700">Detailed Findings ({total})</h2>
  <table>
    <thead>
      <tr>
        <th style="width:100px">Severity</th>
        <th style="width:240px">Finding & CWE</th>
        <th style="width:220px">Location</th>
        <th style="width:90px">Verdict</th>
        <th>Rationale & Remediation Guidance</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows_html) if rows_html else '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:32px">No security findings reported.</td></tr>'}
    </tbody>
  </table>

  <div class="footer">
    Generated by <strong>Swarm Security Scanner</strong> &bull; Multi-Agent Consensus SAST Triage Platform
  </div>
</div>
</body>
</html>"""
    return html


def diff_scans(run_a_findings: List[Dict[str, Any]], run_b_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compare two scan runs (e.g. Baseline vs Current) to calculate:
      - New (introduced) vulnerabilities
      - Fixed (resolved) vulnerabilities
      - Persistent (unchanged) vulnerabilities
    """
    def _make_key(f: Dict[str, Any]) -> str:
        file_p = str(f.get("file", "")).replace("\\", "/").removeprefix("./")
        line = str(f.get("line", 1))
        rule = str(f.get("ruleId") or f.get("rule_id") or f.get("cwe") or f.get("title") or "")
        return f"{file_p}::{line}::{rule}".lower()

    map_a = {_make_key(f): f for f in run_a_findings}
    map_b = {_make_key(f): f for f in run_b_findings}

    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())

    fixed_keys = keys_a - keys_b
    new_keys = keys_b - keys_a
    persistent_keys = keys_a & keys_b

    return {
        "summary": {
            "baseline_count": len(run_a_findings),
            "current_count": len(run_b_findings),
            "new_count": len(new_keys),
            "fixed_count": len(fixed_keys),
            "persistent_count": len(persistent_keys),
        },
        "new_findings": [map_b[k] for k in new_keys],
        "fixed_findings": [map_a[k] for k in fixed_keys],
        "persistent_findings": [map_b[k] for k in persistent_keys],
    }
