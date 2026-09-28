"""
SARIF Parser for AI Security Triage Engine
==========================================
Ingests generic SARIF (Static Analysis Results Interchange Format) files
and normalises them into the unified SAST finding format.
"""

from __future__ import annotations

import json
from typing import Optional

def parse_sarif(file_path: str) -> list[dict]:
    """
    Parse a SARIF file and return a list of unified findings.
    """
    findings = []
    
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"  [SARIF] Error parsing {file_path} as JSON.")
            return []

    runs = data.get("runs", [])
    for run in runs:
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "sarif_tool").lower()
        
        # Build rule dictionary to enrich findings
        rules = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rule_id = rule.get("id")
            if rule_id:
                rules[rule_id] = rule

        results = run.get("results", [])
        for result in results:
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")
            
            # Severity mapping (default: MEDIUM)
            level = result.get("level", "warning")
            severity = "MEDIUM"
            if level == "error":
                severity = "HIGH"
            elif level == "note":
                severity = "INFO"
            
            # Get location
            locations = result.get("locations", [])
            file_path_str = "unknown"
            line = 0
            col = 0
            code_snippet = ""
            
            if locations:
                physical_location = locations[0].get("physicalLocation", {})
                artifact_location = physical_location.get("artifactLocation", {})
                file_path_str = artifact_location.get("uri", "unknown")
                
                region = physical_location.get("region", {})
                line = region.get("startLine", 0)
                col = region.get("startColumn", 0)
                
                snippet = region.get("snippet", {})
                code_snippet = snippet.get("text", "")

            # Attempt to extract CWE from tags if available in rule definition
            cwe = None
            rule_info = rules.get(rule_id, {})
            tags = rule_info.get("properties", {}).get("tags", [])
            for tag in tags:
                if isinstance(tag, str) and tag.upper().startswith("CWE-"):
                    cwe = tag.upper()
                    break

            findings.append({
                "tool": tool_name,
                "rule_id": rule_id,
                "file": file_path_str,
                "line": line,
                "col": col,
                "severity": severity,
                "confidence": "MEDIUM",
                "cwe": cwe,
                "message": message,
                "code": code_snippet,
            })

    return findings
