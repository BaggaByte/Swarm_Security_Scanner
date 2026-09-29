"""
SARIF Parser for AI Security Triage Engine
==========================================
Ingests generic SARIF (Static Analysis Results Interchange Format) files
and normalises them into the unified SAST finding format.
"""

from __future__ import annotations

import json
import os
from typing import Optional
from urllib.parse import unquote, urlparse

from .sast_runner import _source_scope

def parse_sarif(file_path: str, repo_root: Optional[str] = None) -> list[dict]:
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
                parsed_uri = urlparse(file_path_str)
                if parsed_uri.scheme == "file":
                    local_path = unquote(parsed_uri.path)
                    if os.name == "nt" and len(local_path) > 2 and local_path[0] == "/" and local_path[2] == ":":
                        local_path = local_path[1:]
                    file_path_str = os.path.abspath(local_path)
                    if repo_root:
                        try:
                            file_path_str = os.path.relpath(file_path_str, repo_root).replace("\\", "/")
                        except ValueError:
                            pass
                else:
                    file_path_str = unquote(parsed_uri.path).replace("\\", "/").removeprefix("./")
                    if repo_root and os.path.isabs(file_path_str):
                        try:
                            file_path_str = os.path.relpath(file_path_str, repo_root).replace("\\", "/")
                        except ValueError:
                            pass
                
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
                "source_scope": _source_scope(file_path_str),
                "line": line,
                "col": col,
                "severity": severity,
                "confidence": "MEDIUM",
                "cwe": cwe,
                "message": message,
                "code": code_snippet,
            })

    return findings
