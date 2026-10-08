#!/usr/bin/env python3
"""
Swarm Security Scanner — CI/CD Runner
=====================================
Integrates Swarm with GitHub Actions, GitLab CI, and custom build pipelines:
  • Triggers real-world repo scan via Swarm API
  • Polls run progress with timeout handling
  • Downloads standard OASIS SARIF report for GitHub Code Scanning tab
  • Emits GitHub Actions workflow annotations (::error, ::warning)
  • Enforces configurable build gate policies (fail on CRITICAL/HIGH)
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def _http_request(url: str, method: str = "GET", data: dict | None = None, api_key: str = "") -> dict | bytes:
    headers = {
        "User-Agent": "Swarm-CI-Runner/1.0",
        "Accept": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        headers["X-API-Key"] = api_key

    payload = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        payload = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read()
            content_type = resp.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return json.loads(content.decode("utf-8"))
            return content
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(f"::error::Swarm API HTTP {e.code} Error: {err_body}", file=sys.stderr)
        raise RuntimeError(f"Swarm API returned HTTP {e.code}: {err_body}") from e
    except urllib.error.URLError as e:
        print(f"::error::Failed to connect to Swarm API at {url}: {e.reason}", file=sys.stderr)
        raise RuntimeError(f"Connection failed: {e.reason}") from e


def main():
    api_url = os.getenv("SWARM_API_URL", "http://127.0.0.1:8000").rstrip("/")
    api_key = os.getenv("SWARM_API_KEY", "")
    fail_sev = os.getenv("SWARM_FAIL_SEVERITY", "CRITICAL").upper()
    sarif_out = os.getenv("SWARM_SARIF_OUTPUT", "swarm_results.sarif")
    model = os.getenv("SWARM_MODEL", "llama3.2")
    challenger_model = os.getenv("SWARM_CHALLENGER_MODEL", "qwen2.5-coder:7b")
    max_chunks = int(os.getenv("SWARM_MAX_CHUNKS", "0"))
    
    repo_target = os.getenv("GITHUB_REPOSITORY", "")
    if repo_target and not repo_target.startswith("http"):
        repo_target = f"https://github.com/{repo_target}.git"
    if not repo_target:
        repo_target = os.getcwd()

    print(f"🛡️ Initializing Swarm Security Scanner CI/CD Gate")
    print(f"   API Target:   {api_url}")
    print(f"   Repository:   {repo_target}")
    print(f"   Fail Policy:  {fail_sev}")
    print(f"   Model:        {model} (Challenger: {challenger_model})")

    # 1. Health check
    try:
        health_resp = _http_request(f"{api_url}/api/health")
        print(f"✅ Swarm API connection verified: {health_resp.get('message', 'OK')}")
    except Exception as e:
        print(f"::error::Swarm API is not reachable at {api_url}. Is the service running?", file=sys.stderr)
        sys.exit(1)

    # 2. Trigger scan
    scan_payload = {
        "repo": repo_target,
        "model": model,
        "challenger_model": challenger_model,
        "workers": 3,
        "challengers": 2,
        "max_chunks": max_chunks,
        "no_sast": False,
    }

    print("🚀 Triggering Swarm multi-agent scan...")
    try:
        start_resp = _http_request(f"{api_url}/api/repo-scan", method="POST", data=scan_payload, api_key=api_key)
        run_id = start_resp.get("run_id")
        print(f"📋 Scan job submitted successfully — Run ID: {run_id}")
    except Exception as e:
        print(f"::error::Failed to start Swarm scan: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Poll until done
    max_wait_seconds = 900  # 15 min timeout
    poll_interval = 5
    elapsed = 0
    scan_status = "running"
    
    print("⏳ Awaiting swarm consensus and adversarial triage...")
    while elapsed < max_wait_seconds:
        time.sleep(poll_interval)
        elapsed += poll_interval

        try:
            status_data = _http_request(f"{api_url}/api/scan/{run_id}", api_key=api_key)
            scan_status = status_data.get("status", "running")
            if scan_status in ("done", "partial", "error"):
                break
            if elapsed % 15 == 0:
                print(f"   ... still analyzing ({elapsed}s elapsed)")
        except Exception as e:
            print(f"⚠️ Polling error ({e}); retrying...")

    if scan_status not in ("done", "partial"):
        print(f"::error::Scan run {run_id} terminated with unexpected status: {scan_status}", file=sys.stderr)
        sys.exit(2)

    print(f"✨ Scan completed in {elapsed}s (Status: {scan_status})")

    # 4. Fetch and save SARIF report
    sarif_data = {}
    try:
        sarif_data = _http_request(f"{api_url}/api/export/sarif?run_id={run_id}", api_key=api_key)
        with open(sarif_out, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)
        print(f"📄 OASIS SARIF v2.1.0 report saved to {sarif_out}")
    except Exception as e:
        print(f"⚠️ Failed to retrieve SARIF report: {e}", file=sys.stderr)

    # 5. Parse findings and generate GitHub annotations
    findings = []
    try:
        all_findings = _http_request(f"{api_url}/api/findings", api_key=api_key)
        if isinstance(all_findings, list):
            findings = [f for f in all_findings if f.get("scanId") == run_id or not f.get("scanId")]
    except Exception:
        pass

    sev_hierarchy = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "NONE": -1}
    threshold = sev_hierarchy.get(fail_sev, 4)

    critical_count = 0
    high_count = 0
    failing_findings = []

    for f in findings:
        sev = str(f.get("severity", "MEDIUM")).upper()
        verdict = f.get("aiVerdict") or f.get("ai_verdict") or "TP"
        file_path = f.get("file", "unknown")
        line = f.get("line", 1)
        title = f.get("title", "Vulnerability")
        rationale = f.get("swarmRationale") or ""
        
        # Only annotate True Positives
        if verdict == "TP":
            if sev == "CRITICAL":
                critical_count += 1
            elif sev == "HIGH":
                high_count += 1

            sev_val = sev_hierarchy.get(sev, 0)
            if sev_val >= threshold and fail_sev != "NONE":
                failing_findings.append(f)
                # Output GitHub Action error annotation
                print(f"::error file={file_path},line={line},title=[{sev}] {title}::Swarm AI consensus TP: {rationale[:200]}")
            else:
                # Output GitHub Action warning annotation
                print(f"::warning file={file_path},line={line},title=[{sev}] {title}::Swarm AI finding: {rationale[:200]}")

    print("\n" + "=" * 60)
    print("📊 SWARM SECURITY SCAN SUMMARY")
    print(f"   Total TP Findings:  {len([f for f in findings if (f.get('aiVerdict') or f.get('ai_verdict')) == 'TP'])}")
    print(f"   Critical Findings:  {critical_count}")
    print(f"   High Findings:      {high_count}")
    print("=" * 60)

    # Output parameters for GitHub Actions
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"run_id={run_id}\n")
            f.write(f"findings_count={len(findings)}\n")
            f.write(f"critical_count={critical_count}\n")
            f.write(f"sarif_path={sarif_out}\n")

    if failing_findings:
        print(f"\n❌ BUILD FAILED: {len(failing_findings)} findings met or exceeded fail threshold ({fail_sev}).", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n✅ BUILD PASSED: No security policy violations found.")
        sys.exit(0)


if __name__ == "__main__":
    main()
