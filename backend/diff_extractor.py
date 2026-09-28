import subprocess
import tempfile
import os
import re

def extract_diff_from_pr(payload: dict):
    """
    Given a GitHub pull request webhook payload, clones the repo, 
    generates a diff, and parses it to find changed lines per file.
    """
    if payload.get("action") not in ("opened", "synchronize", "reopened"):
        return None
        
    pull_request = payload.get("pull_request")
    if not pull_request:
        return None
        
    clone_url = pull_request.get("head", {}).get("repo", {}).get("clone_url")
    head_branch = pull_request.get("head", {}).get("ref")
    base_branch = pull_request.get("base", {}).get("ref")
    
    if not (clone_url and head_branch and base_branch):
        return None
        
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Clone the head branch
            subprocess.run(["git", "clone", "--depth", "1", "--branch", head_branch, clone_url, tmpdir], check=True, capture_output=True)
            
            # Fetch the base branch
            subprocess.run(["git", "remote", "set-branches", "origin", base_branch], cwd=tmpdir, check=True, capture_output=True)
            subprocess.run(["git", "fetch", "--depth", "1", "origin", base_branch], cwd=tmpdir, check=True, capture_output=True)
            
            # Get the diff
            diff_proc = subprocess.run(["git", "diff", f"origin/{base_branch}...HEAD"], cwd=tmpdir, capture_output=True, text=True, check=True)
            diff_text = diff_proc.stdout
            
            return parse_unified_diff(diff_text)
        except subprocess.CalledProcessError as e:
            print(f"[Diff] Git error: {e.stderr.decode('utf-8')}")
            return None

def parse_unified_diff(diff_text: str):
    """
    Parses a unified diff into a dictionary mapping filenames to lists of changed line numbers.
    """
    changed_files = {}
    current_file = None
    
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            changed_files[current_file] = []
        elif line.startswith("@@ ") and current_file:
            # Match @@ -x,y +start,count @@
            match = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if match:
                start_line = int(match.group(1))
                count = int(match.group(2)) if match.group(2) else 1
                for i in range(count):
                    changed_files[current_file].append(start_line + i)
                    
    return changed_files
