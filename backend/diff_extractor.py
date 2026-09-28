import logging
import os
import re
import subprocess
import tempfile
from backend.security import validate_remote_git_url

logger = logging.getLogger("diff_extractor")

def extract_diff_from_pr(payload: dict):
    """
    Given a GitHub pull request webhook payload, clones the repo, 
    generates a diff, and parses it to find changed lines per file.
    Robustly handles merge bases, shallow clones, and divergent histories.
    """
    if payload.get("action") not in ("opened", "synchronize", "reopened"):
        return None
        
    pull_request = payload.get("pull_request")
    if not pull_request:
        return None
        
    clone_url = pull_request.get("head", {}).get("repo", {}).get("clone_url")
    head_branch = pull_request.get("head", {}).get("ref")
    base_clone_url = pull_request.get("base", {}).get("repo", {}).get("clone_url")
    base_branch = pull_request.get("base", {}).get("ref")
    
    if not (clone_url and head_branch and base_clone_url and base_branch):
        return None

    # Validate clone URLs against SSRF before invoking git
    try:
        validate_remote_git_url(clone_url)
        validate_remote_git_url(base_clone_url)
    except Exception as e:
        logger.warning(f"[Diff] Security rejection for PR clone URL: {e}")
        return None
        
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Clone head branch (full history to preserve merge base context)
            subprocess.run(
                ["git", "clone", "--branch", head_branch, clone_url, tmpdir],
                check=True,
                capture_output=True,
                text=True
            )
            
            # Fetch the base branch from the base repository
            subprocess.run(
                ["git", "remote", "add", "base", base_clone_url],
                cwd=tmpdir,
                check=True,
                capture_output=True,
                text=True
            )
            subprocess.run(
                ["git", "fetch", "base", base_branch],
                cwd=tmpdir,
                check=True,
                capture_output=True,
                text=True
            )
            
            # Check if repository is shallow; if so, unshallow to find common merge base
            is_shallow_proc = subprocess.run(
                ["git", "rev-parse", "--is-shallow-repository"],
                cwd=tmpdir,
                capture_output=True,
                text=True
            )
            if is_shallow_proc.stdout.strip() == "true":
                subprocess.run(["git", "fetch", "--unshallow"], cwd=tmpdir, capture_output=True)
                subprocess.run(["git", "fetch", "base", base_branch, "--unshallow"], cwd=tmpdir, capture_output=True)

            # Determine merge base between base and HEAD
            mb_proc = subprocess.run(
                ["git", "merge-base", f"base/{base_branch}", "HEAD"],
                cwd=tmpdir,
                capture_output=True,
                text=True
            )
            
            diff_text = ""
            if mb_proc.returncode == 0 and mb_proc.stdout.strip():
                merge_base = mb_proc.stdout.strip()
                # Three-dot comparison from merge base to HEAD
                diff_proc = subprocess.run(
                    ["git", "diff", f"{merge_base}...HEAD"],
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    check=True
                )
                diff_text = diff_proc.stdout
            else:
                # Fallback: direct two-dot diff comparing base branch tree against HEAD
                logger.info(f"[Diff] No merge base found between base/{base_branch} and HEAD; falling back to direct diff.")
                diff_proc = subprocess.run(
                    ["git", "diff", f"base/{base_branch}", "HEAD"],
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    check=True
                )
                diff_text = diff_proc.stdout
            
            return parse_unified_diff(diff_text)
        except subprocess.CalledProcessError as e:
            err = e.stderr if isinstance(e.stderr, str) else (e.stderr.decode('utf-8', errors='replace') if e.stderr else str(e))
            logger.error(f"[Diff] Git error: {err}")
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
                    
    for k in changed_files:
        changed_files[k] = sorted(list(set(changed_files[k])))
        
    return changed_files

