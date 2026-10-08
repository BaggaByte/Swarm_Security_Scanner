from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cycle11_ollama_swarm"))
from agents.redaction import redact_sensitive_content  # noqa: E402
from backend.git_url_policy import validate_git_url  # noqa: E402

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
SCANNER = Path(__file__).with_name("run_real_world.py")


class ManifestError(ValueError):
    pass


def _safe_repo_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{field} must be a non-empty relative path")
    path = value.replace("\\", "/")
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path) or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ManifestError(f"{field} must be a normalized relative path")
    return path


def load_manifest(path: Path) -> list[dict[str, Any]]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"Cannot read manifest {path}: {exc}") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("cases"), list):
        raise ManifestError("Manifest must be a JSON object containing a 'cases' array")

    cases = []
    seen_ids = set()
    for index, case in enumerate(manifest["cases"]):
        prefix = f"cases[{index}]"
        if not isinstance(case, dict):
            raise ManifestError(f"{prefix} must be an object")
        cve_id = case.get("cve_id")
        if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
            raise ManifestError(f"{prefix}.cve_id must be a CVE identifier")
        cve_id = cve_id.upper()
        if cve_id in seen_ids:
            raise ManifestError(f"Duplicate CVE case: {cve_id}")
        seen_ids.add(cve_id)

        repo_url_value = case.get("repo_url")
        if not isinstance(repo_url_value, str):
            raise ManifestError(f"{prefix}.repo_url must be a string")
        try:
            repo_url = validate_git_url(repo_url_value)
        except ValueError as exc:
            raise ManifestError(f"{prefix}.repo_url is invalid: {exc}") from exc

        vulnerable_ref = case.get("vulnerable_ref")
        patched_ref = case.get("patched_ref")
        if not isinstance(vulnerable_ref, str) or not SHA_RE.fullmatch(vulnerable_ref):
            raise ManifestError(f"{prefix}.vulnerable_ref must be a 40- or 64-character commit SHA")
        if not isinstance(patched_ref, str) or not SHA_RE.fullmatch(patched_ref):
            raise ManifestError(f"{prefix}.patched_ref must be a 40- or 64-character commit SHA")

        expected_file = _safe_repo_path(case.get("expected_file"), f"{prefix}.expected_file")
        cwe = case.get("cwe")
        if cwe is not None and (not isinstance(cwe, str) or not re.fullmatch(r"CWE-\d+", cwe, re.IGNORECASE)):
            raise ManifestError(f"{prefix}.cwe must be a CWE identifier such as CWE-89")
        keywords = case.get("match_keywords", [])
        if not isinstance(keywords, list) or any(not isinstance(item, str) or not item.strip() for item in keywords):
            raise ManifestError(f"{prefix}.match_keywords must be an array of non-empty strings")
        if not cwe and not keywords:
            raise ManifestError(f"{prefix} must define cwe or at least one match_keyword")

        line = case.get("line")
        line_tolerance = case.get("line_tolerance", 20)
        discovery_lines = case.get("discovery_lines")
        if discovery_lines is not None and (
            not isinstance(discovery_lines, list)
            or not discovery_lines
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 1 for item in discovery_lines)
        ):
            raise ManifestError(f"{prefix}.discovery_lines must be a non-empty array of positive line numbers")
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
            raise ManifestError(f"{prefix}.line must be a positive integer")
        if not isinstance(line_tolerance, int) or isinstance(line_tolerance, bool) or line_tolerance < 0:
            raise ManifestError(f"{prefix}.line_tolerance must be a non-negative integer")

        severity = case.get("severity")
        if severity is not None:
            if not isinstance(severity, str) or severity.upper() not in SEVERITIES:
                raise ManifestError(f"{prefix}.severity must be one of {', '.join(sorted(SEVERITIES))}")

        cases.append({
            **case,
            "cve_id": cve_id,
            "repo_url": repo_url,
            "vulnerable_ref": vulnerable_ref.lower(),
            "patched_ref": patched_ref.lower(),
            "expected_file": expected_file,
            "cwe": cwe.upper() if cwe else None,
            "match_keywords": [item.strip().lower() for item in keywords],
            "line": line,
            "line_tolerance": line_tolerance,
            "discovery_lines": discovery_lines,
            "severity": severity.upper() if severity else None,
        })
    if not cases:
        raise ManifestError("Manifest contains no CVE cases")
    return cases


def _run_git(args: list[str], *, cwd: Path | None = None, timeout: int = 300) -> None:
    env = os.environ.copy()
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ALLOW_PROTOCOL": "https",
    })
    for key in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_EXEC_PATH",
        "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_CONFIG_PARAMETERS",
    ):
        env.pop(key, None)
    for key in list(env):
        if key.startswith(("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            env.pop(key, None)
    result = subprocess.run(
        ["git", "-c", "http.followRedirects=false", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "no diagnostic output").strip()
        raise RuntimeError(f"git {' '.join(args[:3])} failed: {detail[:1200]}")


def _prepare_checkout(repo_url: str, commit: str, checkout: Path, *, clone: bool) -> None:
    if clone:
        _run_git(["clone", "--filter=blob:none", "--no-checkout", repo_url, str(checkout)])
    _run_git(["fetch", "--no-tags", "--depth=1", "origin", commit], cwd=checkout)
    _run_git(["checkout", "--detach", "--force", commit], cwd=checkout)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def _scan_snapshot(
    case: dict[str, Any],
    label: str,
    commit: str,
    checkout: Path,
    output_root: Path,
    args: argparse.Namespace,
) -> dict[str, Any]:
    snapshot_output = output_root / f"{case['cve_id']}-{label.lower()}"
    snapshot_output.mkdir(parents=True, exist_ok=True)
    log_path = snapshot_output / "scanner.log"
    target_file = checkout / Path(case["expected_file"])
    if target_file.is_symlink() or not target_file.is_file():
        raise RuntimeError(f"Expected vulnerable source file is missing or is a symlink: {case['expected_file']}")
    resolved_checkout = checkout.resolve()
    resolved_target = target_file.resolve(strict=True)
    if os.path.commonpath((str(resolved_checkout), str(resolved_target))) != str(resolved_checkout):
        raise RuntimeError(f"Expected source file resolves outside the checkout: {case['expected_file']}")
    source_line_count = max(1, len(target_file.read_text(encoding="utf-8", errors="replace").splitlines()))
    discovery_lines = case.get("discovery_lines")
    if discovery_lines:
        context = 10
        scoped_lines = sorted({
            line
            for target in discovery_lines
            for line in range(max(1, target - context), min(source_line_count, target + context) + 1)
        })
    else:
        scoped_lines = list(range(1, source_line_count + 1))
    scoped_diff = json.dumps({case["expected_file"]: scoped_lines})

    command = [
        sys.executable, "-u", str(SCANNER),
        "--repo", str(checkout),
        "--diff-json", scoped_diff,
        "--model", args.model,
        "--challenger-model", args.challenger_model,
        "--workers", str(args.workers),
        "--challengers", str(args.challengers),
        "--max-chunks", str(args.max_chunks),
        "--output-dir", str(snapshot_output),
        "--url", args.url,
    ]
    if args.no_sast:
        command.append("--no-sast")
    else:
        command.extend(["--sast", *args.sast])

    started = time.monotonic()
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            if process.stdout is not None:
                for line in iter(process.stdout.readline, ""):
                    log.write(redact_sensitive_content(line))
                    log.flush()
            return_code = process.wait()
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait()
            if process.stdout is not None:
                process.stdout.close()
    elapsed = round(time.monotonic() - started, 3)
    if return_code != 0:
        raise RuntimeError(f"Scanner exited {return_code}; see {log_path}")

    metadata_candidates = sorted(snapshot_output.glob("real_world_*_scan_metadata.json"))
    findings_candidates = sorted(snapshot_output.glob("real_world_*_findings.json"))
    if not metadata_candidates or not findings_candidates:
        raise RuntimeError(f"Scanner did not produce scan metadata/findings; see {log_path}")
    metadata = json.loads(metadata_candidates[-1].read_text(encoding="utf-8"))
    findings = json.loads(findings_candidates[-1].read_text(encoding="utf-8"))
    discovery = metadata.get("discovery", {})
    sast_triage = metadata.get("sast_triage", {})
    sast_statuses = metadata.get("sast_status", {})
    discovery_complete = bool(discovery.get("coverage_complete") and not discovery.get("failed_chunks", 0))
    sast_triage_complete = bool(sast_triage.get("coverage_complete", True))
    swarm_status = (
        "complete"
        if discovery_complete and sast_triage_complete
        else "partial"
    )
    sast_status = (
        "complete"
        if sast_statuses and all(item.get("status") == "complete" for item in sast_statuses.values())
        else "partial"
    )
    return {
        "snapshot": label,
        "commit": commit,
        "status": metadata.get("status", "unknown"),
        "swarm_status": swarm_status,
        "sast_status": sast_status,
        "discovery_coverage": discovery,
        "sast_triage_coverage": sast_triage,
        "sast_tool_status": sast_statuses,
        "partial_reasons": metadata.get("partial_reasons", []),
        "duration_seconds": elapsed,
        "log_file": str(log_path),
        "metadata_file": str(metadata_candidates[-1]),
        "findings_file": str(findings_candidates[-1]),
        "findings": findings,
    }


def _normalize_path(path: Any) -> str:
    return str(path or "").replace("\\", "/").strip("./").casefold()


def _finding_matches(case: dict[str, Any], finding: dict[str, Any]) -> bool:
    expected = _normalize_path(case["expected_file"])
    actual = _normalize_path(finding.get("file") or finding.get("file_path"))
    if not actual or not (actual == expected or actual.endswith("/" + expected)):
        return False

    if case.get("line") is not None:
        try:
            line = int(finding.get("line") or finding.get("line_number") or 0)
            tolerance = int(case.get("line_tolerance", 20))
        except (TypeError, ValueError):
            return False
        if line <= 0 or abs(line - int(case["line"])) > tolerance:
            return False

    text_parts = []
    for key in ("cwe", "hypothesis", "evidence", "content", "message", "description", "title", "rationale"):
        value = finding.get(key)
        if isinstance(value, list):
            text_parts.extend(str(item) for item in value)
        elif value is not None:
            text_parts.append(str(value))
    searchable = " ".join(text_parts).casefold()

    cwe_matches = bool(case.get("cwe") and case["cwe"].casefold() in searchable)
    keyword_matches = any(keyword in searchable for keyword in case["match_keywords"])
    return cwe_matches or keyword_matches


def _evidence_summary(finding: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "file", "file_path", "line", "line_number", "severity", "cwe",
        "tool", "rule_id", "title", "hypothesis", "evidence", "description",
        "message", "rationale", "verdict",
    )
    summary = {}
    for key in keys:
        value = finding.get(key)
        if isinstance(value, str):
            summary[key] = redact_sensitive_content(value[:500])
        elif isinstance(value, (int, float, bool)) or value is None:
            if key in finding:
                summary[key] = value
        elif isinstance(value, list):
            summary[key] = [redact_sensitive_content(str(item)[:250]) for item in value[:10]]
    return summary


def _matching_findings(case: dict[str, Any], findings: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    sast = [
        item for item in findings.get("sast", [])
        if isinstance(item, dict) and _finding_matches(case, item)
    ]
    swarm = [
        item.get("finding", {})
        for item in findings.get("triage", [])
        if isinstance(item, dict)
        and item.get("verdict") == "TP"
        and isinstance(item.get("finding"), dict)
        and _finding_matches(case, item["finding"])
    ]
    swarm.extend(
        item for item in findings.get("confirmed_discoveries", [])
        if isinstance(item, dict) and _finding_matches(case, item)
    )
    return {"sast": sast, "swarm": swarm}


def _severity_is_accurate(expected: str | None, matches: list[dict[str, Any]]) -> bool | None:
    if not expected or not matches:
        return None
    expected_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    observed = []
    for item in matches:
        severity = str(item.get("severity", "")).upper()
        if severity in expected_rank:
            observed.append(severity)
    if not observed:
        return False
    return any(severity == expected for severity in observed)


def _score_case(case_result: dict[str, Any]) -> dict[str, Any]:
    vulnerable = case_result.get("vulnerable", {})
    patched = case_result.get("patched", {})
    pre_matches = vulnerable.get("matches", {})
    post_matches = patched.get("matches", {})
    vulnerable_swarm_complete = vulnerable.get("swarm_status") == "complete"
    patched_swarm_complete = patched.get("swarm_status") == "complete"
    vulnerable_sast_complete = vulnerable.get("sast_status") == "complete"
    patched_sast_complete = patched.get("sast_status") == "complete"
    tp = bool(pre_matches.get("swarm"))
    fp = bool(post_matches.get("swarm"))
    tp_sast = bool(pre_matches.get("sast"))
    fp_sast = bool(post_matches.get("sast"))
    return {
        "cve_id": case_result["cve_id"],
        "vulnerable_scan_status": vulnerable.get("status", "error"),
        "patched_scan_status": patched.get("status", "error"),
        "vulnerable_swarm_status": vulnerable.get("swarm_status", "unavailable"),
        "patched_swarm_status": patched.get("swarm_status", "unavailable"),
        "vulnerable_sast_status": vulnerable.get("sast_status", "unavailable"),
        "patched_sast_status": patched.get("sast_status", "unavailable"),
        "swarm_true_positive": tp if vulnerable_swarm_complete else None,
        "swarm_false_positive_after_patch": fp if patched_swarm_complete else None,
        "sast_detected_vulnerable": tp_sast if vulnerable_sast_complete else None,
        "sast_still_flags_after_patch": fp_sast if patched_sast_complete else None,
        "severity_correct": (
            _severity_is_accurate(case_result.get("severity"), pre_matches.get("swarm", []))
            if vulnerable_swarm_complete else None
        ),
    }


def summarize(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [_score_case(item) for item in case_results]
    positive = [item for item in scored if item["vulnerable_swarm_status"] == "complete"]
    negative = [item for item in scored if item["patched_swarm_status"] == "complete"]
    tp = sum(item["swarm_true_positive"] is True for item in positive)
    fn = sum(item["swarm_true_positive"] is False for item in positive)
    fp = sum(item["swarm_false_positive_after_patch"] is True for item in negative)
    tn = sum(item["swarm_false_positive_after_patch"] is False for item in negative)
    severity_cases = [item for item in positive if item["severity_correct"] is not None]
    severity_correct = sum(item["severity_correct"] is True for item in severity_cases)
    sast_positive = [item for item in scored if item["vulnerable_sast_status"] == "complete"]
    sast_negative = [item for item in scored if item["patched_sast_status"] == "complete"]
    sast_tp = sum(item["sast_detected_vulnerable"] is True for item in sast_positive)
    sast_fp = sum(item["sast_still_flags_after_patch"] is True for item in sast_negative)
    return {
        "cases": len(case_results),
        "complete_vulnerable_swarm_scans": len(positive),
        "complete_patched_swarm_scans": len(negative),
        "complete_vulnerable_sast_scans": len(sast_positive),
        "complete_patched_sast_scans": len(sast_negative),
        "incomplete_or_failed_swarm_scans": 2 * len(case_results) - len(positive) - len(negative),
        "swarm": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
            "f1": round(2 * tp / (2 * tp + fp + fn), 4) if 2 * tp + fp + fn else None,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
            "severity_accuracy": round(severity_correct / len(severity_cases), 4) if severity_cases else None,
            "severity_cases": len(severity_cases),
        },
        "sast_baseline": {
            "vulnerable_snapshots_detected": sast_tp,
            "patched_snapshots_still_flagged": sast_fp,
            "incomplete_snapshots": 2 * len(case_results) - len(sast_positive) - len(sast_negative),
        },
        "per_case": scored,
    }


def run(args: argparse.Namespace) -> int:
    cases = load_manifest(Path(args.manifest))
    output_root = Path(args.output_dir).resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    allowed_root = os.environ.get("SWARM_ALLOWED_SCAN_ROOT")
    if allowed_root:
        temp_parent = Path(allowed_root).expanduser().resolve()
        if not temp_parent.is_dir():
            raise ManifestError("SWARM_ALLOWED_SCAN_ROOT must exist and be a directory for benchmark checkouts")
    else:
        temp_parent = Path(tempfile.gettempdir())

    report: dict[str, Any] = {
        "schema_version": 1,
        "started_at": time.time(),
        "manifest": str(Path(args.manifest).resolve()),
        "model": args.model,
        "challenger_model": args.challenger_model,
        "cases": [],
    }
    report_path = output_root / "cve_benchmark_report.json"
    for case in cases:
        case_result: dict[str, Any] = {
            "cve_id": case["cve_id"],
            "project": case.get("project"),
            "severity": case.get("severity"),
            "error": None,
        }
        print(f"[BENCHMARK] {case['cve_id']} — vulnerable and patched snapshots", flush=True)
        try:
            with tempfile.TemporaryDirectory(prefix="swarm-cve-", dir=temp_parent) as work:
                checkout = Path(work) / "repo"
                for label, key in (("vulnerable", "vulnerable_ref"), ("patched", "patched_ref")):
                    commit = case[key]
                    try:
                        _prepare_checkout(case["repo_url"], commit, checkout, clone=(label == "vulnerable"))
                        snapshot = _scan_snapshot(case, label, commit, checkout, output_root, args)
                        raw_findings = snapshot.pop("findings")
                        matches = _matching_findings(case, raw_findings)
                        snapshot["matches"] = {
                            source: [_evidence_summary(item) for item in items]
                            for source, items in matches.items()
                        }
                        case_result[label] = snapshot
                    except Exception as exc:
                        case_result[label] = {"status": "error", "error": str(exc)}
                        case_result["error"] = f"{label} snapshot failed: {exc}"
                        break
        except Exception as exc:
            case_result["error"] = str(exc)

        report["cases"].append(case_result)
        report["summary"] = summarize(report["cases"])
        report["updated_at"] = time.time()
        _write_json(report_path, report)
        print(f"[BENCHMARK] Saved progress to {report_path}", flush=True)

    report["finished_at"] = time.time()
    report["summary"] = summarize(report["cases"])
    _write_json(report_path, report)
    return 1 if any(item.get("error") for item in report["cases"]) else 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run paired pre/post-patch CVE benchmark scans")
    parser.add_argument("--manifest", required=True, help="JSON file with curated CVE cases")
    parser.add_argument("--output-dir", default="results/cve_benchmark", help="Where reports and scan evidence are written")
    parser.add_argument("--model", default="llama3.2")
    parser.add_argument("--challenger-model", default="qwen2.5-coder:7b")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--challengers", type=int, default=2)
    parser.add_argument("--max-chunks", type=int, default=0)
    parser.add_argument("--url", default=os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"))
    parser.add_argument("--sast", nargs="*", default=["bandit", "semgrep"])
    parser.add_argument("--no-sast", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.workers <= 3:
        parser.error("--workers must be between 1 and 3")
    if not 1 <= args.challengers <= 2:
        parser.error("--challengers must be 1 or 2")
    if args.max_chunks < 0:
        parser.error("--max-chunks must be zero or greater")
    try:
        raise SystemExit(run(args))
    except ManifestError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
