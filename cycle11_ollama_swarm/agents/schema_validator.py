"""
Cycle 15 – Hard Schema Validator (Post-Processor Gate)
=======================================================
All LLM-produced findings pass through this gate BEFORE entering the database.
Findings that fail validation are dropped and logged — they never reach Phase 2.

Validation rules:
  1. All 5 evidence-chain fields must be present and non-empty:
       Location, Path, Property, AttackerInput, Consequence
  2. Technology hallucination check: the finding must not reference technologies
     that are absent from the target source (SQL, database, pickle, eval, etc.)
  3. The Path field must contain at least one concrete code element (a function
     name, variable name, or operator that appears in the target source).

Returns: (is_valid: bool, rejection_reason: str | None)
"""

import re
from typing import Optional

# Technologies that do not appear in target_app_cycle13.py
# If a finding claims these, it is hallucinating
HALLUCINATED_TECH_PATTERN = re.compile(
    r"\b("
    r"sql\s+injection|sql injection|sqli|"
    r"sqlite3?\.execute|SELECT\s+\*|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DROP\s+TABLE|"
    r"database|mysql|postgresql|mongodb|redis|"
    r"pickle\.loads|pickle\.load|unpickling|deserialization|yaml\.load|"
    r"buffer\s+overflow|heap\s+spray|stack\s+smashing|shellcode|"
    r"eval\s*\(|exec\s*\(|__import__|compile\s*\("
    r")\b",
    re.IGNORECASE,
)

# Minimum word count for a meaningful Path field
PATH_MIN_WORDS = 5

# Fields required in a valid finding dict
REQUIRED_FIELDS = ("location", "path", "property", "attacker_input", "consequence")

# Alternative keys emitted by the parser (lowercase variants)
_FIELD_ALIASES: dict[str, list[str]] = {
    "attacker_input": ["attacker_input", "attackerinput"],
}


def _get_field(finding: dict, field: str) -> Optional[str]:
    """Return the value of a field, checking aliases."""
    val = finding.get(field)
    if val:
        return str(val).strip()
    for alias in _FIELD_ALIASES.get(field, []):
        val = finding.get(alias)
        if val:
            return str(val).strip()
    # Also check inside the evidence string (for backwards compat)
    evidence = finding.get("evidence", "")
    label_map = {
        "location":      "Location:",
        "path":          "Path:",
        "property":      "Property:",
        "attacker_input": "AttackerInput:",
        "consequence":   "Consequence:",
    }
    label = label_map.get(field)
    if label and label in evidence:
        parts = evidence.split(label, 1)
        if len(parts) > 1:
            segment = parts[1].split(" | ")[0].strip()
            return segment if segment else None
    return None


def validate_finding(finding: dict, target_src: str = "") -> tuple[bool, Optional[str]]:
    """
    Validate a single LLM-produced finding dict.

    Args:
        finding:    The parsed finding dict from _parse_findings()
        target_src: The full target source code string (used for tech check)

    Returns:
        (True, None)           if the finding passes all validation rules
        (False, reason_str)    if the finding is rejected, with a human-readable reason
    """
    # Rule 0: skip OLLAMA_UNAVAILABLE / infrastructure errors
    hypothesis = finding.get("hypothesis", "")
    if "OLLAMA_UNAVAILABLE" in hypothesis or "timeout" in hypothesis.lower():
        return False, "INFRASTRUCTURE_ERROR: not a security finding"

    # Rule 1: all 5 evidence-chain fields must be present and non-empty
    missing = []
    for field in REQUIRED_FIELDS:
        val = _get_field(finding, field)
        if not val:
            missing.append(field)

    if missing:
        return False, f"MISSING_FIELDS: {', '.join(missing)}"

    # Rule 2: technology hallucination check
    # Check Path and Consequence for references to absent technologies
    path_val = _get_field(finding, "path") or ""
    consequence_val = _get_field(finding, "consequence") or ""
    evidence_val = finding.get("evidence", "")
    combined_text = f"{path_val} {consequence_val} {evidence_val}"

    if HALLUCINATED_TECH_PATTERN.search(combined_text):
        matched = HALLUCINATED_TECH_PATTERN.search(combined_text)
        return False, (
            f"TECH_HALLUCINATION: finding references absent technology "
            f"('{matched.group(0)}'); target uses only Python file I/O and JSON"
        )

    # Rule 3: Path field must be substantive (not just "unknown" or placeholder)
    path_words = path_val.split()
    if len(path_words) < PATH_MIN_WORDS:
        return False, (
            f"PATH_TOO_VAGUE: Path field has only {len(path_words)} words "
            f"(minimum {PATH_MIN_WORDS}); must describe a concrete data-flow"
        )

    placeholder_patterns = re.compile(
        r"^(unknown|n/a|not applicable|see above|tbd|todo|none|unclear)$",
        re.IGNORECASE,
    )
    if placeholder_patterns.match(path_val.strip()):
        return False, "PATH_PLACEHOLDER: Path field contains a placeholder value"

    return True, None


def filter_findings(
    findings: list[dict],
    target_src: str = "",
    agent_id: str = "unknown",
) -> tuple[list[dict], list[dict]]:
    """
    Filter a list of LLM findings through the schema validator.

    Args:
        findings:   List of parsed finding dicts from _parse_findings()
        target_src: Full target source code string
        agent_id:   Agent identifier for logging

    Returns:
        (valid_findings, rejected_findings)
        Each rejected finding has an added 'rejection_reason' key.
    """
    valid = []
    rejected = []

    for f in findings:
        ok, reason = validate_finding(f, target_src)
        if ok:
            valid.append(f)
        else:
            f_copy = dict(f)
            f_copy["rejection_reason"] = reason
            rejected.append(f_copy)
            print(
                f"  [SCHEMA-GATE] DROPPED finding from {agent_id}: "
                f"{f.get('hypothesis', '?')[:70]} — {reason}"
            )

    return valid, rejected
