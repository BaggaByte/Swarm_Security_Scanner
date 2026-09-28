"""
Cycle 17 grounded findings parser.
Imported by research_agents when cycle_key == '17'.
"""


def _parse_grounded_findings(text: str) -> list[dict]:
    """
    Parse Cycle 17 grounded LLM output.

    Cycle 17 FINDING block fields (ALL required):
      Title, Location, Imports_Deps, Attacker_Input, Data_Flow,
      Security_Property, Consequence, Mechanism_Evidence, Confidence, Severity

    Mapped to standard dict:
      hypothesis         <- Title
      location           <- Location
      imports_deps       <- Imports_Deps
      attacker_input     <- Attacker_Input
      path               <- Data_Flow
      property           <- Security_Property
      consequence        <- Consequence
      mechanism_evidence <- Mechanism_Evidence  (must be source quote)
      confidence         <- Confidence
      severity           <- Severity
    """
    findings = []
    current: dict = {}
    current_raw_lines: list[str] = []

    _GROUNDED_FIELD_KEYS = (
        "title:", "location:", "imports_deps:", "attacker_input:",
        "data_flow:", "security_property:", "consequence:",
        "mechanism_evidence:", "confidence:", "severity:", "---", "finding",
    )

    def _flush():
        if not current.get("hypothesis"):
            return
        loc  = current.get("location", "")
        path = current.get("path", "")
        prop = current.get("property", "")
        ai   = current.get("attacker_input", "")
        cons = current.get("consequence", "")
        mech = current.get("mechanism_evidence", "")
        imps = current.get("imports_deps", "")
        conf = current.get("confidence", "")
        parts = []
        if loc:  parts.append("Location: " + loc)
        if path: parts.append("Path: " + path)
        if prop: parts.append("Property: " + prop)
        if ai:   parts.append("AttackerInput: " + ai)
        if cons: parts.append("Consequence: " + cons)
        if mech: parts.append("MechanismEvidence: " + mech)
        if imps: parts.append("Imports: " + imps)
        if conf: parts.append("Confidence: " + conf)
        evidence = " | ".join(parts)
        findings.append({
            "hypothesis":         current["hypothesis"],
            "evidence":           evidence,
            "severity":           current.get("severity", "medium"),
            "location":           loc,
            "path":               path,
            "property":           prop,
            "attacker_input":     ai,
            "consequence":        cons,
            "mechanism_evidence": mech,
            "imports_deps":       imps,
            "confidence":         conf,
            "raw_text":           "\n".join(current_raw_lines).strip(),
        })

    _active_field = None

    for raw_line in text.splitlines():
        current_raw_lines.append(raw_line)
        line = raw_line.strip()
        cleaned = line.lstrip("#*- 0123456789.)").strip().replace("**", "").replace("__", "")
        cl = cleaned.lower()

        # Skip MECHANISM_ABSENT self-rejection markers
        if "mechanism_absent" in cl:
            _active_field = None
            continue

        if cl.startswith("finding:") or (cl.startswith("finding") and any(c in cl for c in [":", "1", "2", "3", "4", "5"])):
            _flush()
            current = {}
            current_raw_lines = [raw_line]
            _active_field = None
        elif cl.startswith("title:"):
            current["hypothesis"] = cleaned[6:].strip()
            _active_field = None
        elif cl.startswith("location:"):
            current["location"] = cleaned[9:].strip()
            _active_field = None
        elif cl.startswith("imports_deps:") or cl.startswith("imports deps:") or cl.startswith("imports/deps:"):
            idx = cleaned.find(":")
            current["imports_deps"] = cleaned[idx + 1:].strip()
            _active_field = "imports_deps"
        elif cl.startswith("attacker_input:") or cl.startswith("attacker input:") or cl.startswith("attackerinput:"):
            idx = cleaned.find(":")
            current["attacker_input"] = cleaned[idx + 1:].strip()
            _active_field = "attacker_input"
        elif cl.startswith("data_flow:") or cl.startswith("data flow:") or cl.startswith("dataflow:"):
            idx = cleaned.find(":")
            current["path"] = cleaned[idx + 1:].strip()
            _active_field = "path"
        elif cl.startswith("security_property:") or cl.startswith("security property:"):
            idx = cleaned.find(":")
            current["property"] = cleaned[idx + 1:].strip()
            _active_field = "property"
        elif cl.startswith("consequence:"):
            current["consequence"] = cleaned[12:].strip()
            _active_field = "consequence"
        elif cl.startswith("mechanism_evidence:") or cl.startswith("mechanism evidence:"):
            idx = cleaned.find(":")
            current["mechanism_evidence"] = cleaned[idx + 1:].strip()
            _active_field = "mechanism_evidence"
        elif cl.startswith("confidence:"):
            val = cleaned[11:].strip().upper()
            current["confidence"] = val if val in {"HIGH", "MEDIUM", "LOW"} else "LOW"
            _active_field = None
        elif cl.startswith("severity:"):
            sev = cleaned[9:].strip().lower()
            current["severity"] = sev if sev in {"critical", "high", "medium", "low"} else "medium"
            _active_field = None
        elif cleaned.startswith("---"):
            _active_field = None
        elif _active_field and cleaned and not any(cl.startswith(k) for k in _GROUNDED_FIELD_KEYS):
            current[_active_field] = current.get(_active_field, "") + " " + cleaned

    _flush()
    return findings
