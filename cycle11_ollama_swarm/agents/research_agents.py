"""
Cycle 15/16/17 – Evidence-First Research Agents (Hardened)
===========================================================
Cycle 15/16: evidence-first schema gate + SQL/path hallucination guard
Cycle 17:    adds mandatory GROUNDING PREAMBLE before any finding:
             1. Identify relevant file/function
             2. List actual imports/dependencies used
             3. Identify attacker-controlled input
             4. Trace actual code path
             5. Identify security property violated
             6. State concrete consequence
             7. Verify mechanism exists in source
             8. Self-reject if any required mechanism is absent
             New output fields: MECHANISM_EVIDENCE, IMPORTS_DEPS, CONFIDENCE

Cycle 17 HARD RULE:
  Never infer SQL injection, command injection, path traversal, network exploitation,
  authentication bypass, etc. merely because the pattern is commonly associated with
  the vulnerability category. The claimed mechanism must be demonstrable from the source.
"""
import textwrap
import time
from dataclasses import dataclass

from .llm_client import LLMClient
from .memory import record_finding, record_schema_reject, record_infra_error, record_schema_audit
from .schema_validator import filter_findings
from .grounded_parser import _parse_grounded_findings

# ---------------------------------------------------------------------------
# Negative examples – injected into every prompt to combat hallucination
# ---------------------------------------------------------------------------
_NEGATIVE_EXAMPLE = textwrap.dedent("""\

    === DO NOT DO THIS – Examples of INVALID hallucinated findings ===

    INVALID EXAMPLE 1 – SQL hallucination:
    FINDING:
    Title: SQL Injection in login function
    Location: login()
    Path: username parameter → unsanitised SQL query
    Property: SQL queries must use parameterised statements
    AttackerInput: username=' OR 1=1--
    Consequence: attacker bypasses authentication via SQL injection
    Severity: critical
    ---
    WHY IT IS INVALID: The target code does not use SQL, a database, or any query
    construction. It reads JSON files from disk using pathlib and json.loads().
    SQL injection is impossible. Claiming SQL injection here is fabrication.

    INVALID EXAMPLE 2 – Path traversal hallucination (network stack assumed):
    FINDING:
    Title: Path Traversal in User Profile Service
    Location: get_employee_profile()
    Path: username → HTTP request → directory traversal → /etc/passwd
    Property: file paths must be sanitised
    AttackerInput: username='../../../etc/passwd'
    Consequence: attacker reads arbitrary files via HTTP
    Severity: critical
    ---
    WHY IT IS INVALID: There is no HTTP server, no network stack, no web framework.
    The username is passed as a Python function argument. 'Path traversal via HTTP'
    requires a web server that does not exist in this code.
    The actual issue (if any) would be: does `DATA / f"{username}.json"` allow
    reading outside DATA without sanitisation? That is a different, narrower claim.

    INVALID EXAMPLE 3 – Mechanism mismatch (MD5 + database assumed):
    FINDING:
    Title: Insecure MD5 Hashing of Passwords
    Path: password → MD5 hash → stored in SQL database → exposed via SQL injection
    Consequence: attacker dumps hashes from database and cracks offline
    ---
    WHY IT IS INVALID: There is no SQL database. Hashes are stored in JSON files.
    The correct consequence is: attacker who already has file read access can crack
    the MD5 hashes offline. Do not invent a database that is not present.

    === END NEGATIVE EXAMPLES ===

    """)

# ---------------------------------------------------------------------------
# Role definitions – evidence-first system prompts (Cycle 15/16)
# ---------------------------------------------------------------------------

AGENT_ROLES = {
    "auth_analyst": {
        "name": "Authentication Analyst",
        "focus": "authentication, session management, credential handling, token security",
        "system": textwrap.dedent("""\
            You are a security researcher specialising in authentication and session management.
            You analyse Python source code and report ONLY findings that meet the evidence-first standard.

            A finding is valid ONLY if you can supply ALL of the following:
            1. Exact location (function name + relevant lines or statements)
            2. Concrete data/control-flow path showing how attacker-controlled input or state reaches a sensitive operation
            3. The precise security property that is violated (e.g. "session tokens must be unpredictable")
            4. A concrete attacker-controlled input, condition, or sequence that triggers the issue
            5. The expected observable consequence (what the attacker can actually achieve)

            TECHNOLOGY CONSTRAINT: This target uses Python file I/O (pathlib, json.loads, json.dumps)
            and hashlib. It does NOT use SQL, databases, pickle, eval, exec, or subprocess.
            Do NOT claim SQL injection, deserialization, or command injection.

            Do NOT report:
            - Missing best practices without a reachable exploit path
            - Hypothetical issues that assume code that is not present
            - Claims that require a database, SQL, or other technology that does not appear in the source

            Be precise. Only report what the code actually does."""),
    },
    "access_control": {
        "name": "Access Control Specialist",
        "focus": "authorisation, RBAC, privilege escalation, multi-tenancy, IDOR",
        "system": textwrap.dedent("""\
            You are a security researcher specialising in authorisation and access control.
            You analyse Python source code and report ONLY findings that meet the evidence-first standard.

            A finding is valid ONLY if you can supply ALL of the following:
            1. Exact location (function name + relevant lines or statements)
            2. Concrete data/control-flow path showing how an unauthenticated or unauthorised caller can reach a sensitive operation
            3. The precise security property that is violated (e.g. "profile updates must verify caller ownership")
            4. A concrete attacker-controlled input or condition (e.g. calling the function with a different username)
            5. The expected observable consequence

            TECHNOLOGY CONSTRAINT: This target uses Python file I/O (pathlib, json.loads, json.dumps).
            It does NOT use SQL, databases, or network sockets. Do not claim SQL injection.

            Do not report missing checks unless you can show the function is reachable without those checks
            and produces a security-relevant effect.
            Be precise. Only report what the code actually does."""),
    },
    "input_validator": {
        "name": "Input Validation Researcher",
        "focus": "injection, path traversal, input sanitisation, data validation",
        "system": textwrap.dedent("""\
            You are a security researcher specialising in input validation and injection flaws.
            You analyse Python source code and report ONLY findings that meet the evidence-first standard.

            A finding is valid ONLY if you can supply ALL of the following:
            1. Exact location (function name + relevant lines or statements)
            2. Concrete data/control-flow path from attacker-controlled input to a sensitive operation
               (file open, command execution — NOT SQL query construction, which does not exist here)
            3. The precise security property that is violated
            4. A concrete attacker-controlled input that reaches the sensitive operation
            5. The expected observable consequence

            CRITICAL RULES:
            - Do NOT claim SQL injection. This code has no SQL. There is no database.
              The code reads JSON files with pathlib. Claiming SQL injection is fabrication.
            - Do NOT claim path traversal unless an attacker-controlled string is used in a
              filesystem path (e.g. DATA / f"{username}.json") without containment.
            - Absence of validation is not enough; the input must actually reach a dangerous sink.
            - The target uses only: pathlib, json, hashlib, logging, time.

            Be precise. Only report what the code actually does."""),
    },
    "availability_analyst": {
        "name": "Availability & DoS Researcher",
        "focus": "denial of service, resource exhaustion, rate limiting, pagination",
        "system": textwrap.dedent("""\
            You are a security researcher specialising in availability and denial-of-service.
            You analyse Python source code and report ONLY findings that meet the evidence-first standard.

            A finding is valid ONLY if you can supply ALL of the following:
            1. Exact location (function name + relevant lines or statements)
            2. Concrete data/control-flow path showing how an attacker can trigger unbounded or expensive work
            3. The precise security property that is violated (e.g. "list endpoints must paginate or limit results")
            4. A concrete attacker-controlled input or condition
            5. The expected observable consequence (resource exhaustion, response size, latency, etc.)

            TECHNOLOGY CONSTRAINT: This code reads JSON files from a local directory.
            It does NOT use SQL, databases, or network sockets.

            Do not report missing rate limits or pagination unless you can show the operation
            is reachable and unbounded.
            Be precise. Only report what the code actually does."""),
    },
    "secrets_scanner": {
        "name": "Secrets & Configuration Scanner",
        "focus": "hardcoded secrets, insecure defaults, misconfiguration, weak cryptography",
        "system": textwrap.dedent("""\
            You are a security researcher specialising in secrets management and configuration.
            You analyse Python source code and report ONLY findings that meet the evidence-first standard.

            A finding is valid ONLY if you can supply ALL of the following:
            1. Exact location (constant, assignment, or function)
            2. Evidence that the secret/default is present in source and used in a security-relevant way
            3. The precise security property that is violated (e.g. "secrets must not be hardcoded",
               "password hashes must use a modern KDF")
            4. How an attacker benefits (e.g. offline cracking, token forgery, key compromise)
            5. The expected observable consequence

            TECHNOLOGY CONSTRAINT: This target uses Python hashlib (md5), pathlib, and json.
            It does NOT use SQL, databases, or pickle.

            Hardcoded values used only for non-security purposes are not findings.
            Be precise. Only report what the code actually does."""),
    },
}


# ---------------------------------------------------------------------------
# Cycle 17 – Grounded role definitions (mandatory 8-step pre-analysis)
# ---------------------------------------------------------------------------

_GROUNDED_SYSTEM_BASE = textwrap.dedent("""\
    You are a security researcher. You must ground every finding in the ACTUAL source code.

    BEFORE emitting any finding, you MUST complete this 8-step grounding check:

    STEP 1 – IDENTIFY: Name the specific function and line(s) you are analysing.
    STEP 2 – IMPORTS: List every module imported at the top of the file.
              This target imports: pathlib, json, hashlib, logging, time.
              It does NOT import: sqlite3, flask, django, requests, subprocess, pickle, eval, exec.
    STEP 3 – ATTACKER INPUT: Identify the exact function parameter(s) the attacker controls.
    STEP 4 – CODE PATH: Trace the parameter through each statement step-by-step using the
              actual variable names and operations present in the source. Do not invent steps.
    STEP 5 – PROPERTY: State the specific security property that the traced path violates.
    STEP 6 – CONSEQUENCE: State what the attacker concretely achieves via this exact path.
    STEP 7 – MECHANISM CHECK: Ask yourself: "Does the attack mechanism I am claiming
              (SQL query, HTTP request, eval, pickle, subprocess, network socket, etc.)
              actually appear in the source code I was given?"
              If NO → ABORT. Do not emit this finding.
    STEP 8 – SELF-REJECT: If any required mechanism is absent from the source, write
              MECHANISM_ABSENT and do not emit a FINDING block for this issue.

    HARD RULE: You must NEVER infer SQL injection, command injection, path traversal via
    HTTP, network exploitation, or authentication bypass merely because the vulnerability
    category is commonly associated with those mechanisms. The mechanism must be
    demonstrable directly from the source code you were given.

    The claimed attack path must use ONLY operations that actually appear in the source:
    pathlib.Path operations, json.loads(), json.dumps(), hashlib.md5(), standard Python
    string formatting, and file read/write via Path.read_text() / Path.write_text().

    If you cannot demonstrate the complete path using only those operations, do not emit
    a FINDING block."""
)

_GROUNDED_FINDING_FORMAT = textwrap.dedent("""\
    Use this EXACT format for every valid finding. ALL fields are REQUIRED:

    FINDING:
    Title: <short descriptive title>
    Location: <exact function name and the specific statements involved>
    Imports_Deps: <comma-separated list of imports actually used in this finding's path>
    Attacker_Input: <the exact parameter or value the attacker controls>
    Data_Flow: <step-by-step: param → operation → operation → sensitive result,
                using only actual variable names and code from the source>
    Security_Property: <the specific property that is violated, e.g.
                        "session tokens must be cryptographically unpredictable">
    Consequence: <what the attacker concretely achieves via this exact path>
    Mechanism_Evidence: <quote the exact line(s) from the source that prove
                         the vulnerability mechanism exists; do not paraphrase>
    Confidence: <HIGH | MEDIUM | LOW — your confidence that the path is correct>
    Severity: <critical|high|medium|low>
    ---

    IMPORTANT:
    - A finding missing ANY field above will be discarded.
    - Mechanism_Evidence MUST quote actual source lines, not paraphrase them.
    - If Mechanism_Evidence cannot be filled with real source quotes, ABORT this finding.
    - Confidence=LOW findings still require all fields; they are not exempt.
    - Do not emit a FINDING block for issues where Step 7 found the mechanism absent.""")

CYCLE17_AGENT_ROLES = {
    "auth_analyst": {
        "name": "Authentication Analyst",
        "focus": "authentication, session management, credential handling, token security",
        "system": _GROUNDED_SYSTEM_BASE + textwrap.dedent("""\

            SPECIALISATION: Authentication and session management.
            Focus areas: session token generation, password hashing, credential comparison,
            login function security, token predictability.

            Key questions for this target:
            - How is the session token generated? What inputs does it use?
            - Can an attacker predict or forge the token?
            - How are passwords hashed? Is the algorithm weak?
            - Is the secret key protected or hardcoded?"""),
    },
    "access_control": {
        "name": "Access Control Specialist",
        "focus": "authorisation, RBAC, privilege escalation, IDOR",
        "system": _GROUNDED_SYSTEM_BASE + textwrap.dedent("""\

            SPECIALISATION: Authorisation and access control.
            Focus areas: which functions check the caller's role, which functions
            accept any caller without checking, can a low-privilege caller reach
            high-privilege operations by passing different arguments.

            Key questions for this target:
            - Does patch_profile() verify the caller owns the profile being patched?
            - Does get_employee_profile() restrict who can see which profiles?
            - Does export_all_records() check the caller's role before returning all data?
            - Does promote_user() check that only admins can promote?"""),
    },
    "input_validator": {
        "name": "Input Validation Researcher",
        "focus": "input sanitisation, path construction, data validation",
        "system": _GROUNDED_SYSTEM_BASE + textwrap.dedent("""\

            SPECIALISATION: Input validation and path safety.
            Focus areas: are user-supplied strings used to construct filesystem paths
            (e.g. DATA / f"{username}.json") without sanitisation? Can an attacker
            supply a string that escapes the intended directory?

            REMEMBER: This code has NO SQL, NO HTTP server, NO network stack.
            Do NOT claim SQL injection or HTTP-based path traversal.
            The only sensitive operations are: Path construction with user input,
            json.loads() of user-supplied data, and json.dumps() of user-controlled fields."""),
    },
    "availability_analyst": {
        "name": "Availability & DoS Researcher",
        "focus": "denial of service, resource exhaustion, unbounded operations",
        "system": _GROUNDED_SYSTEM_BASE + textwrap.dedent("""\

            SPECIALISATION: Availability and resource exhaustion.
            Focus areas: operations that iterate over all files, load all records,
            or perform work proportional to attacker-controlled input without limits.

            REMEMBER: This code reads JSON files from a local directory.
            DoS requires demonstrating that an attacker can TRIGGER the expensive
            operation — not just that the operation is unbounded. Show how."""),
    },
    "secrets_scanner": {
        "name": "Secrets & Configuration Scanner",
        "focus": "hardcoded secrets, weak cryptography, insecure defaults",
        "system": _GROUNDED_SYSTEM_BASE + textwrap.dedent("""\

            SPECIALISATION: Secrets and weak cryptography.
            Focus areas: hardcoded strings used as cryptographic keys or secrets,
            use of weak/broken hash algorithms (MD5, SHA1) for security-sensitive
            operations (password storage, token generation).

            Key questions for this target:
            - What is SECRET_KEY set to? How is it used?
            - What algorithm hashes passwords? Is it appropriate?
            - What algorithm generates session tokens? Is it appropriate?
            - Can an attacker obtain a hash and crack it? How (quote the storage mechanism)?"""),
    },
}

CHALLENGER_SYSTEM = textwrap.dedent("""\
    You are a strict adversarial peer-reviewer for evidence-first security findings.
    Another agent has claimed a vulnerability. Your default stance is SCEPTICAL.

    The target application uses ONLY: Python pathlib, json, hashlib, logging, time.
    It does NOT use SQL, databases, pickle, eval, exec, subprocess, or any network stack.
    Immediately respond INVALID if the finding claims SQL injection, deserialization,
    command injection, or any technology absent from the target.

    Confirm (VALID) ONLY if ALL of the following are true and clearly supported by the source:
    1. The claimed location exists and matches the description.
    2. There is a concrete, reachable data or control-flow path from attacker-controlled input/state
       to a sensitive operation that IS PRESENT IN THE SOURCE.
    3. The security property stated is actually violated by that path.
    4. The concrete attacker input/condition is plausible given the code.
    5. The claimed observable consequence follows from the code behaviour.

    Respond with exactly one of: VALID, PARTIAL, or INVALID on the first line.
    - VALID   = evidence chain is complete and the issue is real
    - PARTIAL = something is present but severity, path, or consequence is overstated or incomplete
    - INVALID = missing path, wrong technology assumed, or not a security issue

    Then explain in 2-5 sentences, citing specific code behaviour.
    Do not be lenient. Absence of a best practice alone is never sufficient.""")

CYCLE19_CHALLENGER_SYSTEM = textwrap.dedent("""\
    You are an objective, rigorous security evaluator for code vulnerabilities.
    Your task is to independently evaluate a security finding across 6 specific dimensions.

    The target application uses ONLY: Python pathlib, json, hashlib, logging, time.
    It does NOT use SQL, databases, pickle, eval, exec, subprocess, or network sockets.

    CRITICAL EVALUATION RULES:
    1. FACTUAL_VALIDITY: Does the code behaviour described actually occur in the source?
       - VALID: The statements and operations exist and behave as described.
       - PARTIAL: The code is partially as described, but has factual inaccuracies.
       - INVALID: The described code or technology does not exist in the source.

    2. ATTACK_PATH: Can an attacker realistically reach and trigger this operation?
       - SUPPORTED: Complete, reachable data/control flow from external input to sensitive operation.
       - PARTIAL: Path is plausible but incomplete or missing a step.
       - UNSUPPORTED: No reachable path from attacker input to the operation.

    3. SECURITY_PROPERTY: Is a legitimate security property (e.g. confidentiality, integrity, least privilege, safe crypto) violated?
       - SUPPORTED: A genuine security property is violated.
       - UNSUPPORTED: No security property is violated.

    4. CONSEQUENCE: Does the claimed observable impact follow from the code?
       - SUPPORTED: The attacker can concretely achieve the stated impact.
       - OVERSTATED: An issue exists, but the claimed impact (e.g. RCE, full takeover) is exaggerated.
       - UNSUPPORTED: The claimed impact cannot happen.

    5. SEVERITY: Does the stated severity match standard risk guidelines?
       - AGREE: Severity matches the realistic impact.
       - DISAGREE: You disagree with the severity level (e.g. finding says HIGH but it is MEDIUM).
       - INDETERMINATE: Cannot be determined.

    6. OVERALL:
       - CONFIRMED: Factually valid, path supported, security property violated.
       - PARTIALLY_SUPPORTED: The underlying security concern is genuine, but the path, consequence, or mechanism is incomplete or overstated.
       - INVALID: Not a vulnerability, wrong technology claimed, or unsupported.

    CRITICAL REQUIREMENTS:
    - SEVERITY DECOUPLING: Severity disagreement alone MUST NEVER make a factually supported vulnerability INVALID. If the flaw is real but severity is overstated, evaluate OVERALL as CONFIRMED or PARTIALLY_SUPPORTED and mark SEVERITY as DISAGREE.
    - WRONG MECHANISM VS REAL ISSUE: If the discoverer names the wrong mechanism (e.g., claims DoS/unbounded loop or SQLi) but the source code at that location clearly exhibits a different real security issue (e.g., unauthenticated data dump or weak MD5 hashing), record:
        RELATED_REAL_ISSUE: TRUE
        STATED_CLAIM_VALID: FALSE
      Do NOT silently rewrite the discoverer's claim; evaluate the stated claim strictly, while noting the related real issue.""")


# ---------------------------------------------------------------------------
# Agent base class
# ---------------------------------------------------------------------------

@dataclass
class ResearchAgent:
    agent_id: str
    role_key: str
    client: LLMClient
    conn: object  # sqlite3 connection

    @property
    def role_info(self) -> dict:
        return AGENT_ROLES[self.role_key]

    def _build_prompt(self, source_code: str, cycle_key: str = "15") -> str:
        """Build the discovery prompt. Cycle 17 uses the grounded 8-step format."""
        if cycle_key in ("17", "18", "19", "20", "21"):
            return self._build_grounded_prompt(source_code)
        # Cycle 15/16: original evidence-first format
        return textwrap.dedent(f"""\
            === SOURCE CODE TO ANALYSE ===
            {source_code}
            === END SOURCE CODE ===
            {_NEGATIVE_EXAMPLE}
            Analyse the above Python code through the lens of: {self.role_info['focus']}.

            Emit a finding ONLY when you can complete the full evidence chain.
            Use this EXACT format for every finding (all fields are REQUIRED):

            FINDING:
            Title: <short descriptive title>
            Location: <function name and key statements>
            Path: <step-by-step data/control-flow from attacker input or state to the sensitive operation>
            Property: <the security property that is violated>
            AttackerInput: <concrete input, condition, or sequence the attacker controls>
            Consequence: <observable result the attacker achieves>
            Severity: <critical|high|medium|low>
            ---

            IMPORTANT: A finding missing ANY of the above fields will be discarded.
            Do not emit a FINDING block unless you can fill in ALL fields with specific
            references to the actual source code above.

            If you cannot complete the full evidence chain for any issue in your focus area, respond with exactly:
            NO_FINDINGS

            Do not invent technologies, databases, SQL, or APIs that are not present in the source.""")

    def _build_grounded_prompt(self, source_code: str) -> str:
        """Cycle 17: mandatory 8-step grounding preamble before any finding."""
        role_info = CYCLE17_AGENT_ROLES.get(self.role_key, self.role_info)
        focus = role_info["focus"]
        return textwrap.dedent(f"""\
            === SOURCE CODE TO ANALYSE ===
            {source_code}
            === END SOURCE CODE ===
            {_NEGATIVE_EXAMPLE}
            You are analysing this code through the lens of: {focus}.

            MANDATORY GROUNDING PROCEDURE:
            Before writing any FINDING block, work through ALL 8 steps for each candidate issue:

            STEP 1 – IDENTIFY: Which function and which line(s) are you analysing?
            STEP 2 – IMPORTS: List every import at the top of the source. Does the attack
                     mechanism you are about to claim require any import NOT in that list?
                     If YES → ABORT this finding (MECHANISM_ABSENT).
            STEP 3 – ATTACKER INPUT: What exact parameter does the attacker control?
            STEP 4 – CODE PATH: Trace the parameter through the actual statements in the source.
                     Write each step as: variable/operation → next variable/operation.
                     Only use variable names that appear in the source.
            STEP 5 – PROPERTY: What specific security property does this path violate?
            STEP 6 – CONSEQUENCE: What does the attacker concretely achieve via this exact path?
            STEP 7 – MECHANISM CHECK: Does the attack mechanism (SQL, eval, HTTP, network,
                     pickle, subprocess, directory traversal via HTTP) actually appear in the
                     source? If NOT present → write MECHANISM_ABSENT and stop for this issue.
            STEP 8 – SELF-REJECT: If Step 7 is MECHANISM_ABSENT, do not emit a FINDING block.

            {_GROUNDED_FINDING_FORMAT}

            If after completing all 8 steps for all candidate issues no finding survives
            self-rejection, respond with exactly:
            NO_FINDINGS

            Remember: MECHANISM_ABSENT means no FINDING block for that issue.""")

    def analyse(self, source_code: str, cycle_key: str = "15") -> tuple[list[dict], float]:
        """
        Call the LLM with the source code and parse structured evidence-first findings.
        Returns (findings_list, elapsed_seconds).
        On infrastructure failure: logs infra_error and returns ([], elapsed).
        Cycle 17: uses grounded 8-step prompt and grounded parser.
        """
        prompt = self._build_prompt(source_code, cycle_key=cycle_key)
        # Use Cycle 17/18/19/20/21 system prompt if available
        if cycle_key in ("17", "18", "19", "20", "21"):
            sys_prompt = CYCLE17_AGENT_ROLES.get(self.role_key, self.role_info)["system"]
        else:
            sys_prompt = self.role_info["system"]
        t0 = time.time()
        try:
            response = self.client.chat(
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user",   "content": prompt},
                ]
            )
        except ConnectionError as e:
            elapsed = round(time.time() - t0, 2)
            # Log as infrastructure error — NOT as a finding
            record_infra_error(
                self.conn,
                agent_id=self.agent_id,
                error_type="OLLAMA_UNAVAILABLE",
                detail=str(e),
            )
            print(f"  [INFRA-ERROR] {self.agent_id}: {e}")
            return [], elapsed

        elapsed = round(time.time() - t0, 2)
        if not response:
            return [], elapsed
        stripped = response.strip()
        if stripped == "NO_FINDINGS" or stripped.upper().startswith("NO_FINDINGS"):
            return [], elapsed

        if cycle_key in ("17", "18", "19", "20", "21"):
            return _parse_grounded_findings(response), elapsed
        return _parse_findings(response), elapsed

    def write_findings(
        self,
        findings: list[dict],
        discovery_seconds: float = None,
        target_src: str = "",
    ) -> tuple[list[int], int]:
        """
        Validate findings through schema gate, then write valid ones to shared memory.
        Returns (list_of_valid_ids, rejected_count).
        """
        if not findings:
            return [], 0

        valid, rejected = filter_findings(findings, target_src=target_src, agent_id=self.agent_id)

        # Log rejected findings to schema_rejects table and schema_audit
        for rf in rejected:
            record_schema_reject(
                self.conn,
                agent_id=self.agent_id,
                role=self.role_key,
                hypothesis=rf.get("hypothesis", "?"),
                rejection_reason=rf.get("rejection_reason", "unknown"),
            )
            record_schema_audit(
                self.conn,
                agent_id=self.agent_id,
                role=self.role_key,
                hypothesis=rf.get("hypothesis", "?"),
                status="REJECTED",
                rejection_reason=rf.get("rejection_reason", "unknown"),
                path=rf.get("path"),
                location=rf.get("location"),
                security_property=rf.get("property"),
                raw_text=rf.get("raw_text"),
            )

        ids = []
        per = round(discovery_seconds / len(valid), 2) if valid and discovery_seconds else discovery_seconds
        for f in valid:
            record_schema_audit(
                self.conn,
                agent_id=self.agent_id,
                role=self.role_key,
                hypothesis=f.get("hypothesis", "?"),
                status="ACCEPTED",
                rejection_reason=None,
                path=f.get("path"),
                location=f.get("location"),
                security_property=f.get("property"),
                raw_text=f.get("raw_text"),
            )
            fid = record_finding(
                self.conn,
                agent_id=self.agent_id,
                role=self.role_key,
                hypothesis=f["hypothesis"],
                evidence=f["evidence"],
                severity=f.get("severity", "medium"),
                discovery_seconds=per,
                source="llm",
                pre_confirmed=False,
            )
            ids.append(fid)
        return ids, len(rejected)


# ---------------------------------------------------------------------------
# Challenger agent
# ---------------------------------------------------------------------------

def _parse_cycle19_challenge(response: str) -> dict:
    import re

    def _extract(name: str, allowed: list[str], default: str = None) -> str:
        pattern = rf"(?:(?:\d+\.|\*|-)?\s*\**{name}(?:\:|\=)?\**\s*[:=]?\s*\**([A-Za-z_]+))"
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            val = m.group(1).upper()
            for a in allowed:
                if val == a or val.startswith(a):
                    return a
        return default

    def _extract_bool(name: str, default: bool = False) -> bool:
        pattern = rf"(?:(?:\d+\.|\*|-)?\s*\**{name}(?:\:|\=)?\**\s*[:=]?\s*\**([A-Za-z_]+))"
        m = re.search(pattern, response, re.IGNORECASE)
        if m:
            val = m.group(1).upper()
            if "TRUE" in val or "YES" in val or "1" in val:
                return True
            if "FALSE" in val or "NO" in val or "0" in val:
                return False
        return default

    factual_validity = _extract("FACTUAL_VALIDITY", ["VALID", "PARTIAL", "INVALID"])
    attack_path = _extract("ATTACK_PATH", ["SUPPORTED", "PARTIAL", "UNSUPPORTED"])
    security_property = _extract("SECURITY_PROPERTY", ["SUPPORTED", "UNSUPPORTED"])
    consequence = _extract("CONSEQUENCE", ["SUPPORTED", "OVERSTATED", "UNSUPPORTED"])
    severity_eval = _extract("SEVERITY", ["AGREE", "DISAGREE", "INDETERMINATE"])
    overall = _extract("OVERALL", ["CONFIRMED", "PARTIALLY_SUPPORTED", "INVALID"])
    related_real_issue = _extract_bool("RELATED_REAL_ISSUE", default=False)
    stated_claim_valid = _extract_bool("STATED_CLAIM_VALID", default=False)

    # Natural language fallback when challenger outputs a descriptive paragraph
    resp_upper = response.upper()
    if not factual_validity:
        if any(phrase in resp_upper for phrase in ["IS FACTUALLY VALID", "THE CODE USES", "THE SOURCE CODE CONTAINS", "IS VALID AND SUPPORTED", "FUNCTION GENERATES", "SOURCE CODE USES", "CODE CONSTRUCTS"]):
            factual_validity = "VALID"
        else:
            factual_validity = "INVALID"

    if not security_property:
        if "SECURITY PROPERTY" in resp_upper and any(w in resp_upper for w in ["VIOLATED", "IS VIOLATED", "VIOLATES"]):
            security_property = "SUPPORTED"
        elif any(phrase in resp_upper for phrase in ["CRYPTOGRAPHIC WEAKNESS", "DOES NOT PROPERLY ENFORCE RBAC", "INSECURE ALGORITHM"]):
            security_property = "SUPPORTED"
        else:
            security_property = "UNSUPPORTED"

    if not attack_path:
        if "AN ATTACKER" in resp_upper and any(w in resp_upper for w in ["CAN", "COULD"]):
            attack_path = "SUPPORTED"
        else:
            attack_path = "UNSUPPORTED"

    if not consequence:
        if "CONSEQUENCE" in resp_upper or any(phrase in resp_upper for phrase in ["CAN GAIN ACCESS", "LEADING TO", "EXHAUSTING", "UNAUTHORIZED ACCESS"]):
            consequence = "SUPPORTED"
        else:
            consequence = "UNSUPPORTED"

    if not severity_eval:
        if any(phrase in resp_upper for phrase in ["SEVERITY IS OVERSTATED", "SEVERITY CLAIM", "OVERSTATED AS MEDIUM", "OVERSTATED BY THE DISCOVERER", "DISAGREE"]):
            severity_eval = "DISAGREE"
        elif "AGREE" in resp_upper:
            severity_eval = "AGREE"
        else:
            severity_eval = "INDETERMINATE"

    # Fallback for overall if not explicitly matched
    if not overall:
        if factual_validity == "VALID" and security_property == "SUPPORTED":
            if severity_eval == "DISAGREE" or consequence == "OVERSTATED" or attack_path == "PARTIAL":
                overall = "PARTIALLY_SUPPORTED"
            else:
                overall = "CONFIRMED"
        else:
            overall = "INVALID"

    # Enforce: Severity disagreement alone MUST NEVER make a factually supported vulnerability INVALID
    if overall == "INVALID" and factual_validity == "VALID" and security_property == "SUPPORTED" and severity_eval == "DISAGREE":
        if attack_path == "SUPPORTED" and consequence in ("SUPPORTED", "OVERSTATED"):
            overall = "CONFIRMED"
        else:
            overall = "PARTIALLY_SUPPORTED"

    if stated_claim_valid is False and factual_validity == "VALID":
        stated_claim_valid = True

    # Determine legacy verdict and raw_verdict
    if overall == "CONFIRMED":
        raw_verdict = "FULL_VALID"
        strict_verdict = "confirmed"
    elif overall == "PARTIALLY_SUPPORTED":
        raw_verdict = "PARTIAL"
        strict_verdict = "partial"
    else:
        raw_verdict = "FULL_INVALID"
        strict_verdict = "refuted"

    m_reason = re.search(r"(?:(?:\d+\.|\*|-)?\s*(?:\*\*)?REASONING(?:\*\*)?\s*[:=]\s*)(.*)", response, re.DOTALL | re.IGNORECASE)
    reasoning = m_reason.group(1).strip() if m_reason else response.strip()

    return {
        "verdict": strict_verdict,
        "raw_verdict": raw_verdict,
        "reasoning": reasoning,
        "factual_validity": factual_validity,
        "attack_path": attack_path,
        "security_property": security_property,
        "consequence": consequence,
        "severity_eval": severity_eval,
        "overall_verdict": overall,
        "related_real_issue": related_real_issue,
        "stated_claim_valid": stated_claim_valid,
    }


@dataclass
class ChallengerAgent:
    agent_id: str
    client: LLMClient
    conn: object

    def challenge(
        self,
        finding: dict,
        source_code: str,
        preserve_partial: bool = False,
        cycle_key: str = "15",
    ) -> dict:
        """
        Adversarial review.
        Cycle 19/20: decomposed 6-axis evaluation.
        Cycle 16-18: evidence-first 3-way review.
        """
        if cycle_key in ("19", "20", "21", "22"):
            prompt = textwrap.dedent(f"""\
                === ORIGINAL SOURCE CODE ===
                {source_code}
                === END SOURCE CODE ===

                === FINDING TO EVALUATE ===
                Role: {finding.get('agent_role', '?')}
                Hypothesis: {finding['hypothesis']}
                Evidence: {finding['evidence']}
                Severity: {finding.get('severity', '?')}
                === END FINDING ===

                Evaluate the finding against the original source code.
                Provide your evaluation in this EXACT format (all fields are REQUIRED):

                FACTUAL_VALIDITY: <VALID | PARTIAL | INVALID>
                ATTACK_PATH: <SUPPORTED | PARTIAL | UNSUPPORTED>
                SECURITY_PROPERTY: <SUPPORTED | UNSUPPORTED>
                CONSEQUENCE: <SUPPORTED | OVERSTATED | UNSUPPORTED>
                SEVERITY: <AGREE | DISAGREE | INDETERMINATE>
                OVERALL: <CONFIRMED | PARTIALLY_SUPPORTED | INVALID>
                RELATED_REAL_ISSUE: <TRUE | FALSE>
                STATED_CLAIM_VALID: <TRUE | FALSE>
                REASONING: <2-5 sentences explaining your evaluation citing specific lines and code behaviour>""")
            sys_msg = CYCLE19_CHALLENGER_SYSTEM
        else:
            prompt = textwrap.dedent(f"""\
                === ORIGINAL SOURCE CODE ===
                {source_code}
                === END SOURCE CODE ===

                === FINDING TO EVALUATE ===
                Role: {finding.get('agent_role', '?')}
                Hypothesis: {finding['hypothesis']}
                Evidence: {finding['evidence']}
                Severity: {finding.get('severity', '?')}
                === END FINDING ===

                Evaluate against the evidence-first criteria.
                Remember: this target uses ONLY pathlib, json, hashlib, logging, time.
                There is NO SQL, NO database, NO pickle, NO eval, NO subprocess.
                Respond VALID, PARTIAL, or INVALID on line 1.""")
            sys_msg = CHALLENGER_SYSTEM

        try:
            response = self.client.chat(
                messages=[
                    {"role": "system", "content": sys_msg},
                    {"role": "user",   "content": prompt},
                ],
                num_predict=512,
            )
        except ConnectionError as e:
            record_infra_error(
                self.conn,
                agent_id=self.agent_id,
                error_type="CHALLENGER_TIMEOUT",
                detail=str(e),
            )
            return {"verdict": "inconclusive", "raw_verdict": None, "reasoning": f"Infrastructure error: {e}"}

        if not response:
            return {"verdict": "inconclusive", "raw_verdict": None, "reasoning": "Empty response from LLM"}

        if cycle_key in ("19", "20", "21", "22"):
            return _parse_cycle19_challenge(response)

        lines = response.strip().splitlines()
        first_line = lines[0].strip().upper() if lines else ""
        reasoning = " ".join(lines[1:]).strip() if len(lines) > 1 else response

        # Determine raw_verdict (unmodified, 3-way)
        if "INVALID" in first_line:
            raw_verdict = "FULL_INVALID"
            strict_verdict = "refuted"
        elif "PARTIAL" in first_line:
            raw_verdict = "PARTIAL"
            strict_verdict = "partial" if preserve_partial else "refuted"
        elif "VALID" in first_line:
            raw_verdict = "FULL_VALID"
            strict_verdict = "confirmed"
        else:
            raw_verdict = None
            strict_verdict = "inconclusive"

        return {"verdict": strict_verdict, "raw_verdict": raw_verdict, "reasoning": reasoning}


# ---------------------------------------------------------------------------
# Parser – evidence-first format
# ---------------------------------------------------------------------------

def _parse_findings(text: str) -> list[dict]:
    """Parse LLM output into structured finding dicts with full evidence chain."""
    findings = []
    current: dict = {}

    def _flush():
        if current.get("hypothesis"):
            parts = []
            if current.get("location"):
                parts.append(f"Location: {current['location']}")
            if current.get("path"):
                parts.append(f"Path: {current['path']}")
            if current.get("property"):
                parts.append(f"Property: {current['property']}")
            if current.get("attacker_input"):
                parts.append(f"AttackerInput: {current['attacker_input']}")
            if current.get("consequence"):
                parts.append(f"Consequence: {current['consequence']}")
            if current.get("extra"):
                parts.append(current["extra"])
            evidence = " | ".join(parts) if parts else current.get("evidence", "")
            findings.append({
                "hypothesis": current["hypothesis"],
                "evidence": evidence,
                "severity": current.get("severity", "medium"),
                "location": current.get("location", ""),
                "path": current.get("path", ""),
                "property": current.get("property", ""),
                "attacker_input": current.get("attacker_input", ""),
                "consequence": current.get("consequence", ""),
            })

    for raw_line in text.splitlines():
        line = raw_line.strip()
        cleaned = line.lstrip("#*- 0123456789.)").strip().replace("**", "").replace("__", "")
        cleaned_lower = cleaned.lower()

        if cleaned_lower.startswith("finding:") or (
            cleaned_lower.startswith("finding") and any(c in cleaned_lower for c in [":", "1", "2", "3", "4", "5"])
        ):
            _flush()
            current = {}
        elif cleaned_lower.startswith("title:"):
            current["hypothesis"] = cleaned[6:].strip()
        elif cleaned_lower.startswith("location:"):
            current["location"] = cleaned[9:].strip()
        elif cleaned_lower.startswith("path:"):
            current["path"] = cleaned[5:].strip()
        elif cleaned_lower.startswith("property:"):
            current["property"] = cleaned[9:].strip()
        elif cleaned_lower.startswith("attackerinput:") or cleaned_lower.startswith("attacker_input:") or cleaned_lower.startswith("attacker input:"):
            idx = cleaned.find(":")
            current["attacker_input"] = cleaned[idx + 1:].strip()
        elif cleaned_lower.startswith("consequence:"):
            current["consequence"] = cleaned[12:].strip()
        elif cleaned_lower.startswith("severity:"):
            sev = cleaned[9:].strip().lower()
            current["severity"] = sev if sev in {"critical", "high", "medium", "low"} else "medium"
        elif cleaned_lower.startswith("problem:") or cleaned_lower.startswith("impact:") or cleaned_lower.startswith("fix:"):
            current["extra"] = current.get("extra", "") + " " + cleaned
        elif current.get("path") is not None and not any(
            cleaned_lower.startswith(k) for k in ("title:", "location:", "path:", "property:", "attackerinput:", "attacker_input:", "attacker input:", "consequence:", "severity:", "---", "finding")
        ):
            # Multi-line path continuation
            if cleaned and not cleaned.startswith("---"):
                current["path"] = current.get("path", "") + " " + cleaned

    _flush()
    return findings
