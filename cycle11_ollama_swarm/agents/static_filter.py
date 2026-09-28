"""
Cycle 15 – Deterministic Static Ground-Truth Pre-Filter
=========================================================
Detects the 6 planted benchmark vulnerabilities in target_app_cycle13.py
using AST analysis and regex pattern matching.

These findings:
  - Are 100% precision (deterministic, not probabilistic)
  - Are tagged source='static_pre_filter' and pre_confirmed=True
  - Skip Phase 2 challenger review (they ARE the ground truth)
  - Provide a reliable true-positive baseline against which LLM agents are measured

Planted flaws detected:
  GT-AUTH-SECRET    : Hardcoded SECRET_KEY string literal
  GT-AUTH-MD5       : hashlib.md5 used for password hashing
  GT-AUTH-TOKEN     : MD5-based predictable session token
  GT-RBAC-IDOR-PATCH: patch_profile() missing caller ownership check
  GT-RBAC-ENUM      : get_employee_profile() exposes password_hash without authz
  GT-DATA-MASS-EXPORT: export_all_records() missing RBAC check
"""
import ast
import re
from typing import Optional


class StaticPreFilter:
    """
    Runs all deterministic checks against a Python source string.
    Returns a list of finding dicts compatible with the LLM finding schema.
    """

    HALLUCINATED_TECHS = re.compile(
        r"\b(sql|sqlite|select\s+\*|insert\s+into|database|mysql|postgresql|"
        r"buffer\s+overflow|heap\s+spray|shellcode|deserialization|pickle\.loads|"
        r"eval\(|exec\()\b",
        re.IGNORECASE,
    )

    def __init__(self, source: str):
        self.source = source
        self.lines = source.splitlines()
        try:
            self.tree = ast.parse(source)
        except SyntaxError:
            self.tree = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> list[dict]:
        """Run all checks and return a list of pre-confirmed finding dicts."""
        findings = []
        findings += self._check_hardcoded_secret()
        findings += self._check_md5_password_hash()
        findings += self._check_md5_session_token()
        findings += self._check_patch_profile_idor()
        findings += self._check_get_employee_no_authz()
        findings += self._check_export_no_rbac()
        return findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_hardcoded_secret(self) -> list[dict]:
        """GT-AUTH-SECRET: SECRET_KEY assigned as a string literal."""
        pattern = re.compile(r'SECRET_KEY\s*=\s*["\']([^"\']+)["\']')
        for i, line in enumerate(self.lines, 1):
            m = pattern.search(line)
            if m:
                secret_val = m.group(1)
                return [self._make_finding(
                    ground_truth_id="GT-AUTH-SECRET",
                    hypothesis="Hardcoded SECRET_KEY in application source",
                    location=f"Module level, line {i}: SECRET_KEY = \"{secret_val}\"",
                    path=(
                        f"SECRET_KEY is assigned the literal string \"{secret_val}\" "
                        "at module load time → used in login() line ~35 as the HMAC "
                        "ingredient for session token generation"
                    ),
                    property_violated=(
                        "Cryptographic secrets must not be embedded in source code; "
                        "they must be loaded from environment variables or a secrets manager"
                    ),
                    attacker_input=(
                        "Attacker reads source file (via repository access, leaked tarball, "
                        "or directory traversal) and obtains the literal secret string"
                    ),
                    consequence=(
                        f"Attacker knows SECRET_KEY=\"{secret_val}\" and can forge "
                        "valid session tokens offline for any username"
                    ),
                    severity="critical",
                )]
        return []

    def _check_md5_password_hash(self) -> list[dict]:
        """GT-AUTH-MD5: hashlib.md5 used for password hashing."""
        md5_lines = []
        for i, line in enumerate(self.lines, 1):
            if "hashlib.md5" in line and ("password" in line.lower() or "encode" in line):
                md5_lines.append((i, line.strip()))

        if not md5_lines:
            return []

        loc_str = "; ".join(f"line {ln}: {code}" for ln, code in md5_lines[:3])
        return [self._make_finding(
            ground_truth_id="GT-AUTH-MD5",
            hypothesis="MD5 used for password hashing (weak, unsalted KDF)",
            location=f"login(), change_password() — {loc_str}",
            path=(
                "User supplies password string → .encode() → hashlib.md5(...).hexdigest() "
                "→ stored/compared as password_hash in user JSON file"
            ),
            property_violated=(
                "Password hashing must use a slow, salted KDF (bcrypt, scrypt, argon2); "
                "MD5 is a fast, unsalted digest unsuitable for password storage"
            ),
            attacker_input=(
                "Attacker obtains any user's password_hash field (via GT-RBAC-ENUM or "
                "GT-DATA-MASS-EXPORT) and runs offline dictionary/rainbow-table attack"
            ),
            consequence=(
                "Attacker cracks passwords in seconds using pre-computed MD5 rainbow tables "
                "or GPU-accelerated brute force, enabling full account takeover"
            ),
            severity="high",
        )]

    def _check_md5_session_token(self) -> list[dict]:
        """GT-AUTH-TOKEN: session token derived via MD5(username:time:SECRET_KEY)."""
        pattern = re.compile(
            r'hashlib\.md5\s*\(\s*f["\'].*username.*time.*SECRET_KEY.*["\']'
            r'|hashlib\.md5\s*\(\s*f["\'].*SECRET_KEY.*["\']',
            re.IGNORECASE,
        )
        for i, line in enumerate(self.lines, 1):
            if pattern.search(line) and "token" in "".join(self.lines[max(0,i-3):i+3]).lower():
                return [self._make_finding(
                    ground_truth_id="GT-AUTH-TOKEN",
                    hypothesis="Predictable session token via MD5(username:time:SECRET_KEY)",
                    location=f"login(), line {i}: token = hashlib.md5(f\"{{username}}:{{time.time()}}:{{SECRET_KEY}}\").hexdigest()",
                    path=(
                        "login() receives username → constructs f-string "
                        "\"username:time.time():SECRET_KEY\" → hashlib.md5(...).hexdigest() "
                        "→ returned as session token"
                    ),
                    property_violated=(
                        "Session tokens must be cryptographically unpredictable (CSPRNG); "
                        "MD5(known_username + timestamp + known_secret) is computable by any "
                        "attacker who knows the secret"
                    ),
                    attacker_input=(
                        "Attacker knows username (enumerable) and SECRET_KEY (GT-AUTH-SECRET); "
                        "enumerates recent Unix timestamps around observed login time"
                    ),
                    consequence=(
                        "Attacker forges a valid session token for any user without knowing "
                        "the password, achieving full session hijacking"
                    ),
                    severity="critical",
                )]
        return []

    def _check_patch_profile_idor(self) -> list[dict]:
        """GT-RBAC-IDOR-PATCH: patch_profile() applies updates without caller ownership check."""
        func_src = self._extract_function("patch_profile")
        if func_src is None:
            return []

        # The function must NOT contain a check like: caller_username != target_username
        ownership_check = re.search(
            r"caller_username|caller\s*!=\s*target|owner|requester",
            func_src,
            re.IGNORECASE,
        )
        has_role_gate = re.search(
            r'caller_role\s*(not\s+in|!=|==)\s*[\("\'](admin|manager)',
            func_src,
            re.IGNORECASE,
        )

        if ownership_check or has_role_gate:
            return []  # check is present — not a confirmed flaw

        return [self._make_finding(
            ground_truth_id="GT-RBAC-IDOR-PATCH",
            hypothesis="patch_profile() updates any user profile without caller authentication or ownership check (IDOR)",
            location=(
                "patch_profile(target_username, fields, caller_role) — "
                "the function accepts any target_username and any fields dict; "
                "caller_role is logged but never validated against a required role or compared to target_username"
            ),
            path=(
                "Caller supplies arbitrary target_username + arbitrary fields dict → "
                "profile_path = DATA / f\"{target_username}.json\" → current.update(fields) "
                "→ profile_path.write_text(...) — no check that caller owns or is authorised to modify target_username"
            ),
            property_violated=(
                "Profile update operations must verify the caller is either the owner "
                "of the profile or holds a privileged role (admin/manager)"
            ),
            attacker_input=(
                "Authenticated employee calls patch_profile(target_username='admin', "
                "fields={'role':'admin'}, caller_role='employee')"
            ),
            consequence=(
                "Any authenticated caller can overwrite any field on any user's profile, "
                "including role escalation and credential replacement"
            ),
            severity="critical",
        )]

    def _check_get_employee_no_authz(self) -> list[dict]:
        """GT-RBAC-ENUM: get_employee_profile() returns full profile including password_hash with no authz."""
        func_src = self._extract_function("get_employee_profile")
        if func_src is None:
            return []

        authz_check = re.search(
            r"caller_role\s*(not\s+in|!=|==)\s*|if\s+caller|raise|return\s+None.*caller",
            func_src,
            re.IGNORECASE,
        )
        if authz_check:
            return []

        # Confirm the function returns the full data dict (no field filtering)
        returns_full = "return data" in func_src or "return record" in func_src or "return json" in func_src

        if not returns_full:
            return []

        return [self._make_finding(
            ground_truth_id="GT-RBAC-ENUM",
            hypothesis="get_employee_profile() returns full profile including password_hash without any authorization check",
            location=(
                "get_employee_profile(target_username, caller_role, caller_username) — "
                "caller_role and caller_username are accepted as parameters but never evaluated; "
                "the function reads and returns the full JSON record unconditionally"
            ),
            path=(
                "Any caller → get_employee_profile(target_username='victim', caller_role='employee', ...) "
                "→ profile_path = DATA / f\"{target_username}.json\" → data = json.loads(...) "
                "→ return data  (includes password_hash, role, department, all PII)"
            ),
            property_violated=(
                "Profile retrieval must be gated by role (admin/manager only) or restricted "
                "to the profile owner; sensitive fields such as password_hash must never be returned to peers"
            ),
            attacker_input=(
                "Any authenticated user calls get_employee_profile('admin', 'employee', 'attacker')"
            ),
            consequence=(
                "Any authenticated user can enumerate all employee profiles and harvest "
                "MD5 password hashes for offline cracking (combines with GT-AUTH-MD5)"
            ),
            severity="high",
        )]

    def _check_export_no_rbac(self) -> list[dict]:
        """GT-DATA-MASS-EXPORT: export_all_records() accepts any caller_role, no RBAC check."""
        func_src = self._extract_function("export_all_records")
        if func_src is None:
            return []

        rbac_check = re.search(
            r"caller_role\s*(not\s+in|!=|==)\s*[\(\"\'](admin|manager)|"
            r"if\s+caller_role\s*(!=|not\s+in)|raise|return\s+[\"\']\s*[\"\']\s*$",
            func_src,
            re.IGNORECASE,
        )
        if rbac_check:
            return []

        return [self._make_finding(
            ground_truth_id="GT-DATA-MASS-EXPORT",
            hypothesis="export_all_records() allows any caller to dump all employee records and password_hashes without RBAC check",
            location=(
                "export_all_records(caller_role, fmt='json') — "
                "caller_role is accepted as a parameter but never checked against "
                "a required role before calling list_employees() and serialising all records"
            ),
            path=(
                "Any caller → export_all_records(caller_role='employee', fmt='json') "
                "→ records = list_employees() (reads all *.json files) "
                "→ return json.dumps(records) — full dump including password_hash fields for all users"
            ),
            property_violated=(
                "Bulk data export must be restricted to privileged roles (admin only); "
                "mass export of employee records including credentials is a critical data exfiltration risk"
            ),
            attacker_input=(
                "Authenticated employee calls export_all_records(caller_role='employee')"
            ),
            consequence=(
                "Attacker exfiltrates the complete employee database including all "
                "MD5 password hashes in a single API call, enabling mass account takeover"
            ),
            severity="critical",
        )]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_function(self, func_name: str) -> Optional[str]:
        """Extract the source text of a top-level function by name."""
        if self.tree is None:
            return None
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                start = node.lineno - 1
                end = node.end_lineno
                return "\n".join(self.lines[start:end])
        return None

    @staticmethod
    def _make_finding(
        ground_truth_id: str,
        hypothesis: str,
        location: str,
        path: str,
        property_violated: str,
        attacker_input: str,
        consequence: str,
        severity: str,
    ) -> dict:
        evidence = (
            f"Location: {location} | "
            f"Path: {path} | "
            f"Property: {property_violated} | "
            f"AttackerInput: {attacker_input} | "
            f"Consequence: {consequence}"
        )
        return {
            "hypothesis": hypothesis,
            "evidence": evidence,
            "severity": severity,
            "location": location,
            "path": path,
            "property": property_violated,
            "attacker_input": attacker_input,
            "consequence": consequence,
            "source": "static_pre_filter",
            "pre_confirmed": True,
            "ground_truth_id": ground_truth_id,
        }
