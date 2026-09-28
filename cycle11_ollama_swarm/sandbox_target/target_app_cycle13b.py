"""
Cycle 13B – Hardened Clean Target Application
=============================================
User profile service for an internal HR portal.
Designed with standard secure coding practices and zero deliberately planted vulnerabilities.
Handles authentication, profile retrieval, updates, and user management.
"""
from pathlib import Path
import os
import re
import json
import hashlib
import hmac
import secrets
import time
import logging

logger = logging.getLogger(__name__)

import tempfile

BASE = Path(__file__).parent
def _get_data_dir() -> Path:
    candidates = [BASE / "users", Path(tempfile.gettempdir()) / "target_app_cycle13b_users"]
    for cand in candidates:
        try:
            cand.mkdir(parents=True, exist_ok=True)
            return cand
        except Exception:
            continue
    return Path(tempfile.gettempdir())

DATA = _get_data_dir()

# Secret key loaded from environment with secure fallback (never hardcoded in source)
SECRET_KEY = os.environ.get("HR_PORTAL_SECRET_KEY") or secrets.token_hex(32)

VALID_ROLES = {"admin", "manager", "employee", "contractor"}
SAFE_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")

# In-memory attempt log for brute-force protection: {username_or_ip: [(timestamp, success_bool)]}
_attempt_log: dict[str, list[float]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 300

# Session token store: {token: {"username": str, "role": str, "created_at": float, "expires_at": float}}
_active_sessions: dict[str, dict] = {}
SESSION_TTL_SECONDS = 3600


def _is_rate_limited(identifier: str) -> bool:
    """Check if identifier (e.g. username) exceeded max failed attempts in window."""
    now = time.time()
    attempts = _attempt_log.get(identifier, [])
    # Retain only recent failures within the lockout window
    recent_failures = [t for t in attempts if now - t < LOCKOUT_WINDOW_SECONDS]
    _attempt_log[identifier] = recent_failures
    return len(recent_failures) >= MAX_FAILED_ATTEMPTS


def _record_failed_attempt(identifier: str) -> None:
    """Record a failed login attempt."""
    now = time.time()
    attempts = _attempt_log.setdefault(identifier, [])
    attempts.append(now)


def _clear_failed_attempts(identifier: str) -> None:
    """Reset failed attempts on successful login."""
    _attempt_log.pop(identifier, None)


def _resolve_user_path(username: str) -> Path | None:
    """Safely validate username and resolve within the DATA directory, preventing path traversal."""
    if not isinstance(username, str) or not SAFE_USERNAME_RE.match(username):
        logger.warning("Rejected invalid username format: %r", username)
        return None

    user_path = (DATA / f"{username}.json").resolve()
    # Verify the resolved path stays strictly inside DATA directory
    try:
        user_path.relative_to(DATA.resolve())
    except ValueError:
        logger.error("Path traversal attempt detected for username: %r", username)
        return None

    return user_path


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """
    Hash password using PBKDF2-HMAC-SHA256 with a unique random salt (100,000 iterations).
    Returns (salt_hex, key_hex).
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return salt.hex(), key.hex()


def _verify_password(password: str, salt_hex: str, key_hex: str) -> bool:
    """Constant-time verification of password against stored PBKDF2 key."""
    try:
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        actual_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(actual_key, expected_key)
    except Exception:
        return False


def login(username: str, password: str) -> dict | None:
    """Validate credentials with brute-force protection and return a secure session payload."""
    if not isinstance(username, str) or not isinstance(password, str):
        return None

    if _is_rate_limited(username):
        logger.warning("Account temporarily locked due to repeated failed logins: %s", username)
        return None

    user_path = _resolve_user_path(username)
    if not user_path or not user_path.exists():
        _record_failed_attempt(username)
        logger.warning("Login failed: unknown user %s", username)
        # Dummy verification to mitigate timing attacks on user enumeration
        _verify_password("dummy", "00" * 16, "00" * 32)
        return None

    try:
        record = json.loads(user_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error("Failed to read user record for %s: %s", username, e)
        return None

    salt_hex = record.get("salt")
    key_hex = record.get("password_hash")
    if not salt_hex or not key_hex or not _verify_password(password, salt_hex, key_hex):
        _record_failed_attempt(username)
        logger.warning("Login failed: invalid password for %s", username)
        return None

    # Credentials are valid: clear failure history and issue CSPRNG session token
    _clear_failed_attempts(username)
    token = secrets.token_urlsafe(32)
    role = record.get("role", "employee")
    if role not in VALID_ROLES:
        role = "employee"

    now = time.time()
    _active_sessions[token] = {
        "username": username,
        "role": role,
        "created_at": now,
        "expires_at": now + SESSION_TTL_SECONDS,
    }

    logger.info("Login success: %s (role=%s)", username, role)
    return {"username": username, "role": role, "token": token}


def register_user(username: str, password: str, role: str = "employee", department: str = "") -> tuple[bool, str]:
    """Register a new user with strong password hashing and format validation."""
    if not isinstance(username, str) or not SAFE_USERNAME_RE.match(username):
        return False, "Invalid username format"
    if not isinstance(password, str) or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if role not in VALID_ROLES:
        return False, f"Invalid role: {role}"

    user_path = _resolve_user_path(username)
    if not user_path or user_path.exists():
        return False, "User already exists or invalid path"

    salt_hex, key_hex = _hash_password(password)
    record = {
        "username": username,
        "role": role,
        "department": department,
        "salt": salt_hex,
        "password_hash": key_hex,
        "created_at": time.time(),
    }
    try:
        user_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        return True, "User created successfully"
    except Exception as e:
        return False, f"Failed to save user: {e}"


def get_employee_profile(target_username: str, caller_role: str = "employee", caller_username: str = "") -> dict | None:
    """
    Return sanitized profile record for target_username with strict authorization checks.
    Only administrators, managers, or the user themselves may view the full profile.
    """
    if caller_role not in VALID_ROLES:
        logger.warning("Unauthorized access attempt with invalid caller_role: %r", caller_role)
        return None

    # Enforce IDOR / authorization boundaries
    if caller_role not in ("admin", "manager") and caller_username != target_username:
        logger.warning(
            "Access denied: %s (role=%s) cannot view profile of %s",
            caller_username, caller_role, target_username
        )
        return None

    profile_path = _resolve_user_path(target_username)
    if not profile_path or not profile_path.exists():
        return None

    try:
        data = json.loads(profile_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error("Error reading profile %s: %s", target_username, e)
        return None

    # Redact sensitive security fields before returning
    data.pop("password_hash", None)
    data.pop("salt", None)
    return data


def patch_profile(target_username: str, fields: dict, caller_role: str, caller_username: str) -> bool:
    """
    Apply a partial update to a profile with strict ownership and field-whitelisting guards.
    Callers may only modify their own profile unless they have the admin role.
    """
    if caller_role not in VALID_ROLES or not isinstance(fields, dict):
        return False

    # Enforce ownership check
    if caller_role != "admin" and caller_username != target_username:
        logger.warning(
            "Forbidden patch attempt: %s cannot update %s",
            caller_username, target_username
        )
        return False

    profile_path = _resolve_user_path(target_username)
    if not profile_path or not profile_path.exists():
        return False

    try:
        current = json.loads(profile_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error("Error loading profile %s: %s", target_username, e)
        return False

    # Whitelist allowed mutable fields (disallow altering role, credentials, or system state)
    ALLOWED_MUTABLE_FIELDS = {"display_name", "phone", "bio", "department"}
    sanitized_updates = {
        k: v for k, v in fields.items()
        if k in ALLOWED_MUTABLE_FIELDS and isinstance(v, (str, int, float, bool))
    }

    if not sanitized_updates:
        logger.info("No valid whitelist fields provided for patch on %s", target_username)
        return False

    current.update(sanitized_updates)
    try:
        profile_path.write_text(json.dumps(current, indent=2), encoding="utf-8")
        logger.info("Profile updated: %s by %s (role=%s)", target_username, caller_username, caller_role)
        return True
    except Exception as e:
        logger.error("Failed to write updated profile for %s: %s", target_username, e)
        return False


def list_employees(department: str = "", caller_role: str = "employee", limit: int = 50, offset: int = 0) -> list:
    """
    Return employee records with pagination and credential redaction.
    """
    if caller_role not in VALID_ROLES:
        return []

    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    results = []
    all_files = sorted(DATA.glob("*.json"))
    for f in all_files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if not department or data.get("department") == department:
                # Strip internal security credentials
                data.pop("password_hash", None)
                data.pop("salt", None)
                results.append(data)
        except Exception:
            continue

    # Apply pagination
    return results[offset:offset + limit]


def change_password(username: str, old_password: str, new_password: str, caller_username: str) -> bool:
    """Allow a user to change their own password with validation and constant-time verification."""
    if not isinstance(username, str) or caller_username != username:
        logger.warning("Unauthorized password change attempt on %s by %s", username, caller_username)
        return False

    if not isinstance(new_password, str) or len(new_password) < 8:
        logger.warning("Rejected new password: fails minimum length policy for %s", username)
        return False

    user_path = _resolve_user_path(username)
    if not user_path or not user_path.exists():
        return False

    try:
        record = json.loads(user_path.read_text(encoding="utf-8"))
    except Exception:
        return False

    salt_hex = record.get("salt")
    key_hex = record.get("password_hash")
    if not salt_hex or not key_hex or not _verify_password(old_password, salt_hex, key_hex):
        logger.warning("Change password failed: invalid old password for %s", username)
        return False

    # Generate new random salt and key
    new_salt_hex, new_key_hex = _hash_password(new_password)
    record["salt"] = new_salt_hex
    record["password_hash"] = new_key_hex

    try:
        user_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        logger.info("Password successfully changed for %s", username)
        return True
    except Exception as e:
        logger.error("Failed saving new password for %s: %s", username, e)
        return False


def promote_user(target_username: str, new_role: str, caller_role: str) -> bool:
    """Change the role of a user account. Strictly restricted to admin callers."""
    if caller_role != "admin":
        logger.warning("Unauthorized promote attempt by role=%s for %s", caller_role, target_username)
        return False

    if new_role not in VALID_ROLES:
        logger.warning("Invalid new role specified: %r", new_role)
        return False

    user_path = _resolve_user_path(target_username)
    if not user_path or not user_path.exists():
        return False

    try:
        record = json.loads(user_path.read_text(encoding="utf-8"))
        record["role"] = new_role
        user_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        logger.info("User %s promoted to %s by admin", target_username, new_role)
        return True
    except Exception as e:
        logger.error("Error promoting user %s: %s", target_username, e)
        return False


def remove_user(target_username: str, caller_role: str) -> bool:
    """Permanently remove a user account. Strictly restricted to admin callers."""
    if caller_role != "admin":
        logger.error("Non-admin (role=%s) attempted to delete user %s", caller_role, target_username)
        return False

    target = _resolve_user_path(target_username)
    if not target or not target.exists():
        return False

    try:
        target.unlink()
        logger.info("User %s deleted by admin", target_username)
        return True
    except Exception as e:
        logger.error("Failed to delete user %s: %s", target_username, e)
        return False


def export_all_records(caller_role: str, fmt: str = "json") -> str:
    """Export all employee records. Strictly restricted to admin callers."""
    if caller_role != "admin":
        logger.warning("Unauthorized bulk export attempt by role=%s", caller_role)
        return ""

    records = list_employees(caller_role="admin", limit=1000)
    if fmt == "csv":
        if not records:
            return ""
        headers = list(records[0].keys())
        lines = [",".join(headers)]
        for r in records:
            lines.append(",".join(str(r.get(h, "")) for h in headers))
        return "\n".join(lines)

    return json.dumps(records, indent=2)
