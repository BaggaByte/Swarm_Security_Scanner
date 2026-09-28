"""
User profile service for an internal HR portal.
Handles authentication, profile retrieval, updates, and user management.
"""
from pathlib import Path
import json
import hashlib
import time
import logging

logger = logging.getLogger(__name__)

BASE = Path(__file__).parent
DATA = BASE / "users"
DATA.mkdir(exist_ok=True)

SECRET_KEY = "hr-portal-internal-2024"

_attempt_log: dict = {}

VALID_ROLES = {"admin", "manager", "employee", "contractor"}


def login(username: str, password: str) -> dict | None:
    """Validate credentials and return a session payload, or None on failure."""
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    user_path = DATA / f"{username}.json"
    if not user_path.exists():
        logger.warning("Login failed: unknown user %s", username)
        return None
    record = json.loads(user_path.read_text())
    if record.get("password_hash") != pw_hash:
        logger.warning("Login failed: wrong password for %s", username)
        return None
    token = hashlib.md5(f"{username}:{time.time()}:{SECRET_KEY}".encode()).hexdigest()
    logger.info("Login success: %s", username)
    return {"username": username, "role": record.get("role", "employee"), "token": token}


def get_employee_profile(target_username: str, caller_role: str, caller_username: str) -> dict | None:
    """Return the full profile record for target_username."""
    profile_path = DATA / f"{target_username}.json"
    if not profile_path.exists():
        return None
    data = json.loads(profile_path.read_text())
    return data


def patch_profile(target_username: str, fields: dict, caller_role: str) -> bool:
    """Apply a partial update to a user's profile record."""
    profile_path = DATA / f"{target_username}.json"
    if not profile_path.exists():
        return False
    current = json.loads(profile_path.read_text())
    current.update(fields)
    profile_path.write_text(json.dumps(current, indent=2))
    logger.info("Profile updated: %s by role=%s", target_username, caller_role)
    return True


def list_employees(department: str = "") -> list:
    """Return all employee records, optionally filtered by department."""
    results = []
    for f in DATA.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            if not department or data.get("department") == department:
                results.append(data)
        except Exception:
            continue
    return results


def change_password(username: str, old_password: str, new_password: str) -> bool:
    """Allow a user to change their own password."""
    user_path = DATA / f"{username}.json"
    if not user_path.exists():
        return False
    record = json.loads(user_path.read_text())
    old_hash = hashlib.md5(old_password.encode()).hexdigest()
    if record.get("password_hash") != old_hash:
        return False
    record["password_hash"] = hashlib.md5(new_password.encode()).hexdigest()
    user_path.write_text(json.dumps(record, indent=2))
    return True


def promote_user(target_username: str, new_role: str, caller_role: str) -> bool:
    """Change the role of a user account."""
    if caller_role not in ("admin", "manager"):
        logger.warning("Unauthorised promote attempt by role=%s", caller_role)
        return False
    if new_role not in VALID_ROLES:
        return False
    user_path = DATA / f"{target_username}.json"
    if not user_path.exists():
        return False
    record = json.loads(user_path.read_text())
    record["role"] = new_role
    user_path.write_text(json.dumps(record, indent=2))
    return True


def remove_user(target_username: str, caller_role: str) -> bool:
    """Permanently remove a user account."""
    if caller_role != "admin":
        logger.error("Non-admin attempted to delete user %s", target_username)
        return False
    target = DATA / f"{target_username}.json"
    if target.exists():
        target.unlink()
        return True
    return False


def export_all_records(caller_role: str, fmt: str = "json") -> str:
    """Export all employee records in the requested format (json or csv)."""
    records = list_employees()
    if fmt == "csv":
        if not records:
            return ""
        headers = list(records[0].keys())
        lines = [",".join(headers)]
        for r in records:
            lines.append(",".join(str(r.get(h, "")) for h in headers))
        return "\n".join(lines)
    return json.dumps(records, indent=2)
