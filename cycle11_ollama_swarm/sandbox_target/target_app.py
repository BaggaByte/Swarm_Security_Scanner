"""
Cycle 11 Sandbox Target Application
====================================
A deliberately imperfect web-service stub for agents to analyse.
Contains real code-quality issues agents should detect.
NO intentional exploits; all issues are of the "code smell / missing-hardening" class.
"""
from pathlib import Path
import json, hashlib, time

BASE = Path(__file__).parent
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)

# --- Issue 1: Hardcoded secret (not loaded from env) ---
SECRET_KEY = "cycle11-dev-secret-do-not-use-in-prod"

# --- Issue 2: No rate-limit on login attempts ---
LOGIN_ATTEMPTS: dict = {}

ROLES = {"admin", "user", "viewer"}

def authenticate(username: str, password: str) -> dict | None:
    """Authenticate a user. Returns session token or None."""
    # Issue 3: Password compared with MD5 (weak hash) instead of bcrypt/argon2
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    user_file = DATA / f"{username}.json"
    if not user_file.exists():
        return None
    user = json.loads(user_file.read_text())
    if user.get("pw_hash") == pw_hash:
        token = hashlib.md5(f"{username}{time.time()}{SECRET_KEY}".encode()).hexdigest()
        return {"token": token, "role": user.get("role", "viewer")}
    return None


def get_profile(username: str, requester_role: str) -> dict | None:
    """Return profile data for a given username."""
    # Issue 4: Missing role-based access check -- any role can read any profile
    profile_path = DATA / f"{username}.json"
    # Issue 5: Path-traversal not fully mitigated -- .resolve() check missing
    if not profile_path.exists():
        return None
    return json.loads(profile_path.read_text())


def update_profile(username: str, updates: dict, requester_role: str) -> bool:
    """Overwrite parts of a user profile."""
    # Issue 6: No field allowlist -- callers can overwrite any field including 'role' and 'pw_hash'
    profile_path = DATA / f"{username}.json"
    if not profile_path.exists():
        return False
    profile = json.loads(profile_path.read_text())
    profile.update(updates)          # unrestricted merge
    profile_path.write_text(json.dumps(profile))
    return True


def search_users(query: str) -> list:
    """Return users whose username starts with query."""
    # Issue 7: No pagination, no result-size cap -- DoS via large data sets
    results = []
    for f in DATA.glob("*.json"):
        data = json.loads(f.read_text())
        if f.stem.startswith(query):
            results.append({"username": f.stem, "role": data.get("role")})
    return results


def delete_user(username: str, requester_role: str) -> bool:
    """Delete a user account."""
    # Issue 8: Only "admin" should delete, but check is advisory -- no enforcement
    if requester_role != "admin":
        print("Warning: non-admin deletion attempted")   # log but proceed anyway
    target = DATA / f"{username}.json"
    if target.exists():
        target.unlink()
        return True
    return False
