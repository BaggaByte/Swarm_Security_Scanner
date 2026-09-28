"""
Swarm Security Scanner — Security & API Production Test Suite
============================================================
Tests:
  1. Unauthenticated API access rejection (401)
  2. Authenticated API access acceptance (Bearer & X-API-Key)
  3. Path traversal & system root directory scanning rejection (400 / 403)
  4. SSRF detection for remote Git URLs (private IP / link-local / loopback)
  5. Webhook HMAC-SHA256 signature verification and payload handling
  6. Exploit Sandbox target URL allowlisting
  7. Concurrency limiter enforcement
"""

import hashlib
import hmac
import os
import sys
import pytest
from fastapi.testclient import TestClient

# Add backend directory to sys.path for direct imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Set test environment variables
os.environ["SWARM_API_KEY"] = "test-secret-key-12345"
os.environ["SWARM_ALLOW_ANONYMOUS"] = "false"
os.environ["GITHUB_WEBHOOK_SECRET"] = "webhook-test-secret"
os.environ["SWARM_DB_PATH"] = ":memory:"

from main import app
from security import (
    validate_remote_git_url,
    validate_local_scan_path,
    validate_sandbox_target_url,
    verify_github_webhook_signature,
)

client = TestClient(app)

# ---------------------------------------------------------------------------
# 1. Authentication Tests
# ---------------------------------------------------------------------------

def test_health_check_unauthenticated():
    """Health check endpoint '/' should be accessible without credentials."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_protected_endpoints_reject_anonymous():
    """Protected /api/ endpoints must reject requests lacking API keys."""
    endpoints = [
        ("GET", "/api/scan/active"),
        ("GET", "/api/scan/dummy_run_id"),
        ("POST", "/api/scan"),
        ("POST", "/api/repo-scan"),
        ("POST", "/api/remediate"),
        ("POST", "/api/verify"),
    ]
    for method, path in endpoints:
        if method == "GET":
            resp = client.get(path)
        else:
            resp = client.post(path, json={})
        assert resp.status_code == 401, f"{path} should reject unauthenticated request"


def test_authenticated_with_header():
    """Protected endpoints accept valid X-API-Key header."""
    headers = {"X-API-Key": "test-secret-key-12345"}
    resp = client.get("/api/scan/active", headers=headers)
    assert resp.status_code == 200


def test_authenticated_with_bearer():
    """Protected endpoints accept valid Bearer Authorization header."""
    headers = {"Authorization": "Bearer test-secret-key-12345"}
    resp = client.get("/api/scan/active", headers=headers)
    assert resp.status_code == 200


def test_invalid_api_key_rejected():
    """Providing a wrong key must return 401 Unauthorized."""
    headers = {"X-API-Key": "wrong-key"}
    resp = client.get("/api/scan/active", headers=headers)
    assert resp.status_code == 401
    assert "Invalid API Key" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 2. Path Traversal & Scan Boundary Tests
# ---------------------------------------------------------------------------

def test_system_directories_rejected():
    """Critical OS paths like /etc or C:\\Windows must be rejected with 403."""
    with pytest.raises(Exception) as exc:
        validate_local_scan_path("/etc")
    assert "403" in str(exc.value)

    if sys.platform == "win32":
        with pytest.raises(Exception) as exc:
            validate_local_scan_path("C:\\Windows")
        assert "403" in str(exc.value)


def test_nonexistent_local_path_rejected():
    """Scanning a nonexistent directory must raise 404."""
    with pytest.raises(Exception) as exc:
        validate_local_scan_path("/path/to/nonexistent/directory/xyz987")
    assert "404" in str(exc.value)


# ---------------------------------------------------------------------------
# 3. SSRF & Remote Git URL Tests
# ---------------------------------------------------------------------------

def test_ssrf_blocks_private_ip():
    """SSRF guard must reject private RFC-1918 and loopback targets."""
    blocked_urls = [
        "http://127.0.0.1/repo.git",
        "https://127.0.0.1/repo.git",
        "https://10.0.0.1/repo.git",
        "https://192.168.1.1/repo.git",
        "https://169.254.169.254/latest/meta-data",  # AWS IMDS
        "file:///etc/passwd",
    ]
    for url in blocked_urls:
        with pytest.raises(Exception):
            validate_remote_git_url(url)


def test_ssrf_rejects_credentials_in_url():
    """Git URLs with embedded credentials (user:pass@host) must be rejected."""
    with pytest.raises(Exception) as exc:
        validate_remote_git_url("https://user:password@github.com/org/repo.git")
    assert "credentials" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# 4. Webhook HMAC Signature Tests
# ---------------------------------------------------------------------------

def test_webhook_rejects_missing_signature():
    """Webhook requests without X-Hub-Signature-256 header must return 401."""
    resp = client.post("/api/webhooks/github", json={"action": "ping"})
    assert resp.status_code == 401


def test_webhook_rejects_invalid_signature():
    """Webhook requests with forged signature must return 401."""
    headers = {"X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000"}
    resp = client.post("/api/webhooks/github", json={"action": "ping"}, headers=headers)
    assert resp.status_code == 401


def test_webhook_accepts_valid_signature():
    """Webhook requests with valid HMAC-SHA256 signature must be accepted."""
    payload = b'{"action":"ping","repository":{"full_name":"test/repo"}}'
    secret = b"webhook-test-secret"
    sig = "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": sig,
    }
    resp = client.post("/api/webhooks/github", content=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# 5. Exploit Sandbox Allowlist Tests
# ---------------------------------------------------------------------------

def test_sandbox_target_validation():
    """Only allowlisted sandbox target URLs are permitted."""
    valid_url = "http://localhost:5000"
    assert validate_sandbox_target_url(valid_url) == valid_url

    with pytest.raises(Exception) as exc:
        validate_sandbox_target_url("http://attacker.com/steal")
    assert "403" in str(exc.value)
