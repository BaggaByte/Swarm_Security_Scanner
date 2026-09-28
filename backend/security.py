"""
Swarm Security Scanner — Production Security & Validation Module
================================================================
Implements Defense-in-Depth controls:
  1. API Key Authentication (Bearer, X-API-Key, or Query Token for SSE)
  2. Strict Path Traversal and Local Directory Boundary Validation
  3. SSRF (Server-Side Request Forgery) Prevention for Git Clones
  4. Mandatory GitHub Webhook HMAC-SHA256 Signature Verification
  5. Target URL Validation for Exploit Sandboxing
"""

import os
import hmac
import hashlib
import ipaddress
import socket
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Security, Request, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials

# ---------------------------------------------------------------------------
# 1. API Key & Access Control
# ---------------------------------------------------------------------------

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
HTTP_BEARER = HTTPBearer(auto_error=False)

def get_configured_api_key() -> Optional[str]:
    return os.getenv("SWARM_API_KEY", "").strip() or None

async def require_api_key(
    request: Request,
    api_key_header: Optional[str] = Security(API_KEY_HEADER),
    bearer_auth: Optional[HTTPAuthorizationCredentials] = Security(HTTP_BEARER),
) -> str:
    """
    Enforces API authentication.
    Accepts:
      1. Header 'X-API-Key: <key>'
      2. Header 'Authorization: Bearer <key>'
      3. Query parameter '?token=<key>' or '?api_key=<key>' (for EventSource SSE)
    If SWARM_API_KEY is not set, checks SWARM_ALLOW_ANONYMOUS=true.
    If anonymous is NOT explicitly allowed, rejects with 401 Unauthorized.
    """
    expected_key = get_configured_api_key()
    allow_anonymous = os.getenv("SWARM_ALLOW_ANONYMOUS", "false").lower() in ("true", "1", "yes")

    if not expected_key:
        if allow_anonymous:
            return "anonymous"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: SWARM_API_KEY is enforced. Set SWARM_API_KEY in your environment or set SWARM_ALLOW_ANONYMOUS=true for local dev.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    provided_key = None
    if api_key_header:
        provided_key = api_key_header.strip()
    elif bearer_auth and bearer_auth.credentials:
        provided_key = bearer_auth.credentials.strip()
    elif "token" in request.query_params:
        provided_key = request.query_params.get("token", "").strip()
    elif "api_key" in request.query_params:
        provided_key = request.query_params.get("api_key", "").strip()

    if not provided_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide 'X-API-Key', 'Authorization: Bearer <token>', or '?token=' query parameter.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not hmac.compare_digest(provided_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return provided_key


# ---------------------------------------------------------------------------
# 2. SSRF Prevention & Git URL Validation
# ---------------------------------------------------------------------------

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmark testing
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6 blocks
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("fc00::/7"),            # Unique Local
    ipaddress.ip_network("fe80::/10"),           # Link-local
    ipaddress.ip_network("ff00::/8"),            # Multicast
]

def is_ip_blocked(ip_addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_addr)
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        return True

def validate_remote_git_url(url_str: str) -> str:
    """
    Validates a Git clone URL.
    - Requires HTTPS scheme.
    - Resolves hostname via DNS and ensures none of the IPs are private/loopback/cloud metadata.
    - Disallows credentials in URL (user:pass@host).
    """
    parsed = urlparse(url_str.strip())
    if parsed.scheme.lower() != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Git URL scheme '{parsed.scheme}'. Only 'https://' repositories are permitted for security.",
        )

    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Embedded user credentials in Git URLs are not permitted.",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Git URL: missing hostname.",
        )

    # Disallow literal private IPs in host
    try:
        if is_ip_blocked(hostname):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Access to private/internal network address '{hostname}' is blocked.",
            )
    except Exception:
        pass

    # Resolve hostname to check for SSRF
    try:
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        for entry in addr_info:
            ip_str = entry[4][0]
            if is_ip_blocked(ip_str):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Access to internal network address ({hostname} -> {ip_str}) is prohibited.",
                )
    except socket.gaierror:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to resolve hostname '{hostname}'.",
        )

    return url_str.strip()


# ---------------------------------------------------------------------------
# 3. Path Traversal & Scan Boundary Protection
# ---------------------------------------------------------------------------

SYSTEM_FORBIDDEN_PATHS = [
    "/etc", "/var", "/proc", "/sys", "/dev", "/root", "/boot",
    "c:\\windows", "c:\\program files", "c:\\program files (x86)",
    "c:\\boot", "c:\\recovery", "c:\\system volume information",
]

def validate_local_scan_path(path_str: str) -> str:
    """
    Resolves canonical path and validates against path traversal and system directories.
    Optionally enforces SWARM_ALLOWED_SCAN_ROOT.
    """
    clean_path = os.path.expanduser(path_str.strip())
    try:
        real_path = os.path.realpath(clean_path)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid directory path: {str(e)}",
        )

    clean_path_lower = clean_path.lower()
    real_path_lower = real_path.lower()
    for forbidden in SYSTEM_FORBIDDEN_PATHS:
        if (clean_path_lower == forbidden or clean_path_lower.startswith(forbidden + os.sep) or clean_path_lower.startswith(forbidden + "/") or
            real_path_lower == forbidden or real_path_lower.startswith(forbidden + os.sep) or real_path_lower.startswith(forbidden + "/")):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Scanning system or OS critical directories is strictly prohibited.",
            )

    # If an allowed root is set, require the path to be inside it
    allowed_root = os.getenv("SWARM_ALLOWED_SCAN_ROOT")
    if allowed_root:
        real_root = os.path.realpath(allowed_root)
        if not (real_path == real_root or real_path.startswith(real_root + os.sep)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scan path must reside within the designated scan root: '{real_root}'",
            )

    if not os.path.exists(real_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Specified repository path does not exist: {path_str}",
        )

    return real_path

def validate_scan_target(target: str) -> str:
    """
    Auto-detects whether the target is a remote Git URL or a local path and validates accordingly.
    """
    target_clean = target.strip()
    if target_clean.startswith(("http://", "https://", "git@", "ssh://", "file://")):
        return validate_remote_git_url(target_clean)
    return validate_local_scan_path(target_clean)


# ---------------------------------------------------------------------------
# 4. GitHub Webhook Signature Verification
# ---------------------------------------------------------------------------

def verify_github_webhook_signature(payload_bytes: bytes, signature_header: Optional[str]) -> None:
    """
    Enforces HMAC-SHA256 signature verification for GitHub webhooks.
    Raises 401 if missing or invalid.
    """
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "").strip()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook integration not configured: GITHUB_WEBHOOK_SECRET is not set.",
        )

    if not signature_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing 'X-Hub-Signature-256' signature header.",
        )

    if not signature_header.startswith("sha256="):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature format. Must start with 'sha256='.",
        )

    expected = "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook HMAC signature.",
        )


# ---------------------------------------------------------------------------
# 5. Exploit Sandbox Target URL Validation
# ---------------------------------------------------------------------------

ALLOWED_SANDBOX_TARGETS = [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://sandbox-target:5000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

def validate_sandbox_target_url(target_url: str) -> str:
    """
    Ensures exploit verification only targets isolated, explicitly permitted sandbox targets.
    """
    clean_url = target_url.strip().rstrip("/")

    # Check against allowed list or custom env
    custom_allowed = os.getenv("SWARM_ALLOWED_SANDBOX_TARGETS", "").split(",")
    valid_targets = [t.strip().rstrip("/") for t in custom_allowed if t.strip()] + ALLOWED_SANDBOX_TARGETS

    if clean_url not in valid_targets:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target URL '{clean_url}' is not in the sandbox target allowlist.",
        )

    return clean_url
