"""Shared allowlist and address policy for remote repository URLs."""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


DEFAULT_ALLOWED_GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


def allowed_git_hosts() -> set[str]:
    configured = os.getenv("SWARM_ALLOWED_GIT_HOSTS", "")
    hosts = {host.strip().rstrip(".").lower() for host in configured.split(",") if host.strip()}
    return hosts or DEFAULT_ALLOWED_GIT_HOSTS


def validate_git_url(url: str) -> str:
    """Validate an HTTPS Git URL against configured hosts and public DNS answers."""
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS Git URLs are permitted")
    if parsed.username or parsed.password:
        raise ValueError("Credentials embedded in Git URLs are not permitted")

    try:
        hostname = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Git URL has an invalid hostname") from exc
    if not hostname:
        raise ValueError("Git URL is missing a hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Git URL has an invalid port") from exc
    if port not in (None, 443):
        raise ValueError("Git URLs must use HTTPS port 443")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("Git URL host must be an allowlisted DNS name, not an IP address")

    if hostname not in allowed_git_hosts():
        raise ValueError(f"Git host '{hostname}' is not in SWARM_ALLOWED_GIT_HOSTS")

    try:
        answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve Git host '{hostname}'") from exc
    if not answers:
        raise ValueError(f"Git host '{hostname}' did not resolve")

    for answer in answers:
        address = ipaddress.ip_address(answer[4][0])
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global:
            raise ValueError("Git host resolves to a non-public IP address")

    return url.strip()
