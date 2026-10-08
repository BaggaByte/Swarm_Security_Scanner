"""
Swarm Security Scanner — Multi-Tenant SaaS Licensing & Quota Engine
===================================================================
Sprint 3.3: Enforces daily scan quotas, concurrency ceilings, and tier capabilities.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
from fastapi import HTTPException, status
from . import database as db

TIERS = {
    "community": {
        "name": "Community OSS",
        "daily_scan_limit": 5,
        "max_concurrent_scans": 1,
        "max_chunks": 50,
        "features": ["local_models", "sast_triage", "sarif_export"],
    },
    "team": {
        "name": "Team DevSecOps",
        "daily_scan_limit": 50,
        "max_concurrent_scans": 3,
        "max_chunks": 500,
        "features": ["local_models", "cloud_models", "webhooks", "rbac", "diff_scans", "sarif_export"],
    },
    "enterprise": {
        "name": "Enterprise Shield",
        "daily_scan_limit": 1000,
        "max_concurrent_scans": 10,
        "max_chunks": 0,  # Unlimited
        "features": ["all_models", "unlimited_scans", "webhooks", "rbac", "audit_logs", "custom_rules", "sandbox_exploit"],
    },
}

_SCAN_COUNTER: Dict[str, list[float]] = {}


def get_current_tier(api_key: Optional[str] = None) -> str:
    """Determine current active license tier from environment or API key."""
    import os
    env_tier = os.getenv("SWARM_LICENSE_TIER", "team").lower()
    return env_tier if env_tier in TIERS else "team"


def record_scan(key_id: str = "default"):
    """Record a scan timestamp for quota calculation."""
    now = time.time()
    if key_id not in _SCAN_COUNTER:
        _SCAN_COUNTER[key_id] = []
    # Prune timestamps older than 24 hours (86400s)
    _SCAN_COUNTER[key_id] = [t for t in _SCAN_COUNTER[key_id] if now - t < 86400]
    _SCAN_COUNTER[key_id].append(now)


def get_quota_status(key_id: str = "default", tier_name: Optional[str] = None) -> Dict[str, Any]:
    """Return current quota utilization for the active tier."""
    tier = tier_name or get_current_tier()
    tier_info = TIERS.get(tier, TIERS["team"])
    limit = tier_info["daily_scan_limit"]

    now = time.time()
    recent = [t for t in _SCAN_COUNTER.get(key_id, []) if now - t < 86400]
    used = len(recent)
    remaining = max(0, limit - used)

    return {
        "tier": tier,
        "tier_name": tier_info["name"],
        "daily_scan_limit": limit,
        "scans_used_24h": used,
        "scans_remaining_24h": remaining,
        "max_concurrent_scans": tier_info["max_concurrent_scans"],
        "features": tier_info["features"],
    }


def enforce_quota(key_id: str = "default", tier_name: Optional[str] = None):
    """Enforce quota limits, raising HTTP 429 if the daily limit is exhausted."""
    status_info = get_quota_status(key_id, tier_name)
    if status_info["scans_remaining_24h"] <= 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Daily scan quota exhausted for {status_info['tier_name']} "
                f"({status_info['scans_used_24h']}/{status_info['daily_scan_limit']} scans in 24h). "
                f"Upgrade to Enterprise tier for unlimited scans."
            ),
        )
