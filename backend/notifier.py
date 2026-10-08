"""
Swarm Security Scanner — Outgoing Notification & Webhook Dispatcher
===================================================================
Sprint 2.2: Instant notifications for Slack, Discord, Microsoft Teams,
and custom security webhooks on scan completion and critical findings.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("swarm.notifier")


class NotificationConfig:
    def __init__(
        self,
        webhook_url: str,
        channel_type: str = "generic",  # "slack", "discord", "teams", "generic"
        enabled: bool = True,
        notify_on_critical: bool = True,
        notify_on_complete: bool = True,
    ):
        self.webhook_url = webhook_url
        self.channel_type = channel_type.lower()
        self.enabled = enabled
        self.notify_on_critical = notify_on_critical
        self.notify_on_complete = notify_on_complete

    def to_dict(self) -> dict:
        return {
            "webhook_url": self.webhook_url,
            "channel_type": self.channel_type,
            "enabled": self.enabled,
            "notify_on_critical": self.notify_on_critical,
            "notify_on_complete": self.notify_on_complete,
        }


def _send_payload(url: str, payload: dict) -> bool:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "Swarm-Notifier/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return resp.status in (200, 204)
    except Exception as e:
        logger.warning(f"Failed to send notification to {url}: {e}")
        return False


def format_slack_message(scan_data: dict, findings: list[dict]) -> dict:
    repo = scan_data.get("repo", "Unknown Repo")
    run_id = scan_data.get("run_id", "N/A")
    status = scan_data.get("status", "complete")
    crit_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")

    color = "#ef4444" if crit_count > 0 else ("#f97316" if high_count > 0 else "#34d399")
    status_icon = "🚨" if crit_count > 0 else ("⚠️" if high_count > 0 else "✅")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{status_icon} Swarm Scan Complete: {repo}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Run ID:*\n`{run_id}`"},
                {"type": "mrkdwn", "text": f"*Status:*\n{status.upper()}"},
                {"type": "mrkdwn", "text": f"*Critical Findings:*\n*{crit_count}*"},
                {"type": "mrkdwn", "text": f"*High Findings:*\n*{high_count}*"},
            ],
        },
    ]

    # Add top 3 critical findings
    if crit_count > 0:
        crit_findings = [f for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"][:3]
        for cf in crit_findings:
            title = cf.get("title", "Critical Vulnerability")
            file_loc = f"{cf.get('file', '?')}:{cf.get('line', '?')}"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"• *{title}*\n  `{file_loc}` — {cf.get('swarmRationale', '')[:120]}...",
                },
            })

    return {"attachments": [{"color": color, "blocks": blocks}]}


def format_discord_message(scan_data: dict, findings: list[dict]) -> dict:
    repo = scan_data.get("repo", "Unknown Repo")
    run_id = scan_data.get("run_id", "N/A")
    crit_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")

    color_int = 0xEF4444 if crit_count > 0 else (0xF97316 if high_count > 0 else 0x34D399)

    embed = {
        "title": f"🛡️ Swarm Security Scan Complete",
        "description": f"Security audit completed for **{repo}**",
        "color": color_int,
        "fields": [
            {"name": "Run ID", "value": f"`{run_id}`", "inline": True},
            {"name": "Criticals", "value": str(crit_count), "inline": True},
            {"name": "Highs", "value": str(high_count), "inline": True},
        ],
        "footer": {"text": "Swarm Security Scanner • Multi-Agent Consensus"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return {"embeds": [embed]}


def format_teams_message(scan_data: dict, findings: list[dict]) -> dict:
    repo = scan_data.get("repo", "Unknown Repo")
    run_id = scan_data.get("run_id", "N/A")
    crit_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH")

    theme_color = "EF4444" if crit_count > 0 else ("F97316" if high_count > 0 else "34D399")

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"Swarm Scan for {repo}",
        "themeColor": theme_color,
        "title": f"🛡️ Swarm Security Scan Complete: {repo}",
        "sections": [
            {
                "facts": [
                    {"name": "Run ID", "value": run_id},
                    {"name": "Critical Issues", "value": str(crit_count)},
                    {"name": "High Issues", "value": str(high_count)},
                    {"name": "Total TPs", "value": str(len(findings))},
                ],
                "text": f"Scanned repository {repo} via Swarm Multi-Agent consensus.",
            }
        ],
    }


def dispatch_scan_notification(
    config: NotificationConfig,
    scan_data: dict,
    findings: list[dict],
) -> bool:
    """Dispatch formatted notification to configured webhook destination."""
    if not config.enabled or not config.webhook_url:
        return False

    crit_count = sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL")
    if not config.notify_on_complete and (not config.notify_on_critical or crit_count == 0):
        return False

    ctype = config.channel_type
    if ctype == "slack":
        payload = format_slack_message(scan_data, findings)
    elif ctype == "discord":
        payload = format_discord_message(scan_data, findings)
    elif ctype == "teams":
        payload = format_teams_message(scan_data, findings)
    else:
        payload = {
            "event": "scan_complete",
            "scan": scan_data,
            "findings_count": len(findings),
            "critical_count": crit_count,
            "timestamp": time.time(),
        }

    return _send_payload(config.webhook_url, payload)
