"""Slack + Microsoft Teams webhook dispatcher.

Per-user configuration. Reuses the existing alert_notifications dedup
collection so users don't get spammed for the same repeating event.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Iterable, List, Optional

import httpx

logger = logging.getLogger("sentinelflow.webhooks")

SEV_RANK = {"Informational": 0, "Suspicious": 1, "Likely malicious": 2}
SEV_COLOR = {
    "Informational": "0891b2",
    "Suspicious": "d97706",
    "Likely malicious": "dc2626",
}


def detect_type(url: str) -> str:
    u = (url or "").lower()
    if "office.com" in u or "webhook.office.com" in u or "outlook.office" in u or "teams.microsoft" in u:
        return "teams"
    return "slack"


def slack_payload(alert: dict) -> dict:
    return {
        "text": f":rotating_light: *SentinelFlow · {alert['severity']}* — {alert['rule_id']} {alert['rule_name']}",
        "attachments": [{
            "color": {"Likely malicious": "danger", "Suspicious": "warning",
                      "Informational": "#06b6d4"}.get(alert["severity"], "#06b6d4"),
            "fields": [
                {"title": "Explanation", "value": alert["explanation"], "short": False},
                {"title": "Recommended action (requires human approval)",
                 "value": alert["recommended_action"], "short": False},
                {"title": "Time", "value": alert["created_at"], "short": True},
                {"title": "Evidence", "value": ", ".join(alert.get("evidence_event_ids") or []) or "—",
                 "short": True},
            ],
        }],
    }


def teams_payload(alert: dict) -> dict:
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": SEV_COLOR.get(alert["severity"], "6366f1"),
        "summary": f"SentinelFlow · {alert['severity']} · {alert['rule_id']}",
        "title": f"SentinelFlow · {alert['severity']} · {alert['rule_id']} {alert['rule_name']}",
        "sections": [{
            "text": alert["explanation"],
            "facts": [
                {"name": "Recommended action", "value": alert["recommended_action"]},
                {"name": "Time", "value": alert["created_at"]},
                {"name": "Evidence", "value": ", ".join(alert.get("evidence_event_ids") or []) or "—"},
            ],
            "markdown": True,
        }],
    }


async def send_webhook(url: str, kind: str, alert: dict) -> str:
    payload = teams_payload(alert) if kind == "teams" else slack_payload(alert)
    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            r = await client.post(url, json=payload)
            if r.status_code >= 300:
                logger.warning("webhook %s -> %s: %s", kind, r.status_code, r.text[:200])
                return f"error:{r.status_code}"
            return "sent"
        except Exception as e:
            logger.warning("webhook send failed: %s", e)
            return f"error:{e.__class__.__name__}"


def _fingerprint(alert: dict) -> str:
    kf = alert.get("key_fields") or {}
    return (
        kf.get("src_ip") or kf.get("user") or kf.get("source")
        or (alert.get("evidence_event_ids") or [""])[0] or "-"
    )


async def dispatch_alert_to_users(db, alert: dict) -> List[dict]:
    """For each user with webhook_enabled, dedup + send.

    Returns list of {user, status}.
    """
    users = await db.users.find(
        {"notification_prefs.webhook_enabled": True,
         "notification_prefs.webhook_url": {"$ne": ""}},
        {"email": 1, "notification_prefs": 1},
    ).to_list(500)
    if not users:
        return []
    now = datetime.now(timezone.utc)
    hour = now.strftime("%Y%m%d%H")
    out: List[dict] = []
    for u in users:
        prefs = u.get("notification_prefs") or {}
        min_sev = prefs.get("webhook_min_severity", "Suspicious")
        if SEV_RANK.get(alert.get("severity"), 0) < SEV_RANK.get(min_sev, 1):
            out.append({"user": u.get("email"), "status": "skipped:below-min"})
            continue
        key = f"wh:{alert['rule_id']}:{_fingerprint(alert)}:{hour}:{u['email']}"
        try:
            await db.alert_notifications.insert_one({
                "_id": key,
                "alert_id": alert["id"],
                "user": u["email"],
                "channel": "webhook",
                "created_at": now,
                "expires_at": now + timedelta(hours=int(prefs.get("webhook_dedup_hours") or 1)),
            })
        except Exception:
            out.append({"user": u.get("email"), "status": "skipped:dedup"})
            continue
        url = prefs.get("webhook_url", "")
        kind = prefs.get("webhook_type") or detect_type(url)
        status = await send_webhook(url, kind, alert)
        out.append({"user": u.get("email"), "status": status})
    return out


async def dispatch_alerts(db, alerts: Iterable[dict]) -> List[dict]:
    results: List[dict] = []
    for a in alerts:
        results.extend(await dispatch_alert_to_users(db, a))
    return results


async def send_test(url: str, kind: Optional[str] = None) -> str:
    dummy = {
        "id": "test-alert",
        "rule_id": "R000",
        "rule_name": "SentinelFlow test message",
        "severity": "Suspicious",
        "explanation": "This is a test notification from SentinelFlow. If you can read this, webhook delivery is working.",
        "recommended_action": "No action required — configuration test.",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "evidence_event_ids": [],
    }
    return await send_webhook(url, kind or detect_type(url), dummy)
