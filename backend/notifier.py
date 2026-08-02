"""SMTP-based alert notifier with per-source dedup + rate limiting.

- Reads SMTP config from env; if any required var is empty, sends are skipped
  gracefully (logged, not raised).
- Dedup key: {rule_id}:{fingerprint}:{hour_bucket}. Stored in `alert_notifications`
  with a TTL so entries auto-expire and future occurrences are re-notified.
- Severity floor: only sends >= ALERT_EMAIL_MIN_SEVERITY.
"""
import asyncio
import logging
import os
import smtplib
import ssl
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from typing import Iterable, List

logger = logging.getLogger("sentinelflow.notifier")

SEVERITY_RANK = {"Informational": 0, "Suspicious": 1, "Likely malicious": 2}


def _cfg():
    return {
        "host": os.environ.get("SMTP_HOST", "").strip(),
        "port": int(os.environ.get("SMTP_PORT", "587") or 587),
        "user": os.environ.get("SMTP_USER", "").strip(),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "from_addr": os.environ.get("SMTP_FROM", "").strip()
                     or os.environ.get("SMTP_USER", "").strip(),
        "use_tls": os.environ.get("SMTP_USE_TLS", "true").lower() != "false",
        "to": [e.strip() for e in os.environ.get("ALERT_EMAIL_TO", "").split(",") if e.strip()],
        "min_sev": os.environ.get("ALERT_EMAIL_MIN_SEVERITY", "Suspicious"),
        "dedup_hours": int(os.environ.get("ALERT_EMAIL_DEDUP_HOURS", "1") or 1),
    }


def is_enabled() -> bool:
    c = _cfg()
    return bool(c["host"] and c["from_addr"] and c["to"])


def _fingerprint(alert: dict) -> str:
    kf = alert.get("key_fields") or {}
    return (
        kf.get("src_ip") or kf.get("user") or kf.get("source")
        or (alert.get("evidence_event_ids") or [""])[0] or "-"
    )


def _dedup_key(alert: dict) -> str:
    hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    return f"{alert['rule_id']}:{_fingerprint(alert)}:{hour}"


def _send_sync(cfg: dict, msg: EmailMessage):
    if cfg["use_tls"]:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            if cfg["user"]:
                s.login(cfg["user"], cfg["password"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
            if cfg["user"]:
                s.login(cfg["user"], cfg["password"])
            s.send_message(msg)


def _build_message(cfg: dict, alert: dict) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = cfg["from_addr"]
    msg["To"] = ", ".join(cfg["to"])
    msg["Subject"] = f"[SentinelFlow · {alert['severity']}] {alert['rule_id']} — {alert['rule_name']}"
    text = (
        f"Rule:     {alert['rule_id']} · {alert['rule_name']}\n"
        f"Severity: {alert['severity']}\n"
        f"Time:     {alert['created_at']}\n\n"
        f"{alert['explanation']}\n\n"
        f"Recommended action (requires human approval):\n"
        f"  {alert['recommended_action']}\n\n"
        f"Evidence event ids: {', '.join(alert.get('evidence_event_ids') or []) or '-'}\n"
    )
    html = f"""
<html><body style="font-family:-apple-system,Segoe UI,sans-serif;background:#0A0B0E;color:#e5e7eb;padding:24px">
  <table cellpadding="0" cellspacing="0" style="width:100%;max-width:640px;margin:0 auto;background:#111318;border:1px solid #1F232B;border-radius:6px">
    <tr><td style="padding:20px 24px;border-bottom:1px solid #1F232B">
      <div style="font-family:JetBrains Mono,monospace;font-size:11px;letter-spacing:0.15em;text-transform:uppercase;color:#94a3b8">SentinelFlow · Alert</div>
      <div style="font-size:18px;font-weight:600;margin-top:6px">{alert['rule_id']} — {alert['rule_name']}</div>
      <div style="margin-top:8px">
        <span style="display:inline-block;padding:2px 8px;font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;
                     background:rgba(239,68,68,0.1);color:#f87171;border:1px solid rgba(239,68,68,0.25);border-radius:2px">{alert['severity']}</span>
      </div>
    </td></tr>
    <tr><td style="padding:18px 24px;font-size:14px;line-height:1.6">
      {alert['explanation']}
    </td></tr>
    <tr><td style="padding:12px 24px;border-top:1px solid #1F232B">
      <div style="font-family:JetBrains Mono,monospace;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;color:#f59e0b">Recommended action (human approval required)</div>
      <div style="margin-top:6px;font-size:13px;color:#e5e7eb">{alert['recommended_action']}</div>
    </td></tr>
    <tr><td style="padding:12px 24px;border-top:1px solid #1F232B;font-family:JetBrains Mono,monospace;font-size:11px;color:#94a3b8">
      Time: {alert['created_at']}<br/>
      Evidence: {', '.join(alert.get('evidence_event_ids') or []) or '-'}
    </td></tr>
  </table>
</body></html>
"""
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg


async def send_alert_email(db, alert: dict) -> str:
    """Return status: 'sent' | 'skipped:<reason>' | 'error:<msg>'."""
    cfg = _cfg()
    if not is_enabled():
        return "skipped:disabled"
    if SEVERITY_RANK.get(alert.get("severity"), 0) < SEVERITY_RANK.get(cfg["min_sev"], 1):
        return "skipped:below-min-severity"

    key = _dedup_key(alert)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=cfg["dedup_hours"])
    try:
        await db.alert_notifications.insert_one({
            "_id": key,
            "alert_id": alert["id"],
            "rule_id": alert["rule_id"],
            "created_at": now,
            "expires_at": expires,
        })
    except Exception:
        return "skipped:dedup"

    try:
        msg = _build_message(cfg, alert)
        await asyncio.to_thread(_send_sync, cfg, msg)
        logger.info("Sent alert email for %s (key=%s)", alert["id"], key)
        return "sent"
    except Exception as e:
        logger.warning("Email send failed for alert %s: %s", alert["id"], e)
        return f"error:{e.__class__.__name__}"


async def notify_alerts(db, alerts: Iterable[dict]) -> List[str]:
    return [await send_alert_email(db, a) for a in alerts]
