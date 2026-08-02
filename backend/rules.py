"""SentinelFlow rule-based detection engine.

Every rule returns a list of alerts. Every alert cites raw evidence
(list of normalized event_ids) and includes a human-readable explanation.
"""
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import uuid

# Static blocklist of "known malicious" IPs for MVP
MALICIOUS_IPS = {
    "185.220.101.1", "185.220.102.4", "45.155.205.233",
    "104.244.72.115", "23.129.64.216", "192.42.116.16",
}

# Static country allowlist. For MVP, "unusual country" = anything not in this set.
ALLOWED_COUNTRIES = {"US"}

# Working hours (local server hour) — outside is "off-hours"
WORK_HOUR_START = 8
WORK_HOUR_END = 20

RULES_META = [
    {
        "rule_id": "R001",
        "name": "Brute-force login attempts",
        "condition": "N failed logins from the same source IP within T minutes",
        "threshold": 5,
        "window_minutes": 5,
        "severity": "Likely malicious",
        "template": "IP {src_ip} generated {count} failed logins within {window} minutes — exceeds threshold of {threshold}. Possible brute-force.",
    },
    {
        "rule_id": "R002",
        "name": "Success after repeated failures",
        "condition": "Successful login from same source that just failed >= threshold times",
        "threshold": 3,
        "window_minutes": 10,
        "severity": "Likely malicious",
        "template": "IP {src_ip} had {count} failed logins against user {user} then a successful login at {when} — possible credential compromise.",
    },
    {
        "rule_id": "R003",
        "name": "Off-hours or unusual-country login",
        "condition": "Successful login outside working hours (08:00–20:00) or from a country not in the allowlist",
        "threshold": 1,
        "window_minutes": 0,
        "severity": "Suspicious",
        "template": "User {user} logged in from {src_ip} ({country}) at {when} — outside working hours or from unusual location.",
    },
    {
        "rule_id": "R004",
        "name": "Privilege escalation / security config change",
        "condition": "Event action contains 'privilege_escalation' or 'security_config_change'",
        "threshold": 1,
        "window_minutes": 0,
        "severity": "Likely malicious",
        "template": "User {user} performed {action} on host {host} at {when} — sensitive administrative change.",
    },
    {
        "rule_id": "R005",
        "name": "Known malicious IP match",
        "condition": "Any event with src_ip in the static blocklist",
        "threshold": 1,
        "window_minutes": 0,
        "severity": "Likely malicious",
        "template": "Traffic observed from known malicious IP {src_ip} to {dst_ip} at {when} — static blocklist match.",
    },
    {
        "rule_id": "R006",
        "name": "Log source silent",
        "condition": "No events received from a log source in the last 30 minutes",
        "threshold": 0,
        "window_minutes": 30,
        "severity": "Suspicious",
        "template": "Log source '{source}' has been silent for {minutes} minutes — possible outage or tampering.",
    },
    {
        "rule_id": "R007",
        "name": "Excessive API requests / rate anomaly",
        "condition": "N or more web requests from the same source IP within T minutes",
        "threshold": 120,
        "window_minutes": 1,
        "severity": "Suspicious",
        "template": "IP {src_ip} issued {count} web requests within {window} minute(s) — exceeds threshold of {threshold}. Possible scraping, credential stuffing, or DoS.",
    },
    {
        "rule_id": "R008",
        "name": "Injection pattern in URL",
        "condition": "URL contains SQL-injection, XSS, or directory-traversal signatures",
        "threshold": 1,
        "window_minutes": 0,
        "severity": "Likely malicious",
        "template": "Request from {src_ip} to {url} matched {pattern_class} pattern '{pattern}' at {when} — probable exploitation attempt.",
    },
    {
        "rule_id": "R009",
        "name": "New-device admin login",
        "condition": "Successful login by an admin user from an (IP, user-agent) fingerprint never seen before for that user",
        "threshold": 1,
        "window_minutes": 0,
        "severity": "Suspicious",
        "template": "Admin user {user} logged in from a new device fingerprint {src_ip} · {user_agent} at {when} — verify the login was expected.",
    },
    {
        "rule_id": "R010",
        "name": "Blocklisted IP (analyst-approved)",
        "condition": "Source IP appears on the internal blocklist maintained by analyst-approved actions",
        "threshold": 1,
        "window_minutes": 0,
        "severity": "Likely malicious",
        "template": "Traffic observed from {src_ip} which is on the internal blocklist (approved by {approver} for {reason}) — repeat attempt at {when}.",
    },
]


def _new_alert(rule: Dict[str, Any], explanation: str, evidence_ids: List[str],
               severity: str, key_fields: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "rule_id": rule["rule_id"],
        "rule_name": rule["name"],
        "severity": severity,
        "status": "New",
        "explanation": explanation,
        "evidence_event_ids": evidence_ids,
        "key_fields": key_fields,
        "recommended_action": _recommended_action(rule["rule_id"]),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "assigned_to": None,
        "notes": [],
    }


def _recommended_action(rule_id: str) -> str:
    return {
        "R001": "Review source IP reputation. Consider temporary IP block after human approval.",
        "R002": "Force password reset for the impacted account. Review session activity.",
        "R003": "Contact user to confirm activity. Enable step-up MFA if not yet enabled.",
        "R004": "Verify change was authorized. Roll back if unapproved.",
        "R005": "Isolate affected host. Review lateral movement. Approve firewall block manually.",
        "R006": "Verify agent/collector health. Check network path and disk usage.",
        "R007": "Apply WAF rate-limit rule for this IP after human review. Check for scraping or abuse.",
        "R008": "Block the request pattern at the WAF (human-approved). Audit vulnerable endpoint code.",
        "R009": "Contact the admin user out-of-band. Force MFA re-enrollment if login not recognized.",
        "R010": "Escalate to incident. This IP was previously blocked by an analyst — the blocklist is holding, verify no bypass.",
    }[rule_id]


def _get(rule_id: str) -> Dict[str, Any]:
    for r in RULES_META:
        if r["rule_id"] == rule_id:
            return r
    raise KeyError(rule_id)


def detect_brute_force(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule = _get("R001")
    window = timedelta(minutes=rule["window_minutes"])
    threshold = rule["threshold"]
    by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("app") == "auth" and e.get("http_status") in ("fail", "failure", "401", 401) \
                and e.get("src_ip"):
            by_ip[e["src_ip"]].append(e)
    alerts = []
    for ip, ev_list in by_ip.items():
        ev_list.sort(key=lambda x: x["timestamp"])
        for i in range(len(ev_list)):
            window_evts = [ev_list[i]]
            for j in range(i + 1, len(ev_list)):
                t_i = datetime.fromisoformat(ev_list[i]["timestamp"])
                t_j = datetime.fromisoformat(ev_list[j]["timestamp"])
                if t_j - t_i <= window:
                    window_evts.append(ev_list[j])
                else:
                    break
            if len(window_evts) >= threshold:
                evidence = [e["event_id"] for e in window_evts]
                explanation = rule["template"].format(
                    src_ip=ip, count=len(window_evts),
                    window=rule["window_minutes"], threshold=threshold,
                )
                alerts.append(_new_alert(
                    rule, explanation, evidence, rule["severity"],
                    {"src_ip": ip, "count": len(window_evts)},
                ))
                break  # one alert per IP
    return alerts


def detect_success_after_fail(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule = _get("R002")
    window = timedelta(minutes=rule["window_minutes"])
    threshold = rule["threshold"]
    alerts = []
    # Group by (src_ip, user)
    grouped: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("app") == "auth" and e.get("src_ip") and e.get("user"):
            grouped[(e["src_ip"], e["user"])].append(e)
    for (ip, user), ev in grouped.items():
        ev.sort(key=lambda x: x["timestamp"])
        for idx, evt in enumerate(ev):
            if str(evt.get("http_status")) in ("success", "200", "ok"):
                # look at prior failures within window
                failures = []
                for prev in ev[:idx]:
                    t_e = datetime.fromisoformat(evt["timestamp"])
                    t_p = datetime.fromisoformat(prev["timestamp"])
                    if t_e - t_p <= window and str(prev.get("http_status")) in ("fail", "failure", "401"):
                        failures.append(prev)
                if len(failures) >= threshold:
                    evidence = [e["event_id"] for e in failures] + [evt["event_id"]]
                    explanation = rule["template"].format(
                        src_ip=ip, count=len(failures), user=user,
                        when=evt["timestamp"],
                    )
                    alerts.append(_new_alert(
                        rule, explanation, evidence, rule["severity"],
                        {"src_ip": ip, "user": user, "failures": len(failures)},
                    ))
    return alerts


def detect_off_hours_or_unusual_country(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule = _get("R003")
    alerts = []
    for e in events:
        if e.get("app") != "auth":
            continue
        if str(e.get("http_status")) not in ("success", "200", "ok"):
            continue
        ts = datetime.fromisoformat(e["timestamp"])
        hour = ts.hour
        off_hours = hour < WORK_HOUR_START or hour >= WORK_HOUR_END
        country = (e.get("country") or "").upper()
        unusual_country = bool(country) and country not in ALLOWED_COUNTRIES
        if off_hours or unusual_country:
            reason_bits = []
            if off_hours:
                reason_bits.append(f"hour {hour:02d}:00 outside {WORK_HOUR_START}:00–{WORK_HOUR_END}:00")
            if unusual_country:
                reason_bits.append(f"country {country} not in allowlist")
            explanation = rule["template"].format(
                user=e.get("user"), src_ip=e.get("src_ip"),
                country=country or "unknown", when=e["timestamp"],
            ) + " (" + "; ".join(reason_bits) + ")"
            alerts.append(_new_alert(
                rule, explanation, [e["event_id"]], rule["severity"],
                {"user": e.get("user"), "src_ip": e.get("src_ip"),
                 "country": country, "hour": hour},
            ))
    return alerts


def detect_priv_escalation(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule = _get("R004")
    alerts = []
    trigger_terms = {"privilege_escalation", "security_config_change",
                     "sudo", "role_grant", "policy_change"}
    for e in events:
        action = (e.get("action") or "").lower()
        if any(term in action for term in trigger_terms):
            explanation = rule["template"].format(
                user=e.get("user") or "unknown",
                action=action or "config-change",
                host=e.get("host") or "unknown",
                when=e["timestamp"],
            )
            alerts.append(_new_alert(
                rule, explanation, [e["event_id"]], rule["severity"],
                {"user": e.get("user"), "action": action, "host": e.get("host")},
            ))
    return alerts


def detect_malicious_ip(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule = _get("R005")
    alerts = []
    for e in events:
        if e.get("src_ip") in MALICIOUS_IPS:
            explanation = rule["template"].format(
                src_ip=e["src_ip"], dst_ip=e.get("dst_ip") or "unknown",
                when=e["timestamp"],
            )
            alerts.append(_new_alert(
                rule, explanation, [e["event_id"]], rule["severity"],
                {"src_ip": e["src_ip"], "dst_ip": e.get("dst_ip")},
            ))
    return alerts


async def detect_silent_sources(db) -> List[Dict[str, Any]]:
    """Run this on a schedule. For MVP, run at ingest time and on demand."""
    rule = _get("R006")
    alerts = []
    threshold_min = rule["window_minutes"]
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=threshold_min)
    sources = await db.log_sources.find({}).to_list(1000)
    for src in sources:
        last_seen = src.get("last_event_at")
        if last_seen is None:
            continue
        if isinstance(last_seen, str):
            last_seen_dt = datetime.fromisoformat(last_seen)
        else:
            last_seen_dt = last_seen
        # normalize tz
        if last_seen_dt.tzinfo is None:
            last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
        if last_seen_dt < cutoff:
            silent_min = int((datetime.now(timezone.utc) - last_seen_dt).total_seconds() // 60)
            explanation = rule["template"].format(
                source=src["name"], minutes=silent_min,
            )
            alerts.append(_new_alert(
                rule, explanation, [], rule["severity"],
                {"source": src["name"], "silent_minutes": silent_min},
            ))
    return alerts


def run_all_rules(events: List[Dict[str, Any]],
                  blocklist: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Run all synchronous rules (R001–R005, R007, R008, R010) over a batch of events.
    `blocklist` maps ip -> {reason, approver, ...} for R010."""
    alerts = (
        detect_brute_force(events)
        + detect_success_after_fail(events)
        + detect_off_hours_or_unusual_country(events)
        + detect_priv_escalation(events)
        + detect_malicious_ip(events)
        + detect_rate_anomaly(events)
        + detect_injection_patterns(events)
    )
    if blocklist:
        alerts += detect_blocklisted(events, blocklist)
    return alerts


def detect_blocklisted(events: List[Dict[str, Any]],
                       blocklist: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule = _get("R010")
    alerts = []
    seen_ips = set()  # one alert per (ip, batch)
    for e in events:
        ip = e.get("src_ip")
        if not ip or ip not in blocklist or ip in seen_ips:
            continue
        seen_ips.add(ip)
        info = blocklist[ip]
        explanation = rule["template"].format(
            src_ip=ip,
            approver=info.get("created_by", "an analyst"),
            reason=info.get("reason", "prior alert"),
            when=e["timestamp"],
        )
        alerts.append(_new_alert(
            rule, explanation, [e["event_id"]], rule["severity"],
            {"src_ip": ip, "block_reason": info.get("reason")},
        ))
    return alerts


# -------------------- R007: Rate anomaly --------------------

def detect_rate_anomaly(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule = _get("R007")
    window = timedelta(minutes=rule["window_minutes"])
    threshold = rule["threshold"]
    by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("app") == "web" and e.get("src_ip"):
            by_ip[e["src_ip"]].append(e)
    alerts = []
    for ip, ev_list in by_ip.items():
        ev_list.sort(key=lambda x: x["timestamp"])
        for i in range(len(ev_list)):
            window_evts = [ev_list[i]]
            for j in range(i + 1, len(ev_list)):
                t_i = datetime.fromisoformat(ev_list[i]["timestamp"])
                t_j = datetime.fromisoformat(ev_list[j]["timestamp"])
                if t_j - t_i <= window:
                    window_evts.append(ev_list[j])
                else:
                    break
            if len(window_evts) >= threshold:
                evidence = [e["event_id"] for e in window_evts[:20]]  # cap
                explanation = rule["template"].format(
                    src_ip=ip, count=len(window_evts),
                    window=rule["window_minutes"], threshold=threshold,
                )
                alerts.append(_new_alert(
                    rule, explanation, evidence, rule["severity"],
                    {"src_ip": ip, "count": len(window_evts)},
                ))
                break
    return alerts


# -------------------- R008: Injection patterns --------------------

_INJECTION_PATTERNS = [
    ("sqli", re.compile(r"(?i)union\s+select|or\s+1=1|--(?:\s|$)|\bselect\b.+\bfrom\b|xp_cmdshell|;\s*drop\s+table|information_schema")),
    ("xss",  re.compile(r"(?i)<script|javascript:|onerror\s*=|onload\s*=|<iframe|document\.cookie|<img[^>]+src\s*=\s*['\"]?javascript:")),
    ("traversal", re.compile(r"\.\./|\.\.\\|%2e%2e[/\\]|%2e%2e%2f|/etc/passwd|c:\\windows\\", re.IGNORECASE)),
]


def detect_injection_patterns(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule = _get("R008")
    alerts = []
    for e in events:
        url = e.get("url") or ""
        if not url:
            continue
        try:
            from urllib.parse import unquote
            decoded = unquote(url)
        except Exception:
            decoded = url
        for cls, pattern in _INJECTION_PATTERNS:
            m = pattern.search(decoded) or pattern.search(url)
            if m:
                explanation = rule["template"].format(
                    src_ip=e.get("src_ip") or "unknown", url=url,
                    pattern_class=cls.upper(), pattern=m.group(0)[:40],
                    when=e["timestamp"],
                )
                alerts.append(_new_alert(
                    rule, explanation, [e["event_id"]], rule["severity"],
                    {"src_ip": e.get("src_ip"), "url": url,
                     "pattern_class": cls, "pattern": m.group(0)[:80]},
                ))
                break  # one alert per event
    return alerts


# -------------------- R009: New-device admin login --------------------

async def detect_new_device_admin(db, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Async detector: requires the users collection to know admin identity."""
    rule = _get("R009")
    alerts: List[Dict[str, Any]] = []
    # candidates: successful auth logins with user + src_ip + user_agent
    candidates = [
        e for e in events
        if e.get("app") == "auth"
        and str(e.get("http_status")) in ("success", "200", "ok")
        and e.get("user") and e.get("src_ip") and e.get("user_agent")
    ]
    if not candidates:
        return alerts

    # who is an admin? match on email OR name
    user_names = list({e["user"] for e in candidates})
    admin_docs = await db.users.find(
        {"role": "admin", "$or": [
            {"email": {"$in": user_names}},
            {"name": {"$in": user_names}},
        ]},
        {"email": 1, "name": 1},
    ).to_list(200)
    admin_identities = {d.get("email") for d in admin_docs} | {d.get("name") for d in admin_docs}
    admin_identities.discard(None)

    for e in candidates:
        if e["user"] not in admin_identities:
            continue
        fp = {"user": e["user"], "src_ip": e["src_ip"], "user_agent": e["user_agent"]}
        exists = await db.known_devices.find_one(fp)
        if exists:
            continue
        await db.known_devices.insert_one({
            **fp,
            "first_seen": e["timestamp"],
        })
        explanation = rule["template"].format(
            user=e["user"], src_ip=e["src_ip"],
            user_agent=e["user_agent"][:80], when=e["timestamp"],
        )
        alerts.append(_new_alert(
            rule, explanation, [e["event_id"]], rule["severity"],
            {"user": e["user"], "src_ip": e["src_ip"], "user_agent": e["user_agent"]},
        ))
    return alerts
