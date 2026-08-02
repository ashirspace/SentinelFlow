"""Human-approved response actions.

Every executor here is invoked ONLY after an analyst clicks Approve on an
alert. Each execution writes a row to `response_actions` and a row to
`audit_logs`. Nothing runs automatically.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from bson import ObjectId
from fastapi import HTTPException


# Which action types make sense for which rule.
# Frontend uses this to render the buttons; server also validates.
RECOMMENDED_BY_RULE: Dict[str, list] = {
    "R001": ["block_ip", "escalate_incident"],
    "R002": ["revoke_session", "disable_account", "block_ip", "escalate_incident"],
    "R003": ["revoke_session", "escalate_incident"],
    "R004": ["disable_account", "escalate_incident"],
    "R005": ["block_ip", "escalate_incident"],
    "R006": ["escalate_incident"],
    "R007": ["block_ip", "escalate_incident"],
    "R008": ["block_ip", "escalate_incident"],
    "R009": ["revoke_session", "escalate_incident"],
    "R010": ["escalate_incident"],
}

ACTION_LABELS = {
    "block_ip": "Block IP",
    "disable_account": "Disable account",
    "revoke_session": "Revoke session",
    "escalate_incident": "Escalate to incident",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _record(db, alert_id: str, action_type: str, target: str,
                  approver: dict, result: str, note: str, meta: Optional[dict] = None):
    doc = {
        "id": str(uuid.uuid4()),
        "alert_id": alert_id,
        "action_type": action_type,
        "target": target,
        "approver": approver["email"],
        "approver_id": approver["id"],
        "note": note or "",
        "result": result,
        "meta": meta or {},
        "created_at": _now(),
    }
    await db.response_actions.insert_one(doc)
    await db.audit_logs.insert_one({
        "id": str(uuid.uuid4()),
        "actor": approver["email"],
        "action": f"approve:{action_type}",
        "target": f"alert={alert_id};target={target}",
        "meta": {"result": result, "note": note, **(meta or {})},
        "timestamp": _now(),
    })
    doc.pop("_id", None)
    return doc


async def _load_alert(db, alert_id: str) -> dict:
    a = await db.alerts.find_one({"id": alert_id})
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    return a


def _target_from_alert(action_type: str, alert: dict, override: Optional[str]) -> str:
    if override:
        return override
    kf = alert.get("key_fields") or {}
    if action_type == "block_ip":
        return kf.get("src_ip") or ""
    if action_type in ("disable_account", "revoke_session"):
        return kf.get("user") or ""
    return ""


async def approve_action(db, alert_id: str, action_type: str,
                          approver: dict, target_override: Optional[str] = None,
                          note: str = "") -> dict:
    if action_type not in ACTION_LABELS:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action_type}")

    alert = await _load_alert(db, alert_id)
    allowed = RECOMMENDED_BY_RULE.get(alert["rule_id"], [])
    if action_type not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Action '{action_type}' is not recommended for rule {alert['rule_id']}",
        )

    target = _target_from_alert(action_type, alert, target_override)

    if action_type == "block_ip":
        return await _do_block_ip(db, alert, target, approver, note)
    if action_type == "disable_account":
        return await _do_disable_account(db, alert, target, approver, note)
    if action_type == "revoke_session":
        return await _do_revoke_session(db, alert, target, approver, note)
    if action_type == "escalate_incident":
        return await _do_escalate_incident(db, alert, approver, note)
    raise HTTPException(status_code=400, detail="Unhandled action")


# -------------------- individual executors --------------------

async def _do_block_ip(db, alert: dict, ip: str, approver: dict, note: str) -> dict:
    if not ip:
        raise HTTPException(status_code=400, detail="No target IP available on this alert")
    existing = await db.ip_blocklist.find_one({"ip": ip})
    if existing:
        result = "already_blocked"
        meta = {"first_blocked_at": existing.get("created_at")}
    else:
        await db.ip_blocklist.insert_one({
            "ip": ip,
            "reason": f"{alert['rule_id']} — {alert['rule_name']}",
            "alert_id": alert["id"],
            "created_by": approver["email"],
            "created_at": _now(),
            "note": note or "",
        })
        result = "blocked"
        meta = {}
    return await _record(db, alert["id"], "block_ip", ip, approver, result, note, meta)


async def _do_disable_account(db, alert: dict, account: str, approver: dict, note: str) -> dict:
    if not account:
        raise HTTPException(status_code=400, detail="No target account on this alert")
    # Look up SentinelFlow-managed users by email OR name
    user_doc = await db.users.find_one(
        {"$or": [{"email": account.lower()}, {"name": account}]},
    )
    if user_doc:
        await db.users.update_one(
            {"_id": user_doc["_id"]},
            {"$set": {"disabled": True, "disabled_at": _now(), "disabled_by": approver["email"]},
             "$inc": {"token_version": 1}},
        )
        result = "disabled_internal"
        meta = {"user_id": str(user_doc["_id"]), "user_email": user_doc.get("email")}
    else:
        # External account — record clear recommendation, no auto-action taken.
        result = "recommended_external"
        meta = {
            "recommendation": f"Disable account '{account}' in the source system "
                              f"(evidence alert {alert['id']}, rule {alert['rule_id']}).",
            "account": account,
        }
    return await _record(db, alert["id"], "disable_account", account, approver, result, note, meta)


async def _do_revoke_session(db, alert: dict, account: str, approver: dict, note: str) -> dict:
    if not account:
        raise HTTPException(status_code=400, detail="No target account on this alert")
    user_doc = await db.users.find_one(
        {"$or": [{"email": account.lower()}, {"name": account}]},
    )
    if user_doc:
        await db.users.update_one(
            {"_id": user_doc["_id"]},
            {"$inc": {"token_version": 1},
             "$set": {"sessions_revoked_at": _now(),
                      "sessions_revoked_by": approver["email"]}},
        )
        # also purge any active login_attempt lockout counters
        await db.login_attempts.delete_many({"identifier": {"$regex": f":{user_doc.get('email','')}$"}})
        result = "revoked_internal"
        meta = {"user_id": str(user_doc["_id"])}
    else:
        result = "recommended_external"
        meta = {
            "recommendation": f"Invalidate active sessions/tokens for '{account}' "
                              f"in the source system.",
            "account": account,
        }
    return await _record(db, alert["id"], "revoke_session", account, approver, result, note, meta)


async def _do_escalate_incident(db, alert: dict, approver: dict, note: str) -> dict:
    # if an incident already exists for this alert, return it
    existing = await db.incidents.find_one({"alert_ids": alert["id"]})
    if existing:
        result = "linked_existing"
        meta = {"incident_id": existing["id"]}
        return await _record(db, alert["id"], "escalate_incident", existing["id"],
                             approver, result, note, meta)
    incident = {
        "id": str(uuid.uuid4()),
        "title": f"{alert['rule_id']} · {alert['rule_name']}",
        "status": "Open",
        "severity": alert["severity"],
        "opened_by": approver["email"],
        "opened_at": _now(),
        "updated_at": _now(),
        "alert_ids": [alert["id"]],
        "evidence_event_ids": alert.get("evidence_event_ids") or [],
        "summary": alert["explanation"],
        "root_cause": "",
        "notes": [{"at": _now(), "by": approver["email"], "text": note or "Escalated from alert."}],
        "timeline": [{
            "at": _now(), "kind": "opened", "by": approver["email"],
            "text": f"Incident escalated from alert {alert['id'][:8]} · {alert['rule_id']}.",
            "meta": {"alert_id": alert["id"], "rule_id": alert["rule_id"]},
        }],
    }
    await db.incidents.insert_one(dict(incident))
    return await _record(db, alert["id"], "escalate_incident", incident["id"],
                         approver, "created", note, {"incident_id": incident["id"]})
