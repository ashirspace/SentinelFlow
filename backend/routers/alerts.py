"""Alerts management, SOAR response actions, and IP blocklist."""
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.database import db
from core.deps import current_user, require_admin, audit
from responses import approve_action, RECOMMENDED_BY_RULE, ACTION_LABELS

router = APIRouter(tags=["alerts"])


class AlertStatusUpdate(BaseModel):
    status: str = Field(pattern="^(New|Under Review|Investigating|Confirmed|False Positive|Resolved)$")
    note: Optional[str] = None


class ApproveActionBody(BaseModel):
    action_type: str
    target: Optional[str] = None
    note: Optional[str] = None


@router.get("/alerts")
async def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    _: dict = Depends(current_user),
):
    q = {}
    if status:
        q["status"] = status
    if severity:
        q["severity"] = severity
    if rule_id:
        q["rule_id"] = rule_id
    alerts = await db.alerts.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)
    return alerts


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, _: dict = Depends(current_user)):
    a = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    # Attach evidence events
    ev_ids = a.get("evidence_event_ids") or []
    evidence = await db.normalized_events.find(
        {"event_id": {"$in": ev_ids}}, {"_id": 0}
    ).to_list(500)
    a["evidence_events"] = evidence
    # Attach linked incidents
    linked = await db.incidents.find(
        {"alert_ids": alert_id},
        {"_id": 0, "id": 1, "title": 1, "status": 1, "severity": 1}
    ).to_list(50)
    a["linked_incidents"] = linked
    return a


@router.patch("/alerts/{alert_id}")
async def update_alert(
    alert_id: str,
    body: AlertStatusUpdate,
    user: dict = Depends(current_user),
):
    alert = await db.alerts.find_one({"id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    note = {
        "at": datetime.now(timezone.utc).isoformat(),
        "by": user["email"],
        "from": alert["status"],
        "to": body.status,
        "note": body.note or "",
    }
    await db.alerts.update_one(
        {"id": alert_id},
        {"$set": {"status": body.status,
                  "updated_at": datetime.now(timezone.utc).isoformat()},
         "$push": {"notes": note}},
    )
    await audit(
        user["email"], "alert_status_change", target=alert_id,
        meta={"from": alert["status"], "to": body.status, "note": body.note},
    )
    return {"ok": True}


# -------------------- Response Actions (Human-approved) --------------------

@router.get("/alerts/{alert_id}/recommended-actions")
async def get_recommended_actions(alert_id: str, _: dict = Depends(current_user)):
    alert = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    types = RECOMMENDED_BY_RULE.get(alert["rule_id"], [])
    kf = alert.get("key_fields") or {}
    default_target = {
        "block_ip": kf.get("src_ip") or "",
        "disable_account": kf.get("user") or "",
        "revoke_session": kf.get("user") or "",
        "escalate_incident": "",
    }
    return [
        {"type": t, "label": ACTION_LABELS[t], "default_target": default_target.get(t, "")}
        for t in types
    ]


@router.post("/alerts/{alert_id}/approve")
async def approve_alert_action(
    alert_id: str,
    body: ApproveActionBody,
    user: dict = Depends(current_user),
):
    return await approve_action(
        db, alert_id, body.action_type, user,
        target_override=body.target, note=body.note or "",
    )


@router.get("/alerts/{alert_id}/actions")
async def list_alert_actions(alert_id: str, _: dict = Depends(current_user)):
    docs = await db.response_actions.find({"alert_id": alert_id}, {"_id": 0}) \
        .sort("created_at", -1).to_list(200)
    return docs


# -------------------- IP Blocklist --------------------

@router.get("/blocklist")
async def get_blocklist(_: dict = Depends(current_user)):
    return await db.ip_blocklist.find({}, {"_id": 0}).sort("created_at", -1).to_list(2000)


@router.delete("/blocklist/{ip}")
async def unblock_ip(ip: str, admin: dict = Depends(require_admin)):
    r = await db.ip_blocklist.delete_one({"ip": ip})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="IP not blocked")
    await audit(admin["email"], "unblock_ip", target=ip)
    return {"ok": True}
