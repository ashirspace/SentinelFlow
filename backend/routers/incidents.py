"""Incident management, investigation timeline, and alert correlation."""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.database import db
from core.deps import current_user, audit

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    severity: Optional[str] = "Suspicious"
    summary: Optional[str] = ""
    alert_ids: Optional[List[str]] = None


class IncidentUpdate(BaseModel):
    status: Optional[str] = Field(default=None, pattern="^(Open|Investigating|Resolved|Closed)$")
    note: Optional[str] = None
    root_cause: Optional[str] = None
    title: Optional[str] = None


class LinkAlertsBody(BaseModel):
    alert_ids: List[str]


def _timeline_entry(kind: str, by: str, text: str, meta: Optional[dict] = None) -> dict:
    return {
        "at": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "by": by,
        "text": text,
        "meta": meta or {},
    }


@router.get("")
async def list_incidents(status: Optional[str] = None, _: dict = Depends(current_user)):
    q = {}
    if status:
        q["status"] = status
    return await db.incidents.find(q, {"_id": 0}).sort("opened_at", -1).to_list(500)


@router.get("/{incident_id}")
async def get_incident(incident_id: str, _: dict = Depends(current_user)):
    inc = await db.incidents.find_one({"id": incident_id}, {"_id": 0})
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc["alerts"] = await db.alerts.find(
        {"id": {"$in": inc.get("alert_ids") or []}}, {"_id": 0}
    ).to_list(500)
    inc["evidence_events"] = await db.normalized_events.find(
        {"event_id": {"$in": inc.get("evidence_event_ids") or []}}, {"_id": 0}
    ).to_list(1000)
    inc.setdefault("root_cause", "")
    inc.setdefault("timeline", [])
    return inc


@router.post("")
async def create_incident(body: IncidentCreate, user: dict = Depends(current_user)):
    alert_ids = body.alert_ids or []
    evidence_event_ids: List[str] = []
    if alert_ids:
        found = await db.alerts.find(
            {"id": {"$in": alert_ids}}, {"_id": 0, "id": 1, "evidence_event_ids": 1}
        ).to_list(len(alert_ids))
        found_ids = {a["id"] for a in found}
        missing = [x for x in alert_ids if x not in found_ids]
        if missing:
            raise HTTPException(status_code=400, detail=f"Unknown alert ids: {missing}")
        for a in found:
            evidence_event_ids.extend(a.get("evidence_event_ids") or [])

    incident = {
        "id": str(uuid.uuid4()),
        "title": body.title,
        "status": "Open",
        "severity": body.severity or "Suspicious",
        "opened_by": user["email"],
        "opened_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "alert_ids": alert_ids,
        "evidence_event_ids": list(dict.fromkeys(evidence_event_ids)),
        "summary": body.summary or "",
        "root_cause": "",
        "notes": [],
        "timeline": [_timeline_entry(
            "opened", user["email"],
            f"Incident opened with {len(alert_ids)} alert(s).",
            {"alert_ids": alert_ids},
        )],
    }
    await db.incidents.insert_one(dict(incident))
    incident.pop("_id", None)
    await audit(
        user["email"], "create_incident", target=incident["id"],
        meta={"alerts": len(alert_ids)},
    )
    return incident


@router.patch("/{incident_id}")
async def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    user: dict = Depends(current_user),
):
    inc = await db.incidents.find_one({"id": incident_id})
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    updates: Dict[str, Any] = {"updated_at": datetime.now(timezone.utc).isoformat()}
    push_notes = None
    timeline_entries: List[dict] = []

    if body.status and body.status != inc.get("status"):
        updates["status"] = body.status
        timeline_entries.append(_timeline_entry(
            "status", user["email"],
            f"Status changed: {inc.get('status')} → {body.status}",
            {"from": inc.get("status"), "to": body.status},
        ))
    if body.title:
        updates["title"] = body.title
        timeline_entries.append(_timeline_entry(
            "title", user["email"], f"Title changed to: {body.title}",
        ))
    if body.root_cause is not None and body.root_cause != inc.get("root_cause"):
        updates["root_cause"] = body.root_cause
        timeline_entries.append(_timeline_entry(
            "root_cause", user["email"],
            "Root cause updated.",
            {"length": len(body.root_cause)},
        ))
    if body.note:
        note_entry = {
            "at": datetime.now(timezone.utc).isoformat(),
            "by": user["email"],
            "text": body.note,
        }
        push_notes = note_entry
        timeline_entries.append(_timeline_entry(
            "note", user["email"], body.note,
        ))

    if len(updates) == 1 and not push_notes and not timeline_entries:
        raise HTTPException(status_code=400, detail="Nothing to update")

    op: Dict[str, Any] = {"$set": updates}
    push_ops: Dict[str, Any] = {}
    if push_notes:
        push_ops["notes"] = push_notes
    if timeline_entries:
        push_ops["timeline"] = {"$each": timeline_entries}
    if push_ops:
        op["$push"] = push_ops

    await db.incidents.update_one({"id": incident_id}, op)
    await audit(
        user["email"], "update_incident", target=incident_id,
        meta={"status": body.status, "note": body.note,
              "root_cause_updated": body.root_cause is not None},
    )
    return {"ok": True}


@router.post("/{incident_id}/alerts")
async def link_alerts(
    incident_id: str,
    body: LinkAlertsBody,
    user: dict = Depends(current_user),
):
    inc = await db.incidents.find_one({"id": incident_id})
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    existing = set(inc.get("alert_ids") or [])
    to_add = [x for x in body.alert_ids if x not in existing]
    if not to_add:
        return {"ok": True, "added": 0}
    found = await db.alerts.find(
        {"id": {"$in": to_add}}, {"_id": 0, "id": 1, "evidence_event_ids": 1}
    ).to_list(len(to_add))
    found_ids = {a["id"] for a in found}
    missing = [x for x in to_add if x not in found_ids]
    if missing:
        raise HTTPException(status_code=400, detail=f"Unknown alert ids: {missing}")
    new_events: List[str] = []
    for a in found:
        new_events.extend(a.get("evidence_event_ids") or [])
    await db.incidents.update_one(
        {"id": incident_id},
        {"$addToSet": {
             "alert_ids": {"$each": to_add},
             "evidence_event_ids": {"$each": new_events},
         },
         "$set": {"updated_at": datetime.now(timezone.utc).isoformat()},
         "$push": {"timeline": _timeline_entry(
             "alerts_added", user["email"],
             f"Linked {len(to_add)} alert(s) to incident.",
             {"alert_ids": to_add},
         )}},
    )
    await audit(user["email"], "link_alerts", target=incident_id, meta={"alerts": to_add})
    return {"ok": True, "added": len(to_add)}


@router.delete("/{incident_id}/alerts/{alert_id}")
async def unlink_alert(
    incident_id: str,
    alert_id: str,
    user: dict = Depends(current_user),
):
    inc = await db.incidents.find_one({"id": incident_id})
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if alert_id not in (inc.get("alert_ids") or []):
        raise HTTPException(status_code=404, detail="Alert not linked to this incident")
    remaining = [x for x in inc.get("alert_ids") or [] if x != alert_id]
    remaining_alerts = await db.alerts.find(
        {"id": {"$in": remaining}}, {"_id": 0, "evidence_event_ids": 1}
    ).to_list(len(remaining) or 1)
    new_evidence: List[str] = []
    for a in remaining_alerts:
        new_evidence.extend(a.get("evidence_event_ids") or [])
    await db.incidents.update_one(
        {"id": incident_id},
        {"$set": {"alert_ids": remaining,
                  "evidence_event_ids": list(dict.fromkeys(new_evidence)),
                  "updated_at": datetime.now(timezone.utc).isoformat()},
         "$push": {"timeline": _timeline_entry(
             "alerts_removed", user["email"],
             f"Unlinked alert {alert_id[:8]} from incident.",
             {"alert_id": alert_id},
         )}},
    )
    await audit(user["email"], "unlink_alert", target=incident_id, meta={"alert_id": alert_id})
    return {"ok": True}
