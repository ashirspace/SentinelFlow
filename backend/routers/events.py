"""Events (Log Explorer), annotations, saved searches, and CSV exports."""
import csv
import io
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from core.database import db
from core.deps import current_user, audit

router = APIRouter(tags=["events"])


@router.get("/events")
async def list_events(
    q: Optional[str] = None,
    severity: Optional[str] = None,
    src_ip: Optional[str] = None,
    user_name: Optional[str] = None,
    app_name: Optional[str] = None,
    limit: int = 100,
    skip: int = 0,
    _: dict = Depends(current_user),
):
    query = {}
    if severity:
        query["severity"] = severity
    if src_ip:
        query["src_ip"] = src_ip
    if user_name:
        query["user"] = user_name
    if app_name:
        query["app"] = app_name
    if q:
        query["$or"] = [
            {"src_ip": {"$regex": q, "$options": "i"}},
            {"user": {"$regex": q, "$options": "i"}},
            {"host": {"$regex": q, "$options": "i"}},
            {"url": {"$regex": q, "$options": "i"}},
            {"action": {"$regex": q, "$options": "i"}},
        ]
    cursor = db.normalized_events.find(query, {"_id": 0}) \
        .sort("timestamp", -1).skip(skip).limit(min(limit, 500))
    events = await cursor.to_list(limit)
    total = await db.normalized_events.count_documents(query)
    return {"events": events, "total": total}


@router.get("/events/{event_id}")
async def get_event(event_id: str, _: dict = Depends(current_user)):
    ev = await db.normalized_events.find_one({"event_id": event_id}, {"_id": 0})
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    return ev


class EventAnnotation(BaseModel):
    tags: Optional[List[str]] = None
    note: Optional[str] = None
    reviewed: Optional[bool] = None


@router.patch("/events/{event_id}")
async def annotate_event(
    event_id: str,
    body: EventAnnotation,
    user: dict = Depends(current_user),
):
    updates: Dict[str, Any] = {}
    push = None
    if body.tags is not None:
        updates["tags"] = [t.strip() for t in body.tags if t.strip()]
    if body.reviewed is not None:
        updates["reviewed"] = body.reviewed
        if body.reviewed:
            updates["reviewed_by"] = user["email"]
            updates["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    if body.note:
        push = {
            "notes": {
                "at": datetime.now(timezone.utc).isoformat(),
                "by": user["email"],
                "text": body.note,
            }
        }
    if not updates and not push:
        raise HTTPException(status_code=400, detail="Nothing to update")
    op = {}
    if updates:
        op["$set"] = updates
    if push:
        op["$push"] = push
    r = await db.normalized_events.update_one({"event_id": event_id}, op)
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Event not found")
    await audit(
        user["email"], "annotate_event", target=event_id,
        meta={"tags": body.tags, "reviewed": body.reviewed, "note": body.note},
    )
    return {"ok": True}


@router.get("/export/events.csv")
async def export_events_csv(
    q: Optional[str] = None,
    severity: Optional[str] = None,
    src_ip: Optional[str] = None,
    user_name: Optional[str] = None,
    app_name: Optional[str] = None,
    limit: int = 5000,
    user: dict = Depends(current_user),
):
    query = {}
    if severity: query["severity"] = severity
    if src_ip: query["src_ip"] = src_ip
    if user_name: query["user"] = user_name
    if app_name: query["app"] = app_name
    if q:
        query["$or"] = [
            {"src_ip": {"$regex": q, "$options": "i"}},
            {"user": {"$regex": q, "$options": "i"}},
            {"host": {"$regex": q, "$options": "i"}},
            {"url": {"$regex": q, "$options": "i"}},
            {"action": {"$regex": q, "$options": "i"}},
        ]
    cols = [
        "event_id", "timestamp", "src_ip", "dst_ip", "user", "host", "app",
        "action", "url", "http_method", "http_status", "severity",
        "country", "user_agent", "source_name", "reviewed",
    ]
    docs = await db.normalized_events.find(query, {"_id": 0, "raw_log": 0}) \
        .sort("timestamp", -1).limit(min(limit, 50000)).to_list(limit)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for d in docs:
        w.writerow(d)
    await audit(
        user["email"], "export_events_csv", target="events",
        meta={"count": len(docs), "filters": {"q": q, "severity": severity}},
    )
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelflow_events.csv"},
    )


# -------------------- Saved Searches --------------------

class SavedSearchCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    filters: Dict[str, Any]


@router.get("/saved-searches")
async def list_saved_searches(user: dict = Depends(current_user)):
    return await db.saved_searches.find(
        {"owner": user["email"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(200)


@router.post("/saved-searches")
async def create_saved_search(body: SavedSearchCreate, user: dict = Depends(current_user)):
    doc = {
        "id": str(uuid.uuid4()),
        "owner": user["email"],
        "name": body.name,
        "filters": body.filters,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        await db.saved_searches.insert_one(doc)
    except Exception:
        raise HTTPException(status_code=409, detail="A saved search with this name exists")
    doc.pop("_id", None)
    return doc


@router.delete("/saved-searches/{search_id}")
async def delete_saved_search(search_id: str, user: dict = Depends(current_user)):
    r = await db.saved_searches.delete_one({"id": search_id, "owner": user["email"]})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Saved search not found")
    return {"ok": True}
