"""Log sources management endpoints."""
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.database import db
from core.deps import current_user, require_admin, audit, url_for
import ingest_v1 as _v1

router = APIRouter(prefix="/sources", tags=["sources"])

SOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,79}$")


def validate_source_name(name: str) -> str:
    cleaned = (name or "").strip()
    if not SOURCE_NAME_RE.match(cleaned):
        raise HTTPException(
            status_code=422,
            detail="Source name must be 2-80 URL-safe characters: letters, numbers, dot, underscore, or hyphen.",
        )
    return cleaned


def source_connection(source: dict) -> dict:
    name = source.get("name", "")
    encoded = name.replace("/", "")
    source_type = (source.get("type") or "custom").lower()
    if source_type == "akamai":
        endpoint = url_for(f"/api/integrations/akamai/{encoded}/logs")
        return {
            "endpoint": endpoint,
            "header_name": "X-Ingest-Key",
            "format": "JSON",
            "content_type": "application/json",
            "compression": "off",
            "integration": "akamai_datastream",
        }
    return {
        "endpoint": url_for("/api/v1/ingest"),
        "query": f"source_name={name}",
        "header_name": "Authorization",
        "header_value_prefix": "Bearer ",
        "format": "JSON, NDJSON, or {events:[...]}",
        "content_type": "application/json",
        "integration": source_type,
    }


class SourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    type: str = Field(pattern="^(akamai|web|auth|os|db|api|network|cloudflare|fluent-bit|vector|custom)$")
    description: Optional[str] = ""


class SourceUpdate(BaseModel):
    paused: Optional[bool] = None
    retention_hours: Optional[int] = Field(default=None, ge=1, le=72)
    description: Optional[str] = None


@router.get("")
async def list_sources(_: dict = Depends(current_user)):
    sources = await db.log_sources.find({}, {"_id": 0, "ingest_api_key_hash": 0}).to_list(1000)
    now = datetime.now(timezone.utc)
    for s in sources:
        s.setdefault("paused", False)
        s.setdefault("retention_hours", 72)
        last = s.get("last_event_at")
        if not last:
            s["health"] = "silent"
            s["connection"] = source_connection(s)
            continue
        last_dt = datetime.fromisoformat(last) if isinstance(last, str) else last
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        delta = now - last_dt
        if delta > timedelta(minutes=30):
            s["health"] = "silent"
        elif delta > timedelta(minutes=5):
            s["health"] = "delayed"
        else:
            s["health"] = "healthy"
        s["connection"] = source_connection(s)
    return sources


@router.post("")
async def create_source(body: SourceCreate, admin: dict = Depends(require_admin)):
    source_name = validate_source_name(body.name)
    source_type = body.type.lower().strip()
    plaintext, hashed = _v1.generate_key()
    doc = {
        "id": str(uuid.uuid4()),
        "name": source_name,
        "type": source_type,
        "description": body.description or "",
        "last_event_at": None,
        "paused": False,
        "retention_hours": 72,
        "ingest_api_key_hash": hashed,
        "ingest_api_key_hint": plaintext[:12] + "…",
        "key_created_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        await db.log_sources.insert_one(doc)
    except Exception as e:
        raise HTTPException(status_code=409, detail=f"Source exists: {e}")

    doc.pop("_id", None)
    doc.pop("ingest_api_key_hash", None)
    doc["connection"] = source_connection(doc)
    await audit(admin["email"], "create_source", target=source_name)
    return {**doc, "ingest_api_key": plaintext}


@router.patch("/{name}")
async def update_source(name: str, body: SourceUpdate, admin: dict = Depends(require_admin)):
    updates = {k: v for k, v in body.model_dump().items() if v is not None} if hasattr(body, "model_dump") else {k: v for k, v in body.dict().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")
    r = await db.log_sources.update_one({"name": name}, {"$set": updates})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Source not found")
    await audit(admin["email"], "update_source", target=name, meta=updates)
    return {"ok": True, **updates}


@router.delete("/{name}")
async def delete_source(name: str, purge_events: bool = False, admin: dict = Depends(require_admin)):
    r = await db.log_sources.delete_one({"name": name})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Source not found")
    meta = {"purge_events": purge_events, "events_deleted": 0, "raw_deleted": 0}
    if purge_events:
        e = await db.normalized_events.delete_many({"source_name": name})
        r2 = await db.raw_logs.delete_many({"source_name": name})
        meta["events_deleted"] = e.deleted_count
        meta["raw_deleted"] = r2.deleted_count
    await audit(admin["email"], "delete_source", target=name, meta=meta)
    return {"ok": True, **meta}


@router.post("/{name}/rotate-key")
async def rotate_source_key(name: str, admin: dict = Depends(require_admin)):
    plaintext, hashed = _v1.generate_key()
    r = await db.log_sources.update_one(
        {"name": name},
        {"$set": {
            "ingest_api_key_hash": hashed,
            "ingest_api_key_hint": plaintext[:12] + "…",
            "key_created_at": datetime.now(timezone.utc).isoformat(),
        }},
    )
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Source not found")
    await audit(admin["email"], "rotate_source_key", target=name)
    return {"ingest_api_key": plaintext}


@router.post("/{name}/revoke-key")
async def revoke_source_key(name: str, admin: dict = Depends(require_admin)):
    r = await db.log_sources.update_one(
        {"name": name},
        {"$unset": {"ingest_api_key_hash": "", "ingest_api_key_hint": ""},
         "$set": {"key_revoked_at": datetime.now(timezone.utc).isoformat()}},
    )
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Source not found")
    await audit(admin["email"], "revoke_source_key", target=name)
    return {"ok": True}
