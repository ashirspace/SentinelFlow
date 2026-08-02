"""SentinelFlow — FastAPI backend."""
from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(__file__).parent / ".env")

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from bson import ObjectId
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, Response, UploadFile, File, Query
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from starlette.middleware.cors import CORSMiddleware

from auth import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    set_auth_cookies, clear_auth_cookies, get_current_user,
)
from normalize import normalize_record, parse_upload
from rules import run_all_rules, detect_silent_sources, detect_new_device_admin, RULES_META
from seed import sample_events, demo_sources
from notifier import notify_alerts, is_enabled as email_enabled
from responses import approve_action, RECOMMENDED_BY_RULE, ACTION_LABELS

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("sentinelflow")

# -------------------- App + DB --------------------
mongo_url = os.environ["MONGO_URL"]
mongo = AsyncIOMotorClient(mongo_url)
db = mongo[os.environ["DB_NAME"]]

app = FastAPI(title="SentinelFlow")

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api = APIRouter(prefix="/api")


# -------------------- Auth dependency --------------------
async def current_user(request: Request) -> dict:
    return await get_current_user(request, db)


async def require_admin(user: dict = Depends(current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# -------------------- Audit helper --------------------
async def audit(actor_email: str, action: str, target: str = "", meta: Optional[dict] = None):
    await db.audit_logs.insert_one({
        "id": str(uuid.uuid4()),
        "actor": actor_email,
        "action": action,
        "target": target,
        "meta": meta or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# -------------------- Models --------------------
class LoginBody(BaseModel):
    email: EmailStr
    password: str


class UserCreateBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: str
    role: str = Field(pattern="^(admin|analyst)$")


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    created_at: Optional[str] = None


class SourceCreate(BaseModel):
    name: str
    type: str
    description: Optional[str] = ""


class AlertStatusUpdate(BaseModel):
    status: str = Field(pattern="^(New|Under Review|Investigating|Confirmed|False Positive|Resolved)$")
    note: Optional[str] = None


# -------------------- Auth --------------------
@api.post("/auth/login")
async def login(body: LoginBody, request: Request, response: Response):
    email = body.email.lower().strip()
    ip = request.client.host if request.client else "unknown"
    identifier = f"{ip}:{email}"

    # brute-force lockout: 5 fails in 15 min
    now = datetime.now(timezone.utc)
    attempt = await db.login_attempts.find_one({"identifier": identifier})
    if attempt and attempt.get("locked_until"):
        lu = datetime.fromisoformat(attempt["locked_until"])
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=timezone.utc)
        if lu > now:
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user["password_hash"]):
        # record failure
        fails = (attempt or {}).get("fails", 0) + 1
        update = {"identifier": identifier, "fails": fails, "last_at": now.isoformat()}
        if fails >= 5:
            from datetime import timedelta
            update["locked_until"] = (now + timedelta(minutes=15)).isoformat()
        await db.login_attempts.update_one({"identifier": identifier}, {"$set": update}, upsert=True)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.get("disabled"):
        raise HTTPException(status_code=403, detail="Account disabled")

    await db.login_attempts.delete_one({"identifier": identifier})
    uid = str(user["_id"])
    tv = int(user.get("token_version", 0))
    access = create_access_token(uid, email, user["role"], tv)
    refresh = create_refresh_token(uid, tv)
    set_auth_cookies(response, access, refresh)
    await audit(email, "login", target=uid)
    return {"id": uid, "email": email, "name": user["name"], "role": user["role"]}


@api.post("/auth/logout")
async def logout(response: Response, user: dict = Depends(current_user)):
    clear_auth_cookies(response)
    await audit(user["email"], "logout", target=user["id"])
    return {"ok": True}


@api.get("/auth/me")
async def me(user: dict = Depends(current_user)):
    return {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"]}


# -------------------- Users (admin) --------------------
@api.get("/users", response_model=List[UserOut])
async def list_users(_: dict = Depends(require_admin)):
    docs = await db.users.find({}, {"password_hash": 0}).to_list(1000)
    out = []
    for d in docs:
        out.append(UserOut(
            id=str(d["_id"]), email=d["email"], name=d["name"],
            role=d["role"], created_at=d.get("created_at"),
        ))
    return out


@api.post("/users", response_model=UserOut)
async def create_user(body: UserCreateBody, admin: dict = Depends(require_admin)):
    email = body.email.lower().strip()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="Email already exists")
    doc = {
        "email": email, "password_hash": hash_password(body.password),
        "name": body.name, "role": body.role,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    r = await db.users.insert_one(doc)
    await audit(admin["email"], "create_user", target=email, meta={"role": body.role})
    return UserOut(id=str(r.inserted_id), email=email, name=body.name,
                   role=body.role, created_at=doc["created_at"])


@api.delete("/users/{user_id}")
async def delete_user(user_id: str, admin: dict = Depends(require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete self")
    r = await db.users.delete_one({"_id": ObjectId(user_id)})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await audit(admin["email"], "delete_user", target=user_id)
    return {"ok": True}


# -------------------- Log Sources --------------------
@api.get("/sources")
async def list_sources(_: dict = Depends(current_user)):
    from datetime import timedelta
    sources = await db.log_sources.find({}, {"_id": 0, "ingest_api_key_hash": 0}).to_list(1000)
    now = datetime.now(timezone.utc)
    for s in sources:
        s.setdefault("paused", False)
        s.setdefault("retention_hours", 72)
        last = s.get("last_event_at")
        if not last:
            s["health"] = "silent"
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
    return sources


@api.post("/sources")
async def create_source(body: SourceCreate, admin: dict = Depends(require_admin)):
    import ingest_v1 as _v1
    plaintext, hashed = _v1.generate_key()
    doc = {
        "id": str(uuid.uuid4()), "name": body.name, "type": body.type,
        "description": body.description or "", "last_event_at": None,
        "paused": False, "retention_hours": 72,
        "ingest_api_key_hash": hashed,
        "ingest_api_key_hint": plaintext[:12] + "…",
        "key_created_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        await db.log_sources.insert_one(doc)
    except Exception as e:
        # duplicate name (unique index)
        raise HTTPException(status_code=409, detail=f"Source exists: {e}")
    doc.pop("_id", None)
    doc.pop("ingest_api_key_hash", None)
    await audit(admin["email"], "create_source", target=body.name)
    # Plaintext key is returned once. It is never retrievable again.
    return {**doc, "ingest_api_key": plaintext}


class SourceUpdate(BaseModel):
    paused: Optional[bool] = None
    retention_hours: Optional[int] = Field(default=None, ge=1, le=72)
    description: Optional[str] = None


@api.patch("/sources/{name}")
async def update_source(name: str, body: SourceUpdate, admin: dict = Depends(require_admin)):
    updates = {k: v for k, v in body.dict().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")
    r = await db.log_sources.update_one({"name": name}, {"$set": updates})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="Source not found")
    await audit(admin["email"], "update_source", target=name, meta=updates)
    return {"ok": True, **updates}


@api.delete("/sources/{name}")
async def delete_source(name: str, purge_events: bool = False,
                        admin: dict = Depends(require_admin)):
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


@api.post("/sources/{name}/rotate-key")
async def rotate_source_key(name: str, admin: dict = Depends(require_admin)):
    import ingest_v1 as _v1
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
    # forget any rate-limit budget carried by the old key
    await audit(admin["email"], "rotate_source_key", target=name)
    return {"ingest_api_key": plaintext}


@api.post("/sources/{name}/revoke-key")
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


# -------------------- Public ingest URL --------------------
@api.get("/ingest/config")
async def ingest_config(_: dict = Depends(current_user)):
    import ingest_v1 as _v1
    base = os.environ.get("FRONTEND_URL", "").rstrip("/")
    return {
        "endpoint": f"{base}/api/v1/ingest" if base else "/api/v1/ingest",
        "rate_limit_per_min": _v1.RATE_LIMIT_PER_MIN,
        "max_events_per_request": _v1.MAX_EVENTS_PER_REQ,
        "max_body_bytes": _v1.MAX_BODY_BYTES,
        "auth_header": "Authorization: Bearer sfk_...",
        "alt_header": "X-Ingest-Key: sfk_...",
    }


# -------------------- Ingestion --------------------
async def _ingest_events(records: list, source_name: str, actor_email: str):
    if not records:
        return {"ingested": 0, "alerts": 0}

    source = await db.log_sources.find_one({"name": source_name})
    if source and source.get("paused"):
        raise HTTPException(status_code=409, detail=f"Source '{source_name}' is paused")
    retention_hours = int((source or {}).get("retention_hours") or 72)
    retention_hours = max(1, min(72, retention_hours))

    from datetime import timedelta
    normalized = [normalize_record(r, source_name) for r in records]
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=retention_hours)
    raw_docs = [{"id": str(uuid.uuid4()), "source_name": source_name,
                 "payload": n["raw_log"], "created_at": n["timestamp"],
                 "expires_at": expires_at} for n in normalized]
    await db.raw_logs.insert_many(raw_docs)
    await db.normalized_events.insert_many([dict(n) for n in normalized])

    latest = max(n["timestamp"] for n in normalized)
    await db.log_sources.update_one(
        {"name": source_name},
        {"$set": {"last_event_at": latest}}, upsert=True,
    )

    # load current blocklist to run R010
    bl_docs = await db.ip_blocklist.find({}).to_list(5000)
    blocklist = {d["ip"]: d for d in bl_docs}

    alerts = run_all_rules(normalized, blocklist=blocklist)
    async_alerts = await detect_new_device_admin(db, normalized)
    alerts.extend(async_alerts)
    if alerts:
        await db.alerts.insert_many([dict(a) for a in alerts])
        try:
            statuses = await notify_alerts(db, alerts)
            logger.info("notify_alerts: %s", {s: statuses.count(s) for s in set(statuses)})
        except Exception as e:
            logger.warning("Notifier failed: %s", e)
    await audit(actor_email, "ingest", target=source_name,
                meta={"count": len(normalized), "alerts": len(alerts)})
    return {"ingested": len(normalized), "alerts": len(alerts)}


@api.post("/ingest")
async def ingest(source_name: str = Query(...), file: UploadFile = File(...),
                 user: dict = Depends(current_user)):
    content = await file.read()
    try:
        records = parse_upload(file.filename, content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Parse error: {e}")
    if not isinstance(records, list) or not records:
        raise HTTPException(status_code=400, detail="No records found in file")
    return await _ingest_events(records, source_name, user["email"])


class SyslogBody(BaseModel):
    source_name: str
    text: str


@api.post("/ingest/syslog")
async def ingest_syslog(body: SyslogBody, user: dict = Depends(current_user)):
    """Accept a raw syslog payload (RFC-5424 or RFC-3164) as a JSON string."""
    from syslog_parser import parse_syslog
    records = parse_syslog(body.text)
    if not records:
        raise HTTPException(status_code=400, detail="No syslog lines could be parsed")
    return await _ingest_events(records, body.source_name, user["email"])


# -------------------- Notifier status --------------------
@api.get("/notifier/status")
async def notifier_status(_: dict = Depends(current_user)):
    return {
        "enabled": email_enabled(),
        "min_severity": os.environ.get("ALERT_EMAIL_MIN_SEVERITY", "Suspicious"),
        "dedup_hours": int(os.environ.get("ALERT_EMAIL_DEDUP_HOURS", "1") or 1),
        "recipients": [e.strip() for e in os.environ.get("ALERT_EMAIL_TO", "").split(",") if e.strip()],
        "smtp_host": os.environ.get("SMTP_HOST", ""),
    }


@api.post("/ingest/seed")
async def seed_ingest(user: dict = Depends(require_admin)):
    """Load the sample events. Idempotent-ish (adds another batch each call)."""
    # ensure demo sources exist
    for src in demo_sources():
        exists = await db.log_sources.find_one({"name": src["name"]})
        if not exists:
            await db.log_sources.insert_one(src)
    events = sample_events()
    # split by app for source_name mapping
    by_source = {"auth-server-01": [], "web-nginx-01": [], "linux-prod-db-01": []}
    for e in events:
        if e.get("app") == "auth":
            by_source["auth-server-01"].append(e)
        elif e.get("app") == "web":
            by_source["web-nginx-01"].append(e)
        else:
            by_source["linux-prod-db-01"].append(e)
    total = {"ingested": 0, "alerts": 0}
    for src_name, recs in by_source.items():
        if recs:
            r = await _ingest_events(recs, src_name, user["email"])
            total["ingested"] += r["ingested"]
            total["alerts"] += r["alerts"]
    return total


# -------------------- Events (Log Explorer) --------------------
@api.get("/events")
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


@api.get("/events/{event_id}")
async def get_event(event_id: str, _: dict = Depends(current_user)):
    ev = await db.normalized_events.find_one({"event_id": event_id}, {"_id": 0})
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    return ev


# -------------------- Alerts --------------------
@api.get("/alerts")
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


@api.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, _: dict = Depends(current_user)):
    a = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    # attach evidence events
    ev_ids = a.get("evidence_event_ids") or []
    evidence = await db.normalized_events.find(
        {"event_id": {"$in": ev_ids}}, {"_id": 0}
    ).to_list(500)
    a["evidence_events"] = evidence
    return a


@api.patch("/alerts/{alert_id}")
async def update_alert(alert_id: str, body: AlertStatusUpdate,
                       user: dict = Depends(current_user)):
    alert = await db.alerts.find_one({"id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    note = {
        "at": datetime.now(timezone.utc).isoformat(),
        "by": user["email"],
        "from": alert["status"], "to": body.status,
        "note": body.note or "",
    }
    await db.alerts.update_one(
        {"id": alert_id},
        {"$set": {"status": body.status,
                  "updated_at": datetime.now(timezone.utc).isoformat()},
         "$push": {"notes": note}},
    )
    await audit(user["email"], "alert_status_change", target=alert_id,
                meta={"from": alert["status"], "to": body.status, "note": body.note})
    return {"ok": True}


# -------------------- Response Actions (human-approved) --------------------
@api.get("/alerts/{alert_id}/recommended-actions")
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


class ApproveActionBody(BaseModel):
    action_type: str
    target: Optional[str] = None
    note: Optional[str] = None


@api.post("/alerts/{alert_id}/approve")
async def approve_alert_action(alert_id: str, body: ApproveActionBody,
                                user: dict = Depends(current_user)):
    return await approve_action(db, alert_id, body.action_type, user,
                                 target_override=body.target, note=body.note or "")


@api.get("/alerts/{alert_id}/actions")
async def list_alert_actions(alert_id: str, _: dict = Depends(current_user)):
    docs = await db.response_actions.find({"alert_id": alert_id}, {"_id": 0}) \
        .sort("created_at", -1).to_list(200)
    return docs


# -------------------- IP Blocklist --------------------
@api.get("/blocklist")
async def get_blocklist(_: dict = Depends(current_user)):
    return await db.ip_blocklist.find({}, {"_id": 0}).sort("created_at", -1).to_list(2000)


@api.delete("/blocklist/{ip}")
async def unblock_ip(ip: str, admin: dict = Depends(require_admin)):
    r = await db.ip_blocklist.delete_one({"ip": ip})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="IP not blocked")
    await audit(admin["email"], "unblock_ip", target=ip)
    return {"ok": True}


# -------------------- Incidents --------------------
@api.get("/incidents")
async def list_incidents(status: Optional[str] = None, _: dict = Depends(current_user)):
    q = {}
    if status:
        q["status"] = status
    return await db.incidents.find(q, {"_id": 0}).sort("opened_at", -1).to_list(500)


@api.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, _: dict = Depends(current_user)):
    inc = await db.incidents.find_one({"id": incident_id}, {"_id": 0})
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc["alerts"] = await db.alerts.find(
        {"id": {"$in": inc.get("alert_ids") or []}}, {"_id": 0}
    ).to_list(200)
    inc["evidence_events"] = await db.normalized_events.find(
        {"event_id": {"$in": inc.get("evidence_event_ids") or []}}, {"_id": 0}
    ).to_list(500)
    return inc


class IncidentUpdate(BaseModel):
    status: Optional[str] = Field(default=None, pattern="^(Open|Investigating|Closed)$")
    note: Optional[str] = None


@api.patch("/incidents/{incident_id}")
async def update_incident(incident_id: str, body: IncidentUpdate,
                           user: dict = Depends(current_user)):
    inc = await db.incidents.find_one({"id": incident_id})
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    updates = {"updated_at": datetime.now(timezone.utc).isoformat()}
    push = None
    if body.status:
        updates["status"] = body.status
    if body.note:
        push = {"notes": {"at": datetime.now(timezone.utc).isoformat(),
                          "by": user["email"], "text": body.note}}
    op = {"$set": updates}
    if push:
        op["$push"] = push
    await db.incidents.update_one({"id": incident_id}, op)
    await audit(user["email"], "update_incident", target=incident_id,
                meta={"status": body.status, "note": body.note})
    return {"ok": True}


# -------------------- Event annotations --------------------
class EventAnnotation(BaseModel):
    tags: Optional[List[str]] = None
    note: Optional[str] = None
    reviewed: Optional[bool] = None


@api.patch("/events/{event_id}")
async def annotate_event(event_id: str, body: EventAnnotation,
                          user: dict = Depends(current_user)):
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
        push = {"notes": {"at": datetime.now(timezone.utc).isoformat(),
                          "by": user["email"], "text": body.note}}
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
    await audit(user["email"], "annotate_event", target=event_id,
                meta={"tags": body.tags, "reviewed": body.reviewed, "note": body.note})
    return {"ok": True}


# -------------------- CSV export --------------------
@api.get("/export/events.csv")
async def export_events_csv(
    q: Optional[str] = None, severity: Optional[str] = None,
    src_ip: Optional[str] = None, user_name: Optional[str] = None,
    app_name: Optional[str] = None, limit: int = 5000,
    user: dict = Depends(current_user),
):
    import csv
    import io
    from fastapi.responses import StreamingResponse
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
    cols = ["event_id", "timestamp", "src_ip", "dst_ip", "user", "host", "app",
            "action", "url", "http_method", "http_status", "severity",
            "country", "user_agent", "source_name", "reviewed"]
    docs = await db.normalized_events.find(query, {"_id": 0, "raw_log": 0}) \
        .sort("timestamp", -1).limit(min(limit, 50000)).to_list(limit)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for d in docs:
        w.writerow(d)
    await audit(user["email"], "export_events_csv", target="events",
                meta={"count": len(docs), "filters": {"q": q, "severity": severity}})
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                              headers={"Content-Disposition":
                                       "attachment; filename=sentinelflow_events.csv"})


# -------------------- Rules --------------------
@api.get("/rules")
async def list_rules(_: dict = Depends(current_user)):
    return RULES_META


# -------------------- Dashboard --------------------
@api.get("/dashboard/stats")
async def dashboard_stats(_: dict = Depends(current_user)):
    # 24h events, open alerts, critical alerts, silent sources
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=24)).isoformat()

    events_24h = await db.normalized_events.count_documents({"timestamp": {"$gte": since}})
    open_alerts = await db.alerts.count_documents(
        {"status": {"$in": ["New", "Under Review", "Investigating"]}}
    )
    critical_alerts = await db.alerts.count_documents({"severity": "Likely malicious"})
    silent = await detect_silent_sources(db)

    # timeseries (per hour, last 24h)
    pipeline = [
        {"$match": {"timestamp": {"$gte": since}}},
        {"$project": {"hour": {"$substr": ["$timestamp", 0, 13]}}},
        {"$group": {"_id": "$hour", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]
    ts = await db.normalized_events.aggregate(pipeline).to_list(200)
    timeseries = [{"hour": t["_id"], "count": t["count"]} for t in ts]

    # top source IPs
    pipeline2 = [
        {"$match": {"src_ip": {"$ne": None}}},
        {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 8},
    ]
    tops = await db.normalized_events.aggregate(pipeline2).to_list(20)
    top_ips = [{"src_ip": t["_id"], "count": t["count"]} for t in tops]

    # alerts by severity
    pipeline3 = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    sev = await db.alerts.aggregate(pipeline3).to_list(20)
    alerts_by_severity = [{"severity": s["_id"], "count": s["count"]} for s in sev]

    return {
        "events_24h": events_24h,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "silent_sources": len(silent),
        "timeseries": timeseries,
        "top_ips": top_ips,
        "alerts_by_severity": alerts_by_severity,
    }


# -------------------- Audit Log --------------------
@api.get("/audit")
async def audit_log(limit: int = 200, _: dict = Depends(require_admin)):
    docs = await db.audit_logs.find({}, {"_id": 0}) \
        .sort("timestamp", -1).limit(min(limit, 500)).to_list(limit)
    return docs


# -------------------- Health --------------------
@api.get("/")
async def root():
    return {"service": "SentinelFlow", "status": "ok"}


# -------------------- Startup --------------------
@app.on_event("startup")
async def startup():
    # indexes
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("identifier")
    await db.normalized_events.create_index("timestamp")
    await db.normalized_events.create_index("event_id")
    await db.normalized_events.create_index("src_ip")
    await db.normalized_events.create_index("user")
    await db.alerts.create_index("created_at")
    await db.alerts.create_index("status")
    await db.log_sources.create_index("name", unique=True)
    await db.known_devices.create_index([("user", 1), ("src_ip", 1), ("user_agent", 1)], unique=True)
    # notification dedup TTL — MongoDB will auto-delete expired keys
    await db.alert_notifications.create_index("expires_at", expireAfterSeconds=0)
    # TTL: per-source retention lives in raw_logs.expires_at (BSON date).
    # Drop legacy TTL index if it exists to avoid conflicts.
    try:
        existing_idx = await db.raw_logs.index_information()
        if "created_at_bson_1" in existing_idx:
            await db.raw_logs.drop_index("created_at_bson_1")
    except Exception:
        pass
    await db.raw_logs.create_index("expires_at", expireAfterSeconds=0)
    await db.raw_logs.create_index("source_name")
    # Blocklist + incidents + response actions
    await db.ip_blocklist.create_index("ip", unique=True)
    await db.incidents.create_index("opened_at")
    await db.response_actions.create_index("alert_id")
    await db.response_actions.create_index("created_at")
    # normalized events extras
    await db.normalized_events.create_index("source_name")
    await db.normalized_events.create_index("reviewed")

    # seed admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@sentinelflow.io").lower()
    admin_pw = os.environ.get("ADMIN_PASSWORD", "Admin@12345")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "email": admin_email,
            "password_hash": hash_password(admin_pw),
            "name": "SentinelFlow Admin",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"Seeded admin user: {admin_email}")
    elif not verify_password(admin_pw, existing["password_hash"]):
        await db.users.update_one(
            {"email": admin_email},
            {"$set": {"password_hash": hash_password(admin_pw)}},
        )
    # seed analyst
    analyst_email = "analyst@sentinelflow.io"
    if not await db.users.find_one({"email": analyst_email}):
        await db.users.insert_one({
            "email": analyst_email,
            "password_hash": hash_password("Analyst@123"),
            "name": "Demo Analyst",
            "role": "analyst",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    logger.info("SentinelFlow startup complete.")


@app.on_event("shutdown")
async def shutdown():
    mongo.close()


# -------------------- Push-only, key-auth ingestion (v1) --------------------
# Mounted separately at /api/v1/*. This path ONLY accepts a scoped API key.
# It does not read or write anything except raw_logs + normalized_events + alerts
# via the same _ingest_events pipeline used everywhere else.
from fastapi import Header, Request as _Req  # noqa: E402
import ingest_v1 as _v1  # noqa: E402

v1 = APIRouter(prefix="/api/v1")


async def _auth_ingest_source(request: _Req) -> dict:
    key = _v1.extract_key(request.headers)
    if not key or not key.startswith(_v1.KEY_PREFIX):
        raise HTTPException(status_code=401, detail="Missing or malformed ingest key")
    key_hash = _v1.hash_key(key)
    source = await db.log_sources.find_one({"ingest_api_key_hash": key_hash})
    if not source:
        raise HTTPException(status_code=401, detail="Invalid ingest key")
    if source.get("paused"):
        raise HTTPException(status_code=423, detail="Source is paused")
    allowed, remaining, reset = _v1.check_rate(key_hash)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({_v1.RATE_LIMIT_PER_MIN}/min). Retry in {reset}s",
            headers={"Retry-After": str(reset)},
        )
    source["_rate_remaining"] = remaining
    source["_rate_reset"] = reset
    return source


@v1.get("/ping")
async def v1_ping():
    return {"ok": True, "service": "SentinelFlow", "ingest": "v1"}


@v1.post("/ingest")
async def v1_ingest(request: _Req, source: dict = Depends(_auth_ingest_source)):
    raw = await request.body()
    if len(raw) > _v1.MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large")
    try:
        import json as _json
        payload = _json.loads(raw or b"{}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    try:
        events = _v1.validate_batch(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = await _ingest_events(events, source["name"], f"key:{source['name']}")
    return {
        **result,
        "source": source["name"],
        "rate_limit": {
            "remaining": source.get("_rate_remaining"),
            "reset_seconds": source.get("_rate_reset"),
            "limit_per_min": _v1.RATE_LIMIT_PER_MIN,
        },
    }


app.include_router(api)
app.include_router(v1)
