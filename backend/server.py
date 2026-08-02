"""SentinelFlow — FastAPI backend."""
from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(__file__).parent / ".env")

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional

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
            update["locked_until"] = (now.replace(microsecond=0)
                                      .isoformat().replace("+00:00", "") + "+00:00")
            from datetime import timedelta
            update["locked_until"] = (now + timedelta(minutes=15)).isoformat()
        await db.login_attempts.update_one({"identifier": identifier}, {"$set": update}, upsert=True)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    await db.login_attempts.delete_one({"identifier": identifier})
    uid = str(user["_id"])
    access = create_access_token(uid, email, user["role"])
    refresh = create_refresh_token(uid)
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
    return await db.log_sources.find({}, {"_id": 0}).to_list(1000)


@api.post("/sources")
async def create_source(body: SourceCreate, user: dict = Depends(current_user)):
    doc = {
        "id": str(uuid.uuid4()), "name": body.name, "type": body.type,
        "description": body.description or "", "last_event_at": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.log_sources.insert_one(doc)
    doc.pop("_id", None)
    await audit(user["email"], "create_source", target=body.name)
    return doc


# -------------------- Ingestion --------------------
async def _ingest_events(records: list, source_name: str, actor_email: str):
    if not records:
        return {"ingested": 0, "alerts": 0}
    normalized = [normalize_record(r, source_name) for r in records]
    # store raw + normalized
    raw_docs = [{"id": str(uuid.uuid4()), "source_name": source_name,
                 "payload": n["raw_log"], "created_at": n["timestamp"]} for n in normalized]
    await db.raw_logs.insert_many(raw_docs)
    # normalized: store as-is (raw_log kept inside)
    await db.normalized_events.insert_many([dict(n) for n in normalized])

    # update source last_event_at
    latest = max(n["timestamp"] for n in normalized)
    await db.log_sources.update_one(
        {"name": source_name},
        {"$set": {"last_event_at": latest}}, upsert=True,
    )

    # run detection
    alerts = run_all_rules(normalized)
    async_alerts = await detect_new_device_admin(db, normalized)
    alerts.extend(async_alerts)
    if alerts:
        await db.alerts.insert_many([dict(a) for a in alerts])
        # fire-and-log emails (never raises)
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
    # TTL: purge raw_logs older than 72h (259200s). Uses BSON date field.
    await db.raw_logs.create_index("created_at_bson", expireAfterSeconds=72 * 3600)

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


app.include_router(api)
