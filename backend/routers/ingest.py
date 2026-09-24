"""Log ingestion routes and processing pipeline for SentinelFlow."""
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Query, BackgroundTasks
from pydantic import BaseModel

from akamai_ingest import parse_akamai_payload
from core.database import db
from core.deps import current_user, require_admin, audit, url_for, public_ingest_base, auth_source_from_ingest_key
from normalize import normalize_record, parse_upload
from notifier import notify_alerts
from rules import run_all_rules, detect_new_device_admin
from seed import sample_events, demo_sources
import ingest_v1 as _v1
from routers.sources import validate_source_name
import webhooks as _webhooks

logger = logging.getLogger("sentinelflow.ingest")

router = APIRouter(tags=["ingest"])
v1_router = APIRouter(prefix="/v1", tags=["v1_ingest"])


async def _dispatch_notifications_async(alerts: List[dict]):
    """Background task to dispatch email and webhook notifications for triggered alerts."""
    try:
        statuses = await notify_alerts(db, alerts)
        logger.info("notify_alerts: %s", {s: statuses.count(s) for s in set(statuses)})
    except Exception as e:
        logger.warning("Notifier failed: %s", e)

    try:
        wh = await _webhooks.dispatch_alerts(db, alerts)
        if wh:
            logger.info("webhooks dispatched: %s", len(wh))
    except Exception as e:
        logger.warning("Webhook dispatcher failed: %s", e)


async def ingest_events_pipeline(
    records: list,
    source_name: str,
    actor_email: str,
    background_tasks: Optional[BackgroundTasks] = None,
) -> dict:
    """Core log normalization, storage, rule detection, and alerting pipeline."""
    if not records:
        return {"ingested": 0, "alerts": 0}

    source = await db.log_sources.find_one({"name": source_name})
    if source and source.get("paused"):
        raise HTTPException(status_code=409, detail=f"Source '{source_name}' is paused")

    retention_hours = int((source or {}).get("retention_hours") or 72)
    retention_hours = max(1, min(72, retention_hours))

    normalized = [normalize_record(r, source_name) for r in records]
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=retention_hours)

    raw_docs = [
        {
            "id": str(uuid.uuid4()),
            "source_name": source_name,
            "payload": n["raw_log"],
            "created_at": n["timestamp"],
            "expires_at": expires_at,
        }
        for n in normalized
    ]
    await db.raw_logs.insert_many(raw_docs)
    await db.normalized_events.insert_many([dict(n) for n in normalized])

    latest = max(n["timestamp"] for n in normalized)
    await db.log_sources.update_one(
        {"name": source_name},
        {"$set": {"last_event_at": latest}},
        upsert=True,
    )

    # Load current blocklist for R010 detection
    bl_docs = await db.ip_blocklist.find({}).to_list(5000)
    blocklist = {d["ip"]: d for d in bl_docs}

    alerts = run_all_rules(normalized, blocklist=blocklist)
    async_alerts = await detect_new_device_admin(db, normalized)
    alerts.extend(async_alerts)

    if alerts:
        await db.alerts.insert_many([dict(a) for a in alerts])
        if background_tasks:
            background_tasks.add_task(_dispatch_notifications_async, alerts)
        else:
            await _dispatch_notifications_async(alerts)

    await audit(
        actor_email, "ingest", target=source_name,
        meta={"count": len(normalized), "alerts": len(alerts)},
    )
    return {"ingested": len(normalized), "alerts": len(alerts)}


# -------------------- Ingest Endpoints --------------------

@router.get("/ingest/config")
async def ingest_config(_: dict = Depends(current_user)):
    base = public_ingest_base()
    return {
        "endpoint": f"{base}/api/v1/ingest" if base else "/api/v1/ingest",
        "akamai_endpoint_template": f"{base}/api/integrations/akamai/{{source_name}}/logs"
                                    if base else "/api/integrations/akamai/{source_name}/logs",
        "rate_limit_per_min": _v1.RATE_LIMIT_PER_MIN,
        "max_events_per_request": _v1.MAX_EVENTS_PER_REQ,
        "max_body_bytes": _v1.MAX_BODY_BYTES,
        "auth_header": "Authorization: Bearer sfk_...",
        "alt_header": "X-Ingest-Key: sfk_...",
        "akamai_required_header": "X-Ingest-Key: sfk_...",
        "akamai_log_format": "JSON",
        "integrations": {
            "akamai": {
                "name": "Akamai DataStream 2",
                "endpoint_template": f"{base}/api/integrations/akamai/{{source_name}}/logs"
                                     if base else "/api/integrations/akamai/{source_name}/logs",
                "method": "POST",
                "auth": "Custom header X-Ingest-Key",
                "format": "JSON",
                "content_type": "application/json",
                "compression": "off",
            },
            "custom": {
                "name": "Generic HTTPS collector",
                "endpoint": f"{base}/api/v1/ingest" if base else "/api/v1/ingest",
                "method": "POST",
                "auth": "Authorization: Bearer sfk_... or X-Ingest-Key",
                "format": "JSON, NDJSON, or {events:[...]}",
            },
        },
    }


@router.post("/ingest")
async def ingest(
    source_name: str = Query(...),
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    user: dict = Depends(current_user),
):
    content = await file.read()
    try:
        records = parse_upload(file.filename, content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Parse error: {e}")
    if not isinstance(records, list) or not records:
        raise HTTPException(status_code=400, detail="No records found in file")
    return await ingest_events_pipeline(records, source_name, user["email"], background_tasks)


class SyslogBody(BaseModel):
    source_name: str
    text: str


@router.post("/ingest/syslog")
async def ingest_syslog(
    body: SyslogBody,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    user: dict = Depends(current_user),
):
    """Accept a raw syslog payload (RFC-5424 or RFC-3164) as a JSON string."""
    from syslog_parser import parse_syslog
    records = parse_syslog(body.text)
    if not records:
        raise HTTPException(status_code=400, detail="No syslog lines could be parsed")
    return await ingest_events_pipeline(records, body.source_name, user["email"], background_tasks)


@router.post("/ingest/seed")
async def seed_ingest(
    background_tasks: BackgroundTasks = BackgroundTasks(),
    user: dict = Depends(require_admin),
):
    """Load sample events across demo sources."""
    for src in demo_sources():
        exists = await db.log_sources.find_one({"name": src["name"]})
        if not exists:
            await db.log_sources.insert_one(src)
    events = sample_events()
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
            r = await ingest_events_pipeline(recs, src_name, user["email"], background_tasks)
            total["ingested"] += r["ingested"]
            total["alerts"] += r["alerts"]
    return total


@router.post("/integrations/akamai/{source_name}/logs")
async def ingest_akamai_logs(
    source_name: str,
    request: Request,
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    source_name = validate_source_name(source_name)
    source = await auth_source_from_ingest_key(request)
    if source["name"] != source_name:
        raise HTTPException(status_code=403, detail="Ingest key is not scoped to this Akamai source")

    raw = await request.body()
    MAX_AKAMAI_BODY_BYTES = 10_000_000
    if len(raw) > MAX_AKAMAI_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large (max 10MB)")

    if not raw or not raw.strip():
        # Health check / test probe from Akamai
        return {"ingested": 0, "alerts": 0, "status": "ok", "source": source["name"]}

    try:
        events = parse_akamai_payload(raw)
        if not events:
            return {"ingested": 0, "alerts": 0, "status": "ok", "source": source["name"]}
        if len(events) > 10000:
            raise ValueError("too many events in batch (max 10000)")
        for i, e in enumerate(events):
            if not isinstance(e, dict):
                raise ValueError(f"event #{i} must be a JSON object")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = await ingest_events_pipeline(events, source["name"], f"akamai:{source['name']}", background_tasks)
    return {
        **result,
        "source": source["name"],
        "integration": "akamai_datastream",
        "rate_limit": {
            "remaining": source.get("_rate_remaining"),
            "reset_seconds": source.get("_rate_reset"),
            "limit_per_min": _v1.RATE_LIMIT_PER_MIN,
        },
    }


# -------------------- Push-only v1 Router --------------------

@v1_router.get("/ping")
async def v1_ping():
    return {"ok": True, "service": "SentinelFlow", "ingest": "v1"}


@v1_router.post("/ingest")
async def v1_ingest(
    request: Request,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    source: dict = Depends(auth_source_from_ingest_key),
):
    raw = await request.body()
    if len(raw) > _v1.MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large")
    try:
        payload = json.loads(raw or b"{}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")
    try:
        events = _v1.validate_batch(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = await ingest_events_pipeline(events, source["name"], f"key:{source['name']}", background_tasks)
    return {
        **result,
        "source": source["name"],
        "rate_limit": {
            "remaining": source.get("_rate_remaining"),
            "reset_seconds": source.get("_rate_reset"),
            "limit_per_min": _v1.RATE_LIMIT_PER_MIN,
        },
    }
