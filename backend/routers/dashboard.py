"""Dashboard metrics, aggregations, and SOC audit log."""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends

from core.database import db
from core.deps import current_user, require_admin
from rules import detect_silent_sources

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/stats")
async def dashboard_stats(_: dict = Depends(current_user)):
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=24)).isoformat()

    events_24h = await db.normalized_events.count_documents({"timestamp": {"$gte": since}})
    open_alerts = await db.alerts.count_documents(
        {"status": {"$in": ["New", "Under Review", "Investigating"]}}
    )
    critical_alerts = await db.alerts.count_documents({"severity": "Likely malicious"})
    silent = await detect_silent_sources(db)

    # Timeseries (per hour, last 24h)
    pipeline = [
        {"$match": {"timestamp": {"$gte": since}}},
        {"$project": {"hour": {"$substr": ["$timestamp", 0, 13]}}},
        {"$group": {"_id": "$hour", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]
    ts = await db.normalized_events.aggregate(pipeline).to_list(200)
    timeseries = [{"hour": t["_id"], "count": t["count"]} for t in ts]

    # Top source IPs
    pipeline2 = [
        {"$match": {"src_ip": {"$ne": None}}},
        {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 8},
    ]
    tops = await db.normalized_events.aggregate(pipeline2).to_list(20)
    top_ips = [{"src_ip": t["_id"], "count": t["count"]} for t in tops]

    # Alerts by severity
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


@router.get("/audit")
async def audit_log(limit: int = 200, _: dict = Depends(require_admin)):
    docs = await db.audit_logs.find({}, {"_id": 0}) \
        .sort("timestamp", -1).limit(min(limit, 500)).to_list(limit)
    return docs
