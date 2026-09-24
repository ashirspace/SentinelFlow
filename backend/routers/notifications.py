"""Notification configuration (Email & Webhook preferences)."""
import os
from typing import Optional
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.database import db
from core.deps import current_user, audit
from notifier import is_enabled as email_enabled
import webhooks as _webhooks

router = APIRouter(tags=["notifications"])


class NotificationPrefs(BaseModel):
    webhook_url: Optional[str] = ""
    webhook_type: Optional[str] = None  # slack | teams | auto
    webhook_enabled: Optional[bool] = False
    webhook_min_severity: Optional[str] = Field(
        default="Suspicious",
        pattern="^(Informational|Suspicious|Likely malicious)$",
    )


@router.get("/notifier/status")
async def notifier_status(_: dict = Depends(current_user)):
    return {
        "enabled": email_enabled(),
        "min_severity": os.environ.get("ALERT_EMAIL_MIN_SEVERITY", "Suspicious"),
        "dedup_hours": int(os.environ.get("ALERT_EMAIL_DEDUP_HOURS", "1") or 1),
        "recipients": [e.strip() for e in os.environ.get("ALERT_EMAIL_TO", "").split(",") if e.strip()],
        "smtp_host": os.environ.get("SMTP_HOST", ""),
    }


@router.get("/me/notifications")
async def get_my_notifications(user: dict = Depends(current_user)):
    doc = await db.users.find_one({"_id": ObjectId(user["id"])}, {"notification_prefs": 1})
    prefs = (doc or {}).get("notification_prefs") or {}
    prefs.setdefault("webhook_url", "")
    prefs.setdefault("webhook_type", None)
    prefs.setdefault("webhook_enabled", False)
    prefs.setdefault("webhook_min_severity", "Suspicious")
    if prefs.get("webhook_url") and not prefs.get("webhook_type"):
        prefs["webhook_type"] = _webhooks.detect_type(prefs["webhook_url"])
    return prefs


@router.put("/me/notifications")
async def set_my_notifications(body: NotificationPrefs, user: dict = Depends(current_user)):
    prefs = body.model_dump() if hasattr(body, "model_dump") else body.dict()
    url = prefs.get("webhook_url") or ""
    if prefs.get("webhook_enabled") and not url:
        raise HTTPException(status_code=400, detail="webhook_url is required when enabling")
    if url and not (url.startswith("https://") or url.startswith("http://")):
        raise HTTPException(status_code=400, detail="webhook_url must start with http(s)://")
    if not prefs.get("webhook_type") and url:
        prefs["webhook_type"] = _webhooks.detect_type(url)
    await db.users.update_one(
        {"_id": ObjectId(user["id"])},
        {"$set": {"notification_prefs": prefs}},
    )
    await audit(
        user["email"], "update_notification_prefs", target=user["id"],
        meta={"enabled": prefs.get("webhook_enabled"), "type": prefs.get("webhook_type")},
    )
    return prefs


@router.post("/me/notifications/test")
async def test_my_webhook(user: dict = Depends(current_user)):
    doc = await db.users.find_one({"_id": ObjectId(user["id"])}, {"notification_prefs": 1})
    prefs = (doc or {}).get("notification_prefs") or {}
    if not prefs.get("webhook_url"):
        raise HTTPException(status_code=400, detail="No webhook configured")
    result = await _webhooks.send_test(prefs["webhook_url"], prefs.get("webhook_type"))
    return {"result": result}
